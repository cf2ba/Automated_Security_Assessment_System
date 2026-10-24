"""Docker 隔离环境：每项目一个容器，源码只读挂载 /src，可写工作区 /workspace。"""
from __future__ import annotations

import logging
import os
import posixpath
import shlex
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import docker
from docker.errors import BuildError, DockerException, ImageNotFound, NotFound

logger = logging.getLogger(__name__)


class IsolationError(RuntimeError):
    pass


_client = None


def get_client():
    global _client
    if _client is None:
        try:
            _client = docker.from_env()
            _client.ping()
        except DockerException as exc:
            _client = None
            raise IsolationError(f"无法连接 Docker：{exc}") from exc
    return _client


def docker_available() -> bool:
    try:
        get_client()
        return True
    except IsolationError:
        return False


def container_name(project_id: int) -> str:
    return f"sas-env-{project_id}"


def ensure_image(image: str, dockerfile_dir: str | None = None) -> None:
    client = get_client()
    try:
        client.images.get(image)
        return
    except ImageNotFound:
        pass
    context = dockerfile_dir or str(Path(__file__).resolve().parents[2] / "docker")
    dockerfile = os.path.join(context, "Dockerfile")
    if not os.path.exists(dockerfile):
        raise IsolationError(f"未找到 Dockerfile：{dockerfile}")
    logger.info("构建隔离镜像 %s ...", image)
    try:
        client.images.build(path=context, tag=image, rm=True)
    except BuildError as exc:
        lines = []
        for chunk in exc.build_log or []:
            text = chunk.get("stream") or chunk.get("error") or ""
            if text:
                lines.append(text.rstrip())
        detail = "\n".join(lines[-20:])[-2000:]
        raise IsolationError(
            f"镜像构建失败：{exc}\n{detail}" if detail else f"镜像构建失败：{exc}"
        ) from exc


def remove_existing(project_id: int) -> None:
    client = get_client()
    try:
        client.containers.get(container_name(project_id)).remove(force=True)
    except NotFound:
        pass


def create_environment(
    project_id: int,
    host_source_path: str,
    workspace_path: str,
    image: str,
    target_port: int = 5000,
) -> str:
    client = get_client()
    source = os.path.abspath(host_source_path)
    workspace = os.path.abspath(workspace_path)
    if not os.path.isdir(source):
        raise IsolationError(f"源码目录不存在：{source}")
    Path(workspace).mkdir(parents=True, exist_ok=True)

    remove_existing(project_id)
    container = client.containers.run(
        image,
        command="sleep infinity",
        name=container_name(project_id),
        detach=True,
        volumes={
            source: {"bind": "/src", "mode": "ro"},
            workspace: {"bind": "/workspace", "mode": "rw"},
        },
        working_dir="/workspace",
        environment={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "TARGET_PORT": str(target_port),
            "PORT": str(target_port),
        },
        labels={"sas.project_id": str(project_id), "sas.managed": "true"},
        network_disabled=True,
        mem_limit="1g",
        nano_cpus=1_000_000_000,
        pids_limit=256,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
    )
    return container.short_id


def get_container_by_project(project_id: int):
    try:
        return get_client().containers.get(container_name(project_id))
    except NotFound:
        return None


def exec_command(project_id: int, command: str, timeout: int = 60, workdir: str = "/workspace") -> tuple[int, str]:
    container = get_container_by_project(project_id)
    if container is None:
        raise IsolationError("隔离环境不存在或已销毁")
    wrapped = f"timeout {int(timeout)} sh -c {shlex.quote(command)}"
    try:
        result = container.exec_run(["sh", "-c", wrapped], workdir=workdir, demux=False)
        output = result.output or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return int(result.exit_code or 0), output
    except DockerException as exc:
        raise IsolationError(f"命令执行失败：{exc}") from exc


def start_target_app(
    project_id: int,
    entry: str = "app.py",
    port: int = 5000,
    wait_seconds: int = 25,
) -> tuple[bool, str]:
    container = get_container_by_project(project_id)
    if container is None:
        return False, "隔离环境不存在"

    entry = entry.replace("\\", "/").lstrip("/")
    entry_dir = posixpath.dirname(entry) or "."
    entry_name = posixpath.basename(entry)
    prepare = "rm -rf /workspace/app && cp -a /src /workspace/app"
    code, output = exec_command(project_id, prepare, timeout=30, workdir="/workspace")
    if code != 0:
        return False, f"复制源码到工作区失败：{output[:1000]}"

    cmd = (
        f"cd /workspace/app/{shlex.quote(entry_dir)} && "
        f"nohup python {shlex.quote(entry_name)} > /workspace/app.log 2>&1 & echo started"
    )
    container.exec_run(["sh", "-c", cmd], workdir="/workspace/app", demux=False)

    deadline = time.time() + wait_seconds
    last = ""
    while time.time() < deadline:
        code, out = exec_command(
            project_id,
            f'curl -s -o /dev/null -w "%{{http_code}}" http://127.0.0.1:{port}/ || true',
            timeout=10,
        )
        last = out.strip()
        if last and last != "000":
            return True, f"目标应用已就绪（HTTP {last}）"
        time.sleep(1.5)
    try:
        _, log = exec_command(project_id, "tail -n 40 /workspace/app.log || true", timeout=10)
    except IsolationError:
        log = ""
    return False, f"目标应用启动超时。\n{log}".strip()


def stop_environment(project_id: int) -> None:
    container = get_container_by_project(project_id)
    if container:
        try:
            container.stop(timeout=5)
        except DockerException:
            pass


def destroy_environment(project_id: int) -> None:
    remove_existing(project_id)


def container_stats(project_id: int) -> tuple[float, float] | None:
    """返回容器 (cpu%, memory MB)；不可用时返回 None。"""
    container = get_container_by_project(project_id)
    if container is None:
        return None
    try:
        stats = container.stats(stream=False)
        cpu_delta = (
            stats["cpu_stats"]["cpu_usage"]["total_usage"]
            - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        system_delta = (
            stats["cpu_stats"].get("system_cpu_usage", 0)
            - stats["precpu_stats"].get("system_cpu_usage", 0)
        )
        online = stats["cpu_stats"].get("online_cpus") or len(
            stats["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1]
        )
        cpu = (cpu_delta / system_delta) * online * 100.0 if system_delta > 0 else 0.0
        mem = stats["memory_stats"].get("usage", 0) / (1024 * 1024)
        return round(cpu, 2), round(mem, 2)
    except (DockerException, KeyError):
        return None


def clone_repo(repo_url: str, dest_dir: str, timeout: int = 120) -> str:
    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise IsolationError("仅支持 http/https Git 仓库地址")
    dest = Path(dest_dir)
    if dest.exists():
        if any(dest.iterdir()):
            return str(dest)
        dest.rmdir()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, str(dest)],
            check=True,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise IsolationError("未找到 git 命令，无法克隆仓库") from exc
    except subprocess.CalledProcessError as exc:
        raise IsolationError(f"git clone 失败：{exc.stderr}") from exc
    return str(dest)
