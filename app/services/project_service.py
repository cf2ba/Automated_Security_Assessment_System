"""项目创建、查询、运行控制、级联删除。"""
from __future__ import annotations

import logging
import os
import shutil
import stat
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import settings
from app.core.errors import (
    AppError,
    GitCloneFailed,
    ProjectNotFound,
    ProjectNotRunning,
    ProjectRunning,
    SourcePathInvalid,
    SourcePathNotAllowed,
)
from app.database import SessionLocal
from app.isolation import docker as docker_iso
from app.models import (
    AttackPath,
    AttackPathItem,
    ChatMessage,
    Project,
    Report,
    ResourceUsage,
    RuntimeLog,
    RuntimeStage,
    Vulnerability,
    WorkerTask,
    utcnow,
)
from app.services import stage_service

logger = logging.getLogger(__name__)


def workspace_dir(project_id: int) -> Path:
    return settings.workspace_dir / str(project_id)


def _remove_tree(path: Path) -> None:
    """删除目录；Windows 上 Git 对象等只读文件需先去掉只读属性。"""
    if not path.exists():
        return
    for root, dirs, files in os.walk(path):
        for name in files + dirs:
            try:
                os.chmod(os.path.join(root, name), stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
    shutil.rmtree(path)


def resolve_source_path(project: Project) -> Path:
    """本地项目返回用户路径；Git 项目返回克隆目录（source_path 始终保留原始 URL）。"""
    if project.source_type == "git":
        return workspace_dir(project.id) / "src"
    return Path(project.source_path)


def _validate_local_path(raw: str) -> Path:
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourcePathInvalid(f"源码目录不存在或不可访问：{raw}") from exc
    if not resolved.is_dir():
        raise SourcePathInvalid(f"源码路径不是目录：{raw}")
    roots = settings.allowed_source_root_list
    if roots and not any(_is_under(resolved, root) for root in roots):
        raise SourcePathNotAllowed("源码目录不在 ALLOWED_SOURCE_ROOTS 允许范围内")
    return resolved


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_git_url(raw: str) -> str:
    value = raw.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SourcePathInvalid("Git 地址必须是 http/https URL")
    return value


def create_project(
    db: Session,
    project_name: str,
    source_type: str,
    source_path: str,
    task_content: str,
    isolation_type: str,
    created_by: int,
) -> Project:
    name = (project_name or "").strip()
    if not name:
        raise SourcePathInvalid("项目名称不能为空")
    if source_type not in ("local", "git"):
        raise SourcePathInvalid("源码类型必须是 local 或 git")
    if isolation_type not in ("docker",):
        raise SourcePathInvalid("当前仅支持 docker 隔离环境")

    raw_source = (source_path or "").strip()
    if source_type == "local":
        raw_source = str(_validate_local_path(raw_source))
    else:
        raw_source = _validate_git_url(raw_source)

    project = Project(
        project_name=name[:128],
        source_type=source_type,
        source_path=raw_source,
        task_content=(task_content or "")[:5000],
        isolation_type="docker",
        project_status="created",
        created_by=created_by,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    if source_type == "git":
        dest = workspace_dir(project.id) / "src"
        try:
            docker_iso.clone_repo(raw_source, str(dest))
        except Exception as exc:  # noqa: BLE001
            db.delete(project)
            db.commit()
            try:
                _remove_tree(workspace_dir(project.id))
            except OSError:
                logger.warning("清理克隆目录失败：%s", workspace_dir(project.id))
            raise GitCloneFailed(f"Git 仓库克隆失败：{exc}") from exc
    return project


def list_projects(db: Session, status: str | None = None, keyword: str | None = None) -> list[Project]:
    q = db.query(Project)
    if status:
        q = q.filter(Project.project_status == status)
    if keyword:
        q = q.filter(Project.project_name.like(f"%{keyword}%"))
    return q.order_by(Project.id.desc()).all()


def paginate_projects(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    keyword: str | None = None,
) -> tuple[list[Project], int]:
    q = db.query(Project)
    if status:
        q = q.filter(Project.project_status == status)
    if keyword:
        q = q.filter(Project.project_name.like(f"%{keyword}%"))
    total = q.count()
    rows = (
        q.order_by(Project.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return rows, total


def get_project(db: Session, project_id: int) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise ProjectNotFound("项目不存在")
    return project


def update_status(
    db: Session,
    project_id: int,
    status: str,
    error: str | None = None,
    finished: bool = False,
) -> Project | None:
    project = db.get(Project, project_id)
    if not project:
        return None
    project.project_status = status
    project.updated_at = utcnow()
    if error is not None:
        project.error_message = error
    if finished:
        project.last_finished_at = utcnow()
    db.commit()
    db.refresh(project)
    return project


def update_status_db(project_id: int, status: str, error: str | None = None, finished: bool = True) -> None:
    db = SessionLocal()
    try:
        update_status(db, project_id, status, error, finished)
    finally:
        db.close()


def project_dict(project: Project, db: Session | None = None) -> dict:
    data = {
        "id": project.id,
        "project_name": project.project_name,
        "source_type": project.source_type,
        "source_path": project.source_path,
        "task_content": project.task_content,
        "project_status": project.project_status,
        "isolation_type": project.isolation_type,
        "isolation_env_id": project.isolation_env_id,
        "run_no": project.run_no,
        "error_message": project.error_message,
        "created_by": project.created_by,
        "last_started_at": project.last_started_at.isoformat() if project.last_started_at else None,
        "last_finished_at": project.last_finished_at.isoformat() if project.last_finished_at else None,
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "updated_at": project.updated_at.isoformat() if project.updated_at else None,
    }
    if db is not None:
        data["vulnerability_count"] = (
            db.query(Vulnerability).filter(Vulnerability.project_id == project.id).count()
        )
        data["attack_path_count"] = (
            db.query(AttackPath).filter(AttackPath.project_id == project.id).count()
        )
        latest_report = (
            db.query(Report).filter(Report.project_id == project.id).order_by(Report.id.desc()).first()
        )
        data["report_status"] = latest_report.report_status if latest_report else None
        data["report_ready"] = bool(latest_report and latest_report.report_status == "ready")
        data["report_id"] = latest_report.id if latest_report else None
    return data


def reset_runtime_data(db: Session, project_id: int) -> None:
    """清理上一次运行的业务产物；日志与资源记录保留，供历史排查。"""
    path_ids = [row.id for row in db.query(AttackPath.id).filter(AttackPath.project_id == project_id)]
    if path_ids:
        db.query(AttackPathItem).filter(AttackPathItem.path_id.in_(path_ids)).delete(
            synchronize_session=False
        )
    db.query(AttackPath).filter(AttackPath.project_id == project_id).delete(synchronize_session=False)
    db.query(Vulnerability).filter(Vulnerability.project_id == project_id).delete(
        synchronize_session=False
    )
    db.query(Report).filter(Report.project_id == project_id).delete(synchronize_session=False)
    db.query(ChatMessage).filter(ChatMessage.project_id == project_id).delete(
        synchronize_session=False
    )
    db.query(WorkerTask).filter(WorkerTask.project_id == project_id).delete(synchronize_session=False)
    db.query(RuntimeStage).filter(RuntimeStage.project_id == project_id).delete(
        synchronize_session=False
    )
    db.flush()

    try:
        _remove_tree(settings.report_dir / str(project_id))
    except OSError:
        logger.warning("清理报告目录失败：%s", settings.report_dir / str(project_id))
    work = workspace_dir(project_id)
    if work.exists():
        for name in ("app", "app.log"):
            target = work / name
            if target.is_dir():
                try:
                    _remove_tree(target)
                except OSError:
                    logger.warning("清理工作区目录失败：%s", target)
            elif target.exists():
                target.unlink(missing_ok=True)
        for poc in work.glob("poc_*.py"):
            poc.unlink(missing_ok=True)


def start_run(db: Session, project_id: int) -> dict:
    project = (
        db.query(Project)
        .filter(Project.id == project_id)
        .with_for_update()
        .first()
    )
    if not project:
        raise ProjectNotFound("项目不存在")
    if project.project_status == "running":
        raise ProjectRunning("该项目已在运行")

    reset_runtime_data(db, project_id)
    project.run_no = (project.run_no or 0) + 1
    project.project_status = "running"
    project.isolation_env_id = None
    project.error_message = None
    project.last_started_at = utcnow()
    project.last_finished_at = None
    stage_service.create_stages(db, project_id)
    db.commit()
    db.refresh(project)
    return {
        "id": project.id,
        "project_status": project.project_status,
        "run_no": project.run_no,
        "started_at": project.last_started_at.isoformat() if project.last_started_at else None,
    }


def stop_run(db: Session, project_id: int) -> Project:
    project = get_project(db, project_id)
    if project.project_status != "running":
        raise ProjectNotRunning("项目未在运行")
    project.project_status = "stopped"
    project.last_finished_at = utcnow()
    project.updated_at = utcnow()
    stage_service.finish_unfinished(db, project_id, "stopped")
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, project: Project) -> None:
    pid = project.id
    try:
        docker_iso.destroy_environment(pid)
    except Exception as exc:  # Docker 不可用时仍允许清理数据库与文件
        logger.warning("销毁容器失败（继续删除项目）：%s", exc)

    for base in (settings.report_dir, settings.log_dir, settings.workspace_dir):
        target = base / str(pid)
        if target.exists():
            try:
                _remove_tree(target)
            except OSError as exc:
                raise AppError(f"删除项目目录失败：{target}（{exc}）") from exc

    path_ids = [row.id for row in db.query(AttackPath.id).filter(AttackPath.project_id == pid)]
    if path_ids:
        db.query(AttackPathItem).filter(AttackPathItem.path_id.in_(path_ids)).delete(
            synchronize_session=False
        )
    db.query(AttackPath).filter(AttackPath.project_id == pid).delete(synchronize_session=False)
    db.query(Vulnerability).filter(Vulnerability.project_id == pid).delete(synchronize_session=False)
    db.query(Report).filter(Report.project_id == pid).delete(synchronize_session=False)
    db.query(ChatMessage).filter(ChatMessage.project_id == pid).delete(synchronize_session=False)
    db.query(RuntimeLog).filter(RuntimeLog.project_id == pid).delete(synchronize_session=False)
    db.query(ResourceUsage).filter(ResourceUsage.project_id == pid).delete(synchronize_session=False)
    db.query(WorkerTask).filter(WorkerTask.project_id == pid).delete(synchronize_session=False)
    db.query(RuntimeStage).filter(RuntimeStage.project_id == pid).delete(synchronize_session=False)
    db.query(Project).filter(Project.id == pid).delete(synchronize_session=False)
    db.commit()
