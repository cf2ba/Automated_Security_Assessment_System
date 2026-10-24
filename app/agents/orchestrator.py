"""多智能体阶段编排：环境检查 → 代码分析 → 漏洞验证 → 报告生成 → 完成。"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import psutil

from app.agents import roles, tools
from app.config import settings
from app.core import llm
from app.core.events import broker
from app.core.task_manager import task_manager
from app.database import SessionLocal
from app.isolation import docker as iso
from app.models import Project
from app.services import (
    monitor_service,
    report_service,
    stage_service,
    vuln_service,
)

logger = logging.getLogger(__name__)

_TOKEN_TOTALS: dict[int, int] = {}


def reset_tokens(project_id: int) -> None:
    _TOKEN_TOTALS[project_id] = 0


def add_tokens(project_id: int, tokens: int) -> int:
    _TOKEN_TOTALS[project_id] = _TOKEN_TOTALS.get(project_id, 0) + max(0, int(tokens or 0))
    return _TOKEN_TOTALS[project_id]


def get_tokens(project_id: int) -> int:
    return _TOKEN_TOTALS.get(project_id, 0)


# ---------------------------------------------------------------------------
# DB / 事件辅助
# ---------------------------------------------------------------------------

def _db(fn):
    db = SessionLocal()
    try:
        return fn(db)
    finally:
        db.close()


async def _run_db(fn):
    return await asyncio.to_thread(_db, fn)


async def _log(
    pid: int,
    content: str,
    level: str = "info",
    stage_id: int | None = None,
    worker_id: int | None = None,
) -> None:
    try:
        data = await _run_db(
            lambda db: monitor_service.log_dict(
                monitor_service.add_log(db, pid, content, level, stage_id, worker_id)
            )
        )
        await broker.publish(pid, {"type": "runtime_log", **data})
    except Exception as exc:  # 日志失败不应中断评估
        logger.warning("写入运行日志失败：%s", exc)


async def _chat(pid: int, role: str, text: str, message_type: str = "info") -> None:
    try:
        data = await _run_db(
            lambda db: monitor_service.chat_dict(
                monitor_service.add_chat(db, pid, role, text, message_type)
            )
        )
        await broker.publish(pid, {"type": "chat_message", **data})
    except Exception as exc:
        logger.warning("写入角色消息失败：%s", exc)


async def _stage_start(pid: int, name: str) -> int:
    stage_id = await _run_db(lambda db: stage_service.start_stage(db, pid, name))
    await broker.publish(pid, {
        "type": "stage_status", "project_id": pid, "stage_name": name, "stage_status": "running",
    })
    await _log(pid, f"阶段 {name} 开始", stage_id=stage_id)
    return stage_id


async def _stage_finish(
    pid: int, stage_id: int, name: str, status: str, error: str | None = None
) -> None:
    await _run_db(lambda db: stage_service.finish_stage(db, pid, name, status, error))
    await broker.publish(pid, {
        "type": "stage_status", "project_id": pid, "stage_name": name, "stage_status": status,
    })
    await _log(
        pid,
        f"阶段 {name} 结束：{status}" + (f"（{error}）" if error else ""),
        level="error" if status == "failed" else "info",
        stage_id=stage_id,
    )


async def _worker_start(pid: int, stage_id: int, role: str, task_content: str) -> int:
    wid = await _run_db(
        lambda db: stage_service.start_worker(db, pid, stage_id, role, task_content)
    )
    await broker.publish(pid, {
        "type": "worker_status", "worker_task_id": wid, "worker_role": role,
        "task_status": "running", "task_content": task_content,
    })
    return wid


async def _worker_finish(
    pid: int,
    wid: int,
    role: str,
    status: str,
    summary: str | None = None,
    error: str | None = None,
    tokens: int = 0,
) -> None:
    await _run_db(lambda db: stage_service.finish_worker(db, wid, status, summary, error, tokens))
    await broker.publish(pid, {
        "type": "worker_status", "worker_task_id": wid, "worker_role": role,
        "task_status": status, "result_summary": summary, "error_message": error,
        "token_count": tokens,
    })


def _should_stop(pid: int) -> bool:
    return task_manager.is_stop_requested(pid)


def _clean_code(text: str) -> str:
    text = (text or "").strip()
    text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text[:20000]


# ---------------------------------------------------------------------------
# 隔离环境准备
# ---------------------------------------------------------------------------

async def prepare_isolation(pid: int, source_path: str, cfg: dict[str, Any]) -> tuple[bool, str]:
    def work():
        if not iso.docker_available():
            return False, "Docker 不可用，无法创建隔离环境。"
        image = cfg.get("docker_image") or settings.docker_image
        try:
            iso.ensure_image(image, settings.dockerfile_dir)
            env_id = iso.create_environment(
                pid,
                source_path,
                str(settings.workspace_dir / str(pid)),
                image,
                int(cfg.get("isolation_target_port") or settings.isolation_target_port),
            )
            return True, env_id
        except Exception as exc:  # noqa: BLE001
            return False, f"隔离环境准备失败：{exc}"

    ok, detail = await asyncio.to_thread(work)
    if ok:
        def save(db):
            project = db.get(Project, pid)
            if project:
                project.isolation_env_id = detail
                db.commit()

        await _run_db(save)
        await _log(pid, f"Docker 隔离环境已就绪，环境编号 {detail}")
        await _chat(pid, roles.ROLE_OPS, f"隔离环境已创建：{detail}", "info")
    else:
        await _log(pid, detail, level="warning")
        await _chat(pid, roles.ROLE_OPS, detail, "warning")
    return ok, detail


# ---------------------------------------------------------------------------
# 阶段 1：环境检查
# ---------------------------------------------------------------------------

async def _env_checker_worker(pid: int, stage_id: int, state: dict, files: list[str]) -> dict:
    role = roles.ROLE_ENV
    wid = await _worker_start(pid, stage_id, role, "识别项目语言、依赖与入口文件")
    tokens = 0
    try:
        dep_snippets = []
        for name in ("requirements.txt", "pyproject.toml", "package.json", "pom.xml", "go.mod", "Gemfile"):
            if name in files:
                dep_snippets.append(f"### {name}\n{tools.read_text(state['source_path'], name, 4000)}")
        user_prompt = (
            f"项目名称：{state['project_name']}\n"
            f"任务说明：{state['task_content']}\n"
            f"源码文件（前 120 个）：\n" + "\n".join(files[:120]) +
            ("\n\n依赖文件内容：\n" + "\n\n".join(dep_snippets) if dep_snippets else "\n\n未发现常见依赖文件。") +
            "\n\n请输出 JSON：{\"summary\":..., \"language\":..., \"entry_candidates\":[...], "
            "\"dependencies\":[...], \"environment_ok\":true/false, \"notes\":...}"
        )
        result, tokens = await llm.complete_json(
            "env_scan", roles.ROLES[role]["system"], user_prompt, state["cfg"]
        )
        add_tokens(pid, tokens)
        summary = result.get("summary") or "环境检查完成"
        await _chat(pid, role, summary, "result")
        await _worker_finish(pid, wid, role, "success", summary=summary, tokens=tokens)
        return result
    except Exception as exc:  # noqa: BLE001
        fallback = {
            "summary": f"模型环境检查失败，使用本地目录信息：{exc}",
            "language": "未知",
            "entry_candidates": tools.detect_entry_candidates(state["source_path"]),
            "dependencies": [],
            "environment_ok": bool(files),
        }
        await _worker_finish(pid, wid, role, "failed", error=str(exc), tokens=tokens)
        await _log(pid, f"环境检查角色失败：{exc}", level="error", stage_id=stage_id, worker_id=wid)
        return fallback


async def _ops_worker(pid: int, stage_id: int, state: dict, container_ready: bool) -> dict:
    role = roles.ROLE_OPS
    wid = await _worker_start(pid, stage_id, role, "检查隔离环境与运行资源")
    tokens = 0
    try:
        docker_ok = await asyncio.to_thread(iso.docker_available)
        container = await asyncio.to_thread(iso.get_container_by_project, pid) if docker_ok else None
        status_text = {
            "docker_available": docker_ok,
            "container_ready": bool(container),
            "container_status": container.status if container else "none",
            "isolation_env_id": state.get("isolation_env_id", ""),
        }
        user_prompt = (
            f"隔离环境检查结果：{status_text}\n"
            f"项目：{state['project_name']}\n任务：{state['task_content']}\n"
            "请输出 JSON：{\"summary\":..., \"environment_ok\":true/false, "
            "\"docker_status\":..., \"recommendation\":...}"
        )
        result, tokens = await llm.complete_json(
            "ops", roles.ROLES[role]["system"], user_prompt, state["cfg"]
        )
        add_tokens(pid, tokens)
        summary = result.get("summary") or "隔离环境检查完成"
        await _chat(pid, role, summary, "result")
        await _worker_finish(pid, wid, role, "success", summary=summary, tokens=tokens)
        return result
    except Exception as exc:  # noqa: BLE001
        await _worker_finish(pid, wid, role, "failed", error=str(exc), tokens=tokens)
        return {"summary": f"运维检查失败：{exc}", "environment_ok": container_ready}


async def environment_scan_node(state: dict) -> dict:
    pid = state["project_id"]
    if _should_stop(pid):
        state["stopped"] = True
        return state
    name = "environment_scan"
    stage_id = await _stage_start(pid, name)
    files = await asyncio.to_thread(tools.iter_source_files, state["source_path"])
    if not files:
        error = "未发现可读源码文件，请检查源码路径"
        await _log(pid, error, level="warning", stage_id=stage_id)
        state["error"] = error
        await _stage_finish(pid, stage_id, name, "failed", error)
        return state

    env_res, ops_res = await asyncio.gather(
        _env_checker_worker(pid, stage_id, state, files),
        _ops_worker(pid, stage_id, state, state.get("container_ready", False)),
        return_exceptions=True,
    )
    if isinstance(env_res, Exception):
        env_res = {"summary": str(env_res)}
    state["env_result"] = env_res if isinstance(env_res, dict) else {}
    state["files"] = files

    if _should_stop(pid):
        await _stage_finish(pid, stage_id, name, "stopped")
        state["stopped"] = True
    else:
        await _stage_finish(pid, stage_id, name, "success")
    return state


# ---------------------------------------------------------------------------
# 阶段 2：代码分析
# ---------------------------------------------------------------------------

async def _general_worker(pid: int, stage_id: int, state: dict, files: list[str]) -> dict:
    role = roles.ROLE_GENERAL
    wid = await _worker_start(pid, stage_id, role, "拆解评估任务并确定审计重点")
    tokens = 0
    try:
        user_prompt = (
            f"项目名称：{state['project_name']}\n"
            f"任务说明：{state['task_content']}\n"
            f"环境检查结论：{state.get('env_result', {})}\n"
            f"源码文件（前 120 个）：\n" + "\n".join(files[:120]) +
            "\n\n请输出 JSON：{\"strategy\":..., \"focus_files\":[...], \"risk_areas\":[...]}"
        )
        result, tokens = await llm.complete_json(
            "plan_analysis", roles.ROLES[role]["system"], user_prompt, state["cfg"]
        )
        add_tokens(pid, tokens)
        summary = result.get("strategy") or "已完成分析计划"
        await _chat(pid, role, summary, "plan")
        await _worker_finish(pid, wid, role, "success", summary=summary, tokens=tokens)
        return result
    except Exception as exc:  # noqa: BLE001
        fallback = {
            "focus_files": files[:20],
            "risk_areas": ["SQL 注入", "命令注入", "XSS", "路径穿越", "硬编码密钥"],
            "strategy": f"模型计划失败，改为按入口与高风险关键字审计：{exc}",
        }
        await _worker_finish(pid, wid, role, "failed", error=str(exc), tokens=tokens)
        await _log(pid, f"通用处理角色失败：{exc}", level="error", stage_id=stage_id, worker_id=wid)
        return fallback


async def _analyst_worker(pid: int, stage_id: int, state: dict, plan: dict) -> list[dict]:
    role = roles.ROLE_ANALYST
    wid = await _worker_start(pid, stage_id, role, "审计源码并识别潜在漏洞")
    tokens = 0
    llm_error = ""
    raw: list[dict] = []
    try:
        focus = [f for f in (plan.get("focus_files") or []) if isinstance(f, str)]
        context = await asyncio.to_thread(
            tools.collect_context,
            state["source_path"],
            focus,
            int(state["cfg"].get("max_context_chars") or settings.max_context_chars),
            int(state["cfg"].get("max_read_files") or settings.max_read_files),
        )
        keyword_hits = await asyncio.to_thread(tools.search_keywords, state["source_path"])
        user_prompt = (
            f"项目名称：{state['project_name']}\n任务说明：{state['task_content']}\n"
            f"风险关注点：{plan.get('risk_areas', [])}\n\n"
            f"{context}\n\n## 关键字搜索结果\n{keyword_hits}\n\n"
            "请输出 JSON：{\"vulnerabilities\":[{\"vuln_title\":..., \"vuln_type\":"
            "\"sqli|command_injection|xss|path_traversal|hardcoded_secret|weak_auth|ssrf|deserialization|other\", "
            "\"risk_level\":\"critical|high|medium|low\", \"file_path\":..., \"line\":数字, \"impact_text\":..., "
            "\"condition_text\":..., \"evidence_text\":..., \"recommendation_text\":...}]}"
        )
        result, tokens = await llm.complete_json(
            "analyze_code", roles.ROLES[role]["system"], user_prompt, state["cfg"]
        )
        add_tokens(pid, tokens)
        raw = [v for v in (result.get("vulnerabilities") or []) if isinstance(v, dict)]
    except Exception as exc:  # noqa: BLE001
        llm_error = str(exc)
        await _log(
            pid, f"代码分析模型失败，启用静态规则兜底：{exc}",
            level="error", stage_id=stage_id, worker_id=wid,
        )

    static_findings = await asyncio.to_thread(tools.static_scan, state["source_path"])
    saved_rows = await _run_db(
        lambda db: vuln_service.save_vulnerabilities(db, pid, raw + static_findings)
    )
    saved = [vuln_service.vuln_dict(row, detail=True) for row in saved_rows]
    for v in saved:
        await broker.publish(pid, {
            "type": "vulnerability_found",
            "vuln_id": v["id"],
            "vuln_title": v["vuln_title"],
            "risk_level": v["risk_level"],
            "risk_score": v["risk_score"],
        })
    summary = f"发现 {len(saved)} 个疑似漏洞"
    if static_findings:
        summary += "（含静态规则补充）"
    if saved:
        summary += "：" + "、".join(v["vuln_title"] for v in saved[:6])
    await _chat(pid, role, summary, "result")
    await _worker_finish(
        pid, wid, role, "failed" if llm_error else "success",
        summary=summary, error=llm_error or None, tokens=tokens,
    )
    return saved


async def code_analysis_node(state: dict) -> dict:
    pid = state["project_id"]
    if _should_stop(pid):
        state["stopped"] = True
        return state
    name = "code_analysis"
    stage_id = await _stage_start(pid, name)
    files = state.get("files") or await asyncio.to_thread(
        tools.iter_source_files, state["source_path"]
    )

    plan = await _general_worker(pid, stage_id, state, files)
    state["plan_result"] = plan

    if _should_stop(pid):
        await _stage_finish(pid, stage_id, name, "stopped")
        state["stopped"] = True
        return state

    vulns = await _analyst_worker(pid, stage_id, state, plan)
    state["vulnerabilities"] = vulns
    await _stage_finish(pid, stage_id, name, "success")
    return state


# ---------------------------------------------------------------------------
# 阶段 3：漏洞验证
# ---------------------------------------------------------------------------

async def _verify_one(
    pid: int,
    stage_id: int,
    vuln: dict,
    state: dict,
    container_ready: bool,
    sem: asyncio.Semaphore,
) -> dict:
    async with sem:
        role = roles.ROLE_VERIFIER
        if _should_stop(pid):
            return vuln
        wid = await _worker_start(pid, stage_id, role, f"验证漏洞 {vuln['vuln_code']} {vuln['vuln_title']}")
        tokens = 0
        llm_error = ""
        result: dict[str, Any] = {
            "verified": False,
            "verify_status": "unverified",
            "evidence_text": "",
            "reproduce_steps_text": "",
            "verify_code_text": "",
        }
        try:
            snippet = ""
            if vuln.get("file_path"):
                snippet = await asyncio.to_thread(
                    tools.read_text, state["source_path"], vuln["file_path"], 8000
                )
            target = f"http://127.0.0.1:{state['cfg'].get('isolation_target_port', 5000)}"
            user_prompt = (
                f"漏洞编号：{vuln['vuln_code']}\n漏洞标题：{vuln['vuln_title']}\n"
                f"风险等级：{vuln['risk_level']}\n文件：{vuln.get('file_path')}:{vuln.get('line_number')}\n"
                f"触发条件：{vuln.get('condition_text')}\n证据：{vuln.get('evidence_text')}\n\n"
                f"## 相关源码\n```\n{snippet}\n```\n\n"
                f"隔离容器可用：{container_ready}；目标应用地址：{target}\n"
                "请判断可利用性并给出验证脚本。脚本将在容器内执行，成功时打印 SAS_POC_SUCCESS。\n"
                "输出 JSON：{\"verified\":true/false, \"verify_status\":\"verified|unverified\", "
                "\"impact_text\":..., \"evidence_text\":..., \"reproduce_steps_text\":..., "
                "\"verify_code_text\":\"完整 python 脚本\"}"
            )
            result, tokens = await llm.complete_json(
                "verify", roles.ROLES[role]["system"], user_prompt, state["cfg"]
            )
            add_tokens(pid, tokens)
        except Exception as exc:  # noqa: BLE001
            llm_error = str(exc)
            result["evidence_text"] = f"验证模型调用失败：{exc}"

        status = "unverified"
        prefix = ""
        poc = _clean_code(result.get("verify_code_text") or "")
        dynamic_ok = False
        dynamic_output = ""
        if container_ready and state["cfg"].get("enable_dynamic_verify", True) and poc.strip():
            poc_path = settings.workspace_dir / str(pid) / f"poc_{vuln['id']}.py"
            poc_path.write_text(poc, encoding="utf-8")
            try:
                code, output = await asyncio.to_thread(
                    iso.exec_command, pid, f"python /workspace/poc_{vuln['id']}.py", 60
                )
                dynamic_output = output
                dynamic_ok = code == 0 and "SAS_POC_SUCCESS" in output
                prefix = (
                    f"[动态验证通过] 容器执行退出码 {code}\n{output[:2000]}"
                    if dynamic_ok
                    else f"[动态验证未复现] 容器执行退出码 {code}\n{output[:2000]}"
                )
            except Exception as exc:  # noqa: BLE001
                prefix = f"[动态验证失败] {exc}"
        elif not container_ready and result.get("verified"):
            status = "statically_confirmed"
            prefix = "[静态确认] 隔离环境不可用，基于源码推理确认可达性"
        if dynamic_ok:
            status = "verified"
        elif status != "statically_confirmed":
            status = "unverified"
            if not prefix:
                prefix = "[静态推理] 未执行动态 PoC"

        def work(db):
            row = vuln_service.update_verification(
                db, vuln["id"], result, status, prefix, tokens=tokens
            )
            return vuln_service.vuln_dict(row, detail=True) if row else vuln

        updated = await _run_db(work)
        await broker.publish(pid, {
            "type": "vulnerability_updated", "vuln_id": vuln["id"],
            "verify_status": status, "risk_score": updated.get("risk_score"),
        })
        await _chat(
            pid, role,
            f"{vuln['vuln_code']} {vuln['vuln_title']}：{status}"
            + ("（动态复现成功）" if dynamic_ok else ""),
            "result",
        )
        await _worker_finish(
            pid, wid, role,
            "failed" if llm_error else "success",
            summary=f"验证状态：{status}",
            error=llm_error or None,
            tokens=tokens,
        )
        updated["_dynamic_output"] = dynamic_output
        return updated


async def vulnerability_verify_node(state: dict) -> dict:
    pid = state["project_id"]
    if _should_stop(pid):
        state["stopped"] = True
        return state
    name = "vulnerability_verify"
    stage_id = await _stage_start(pid, name)
    vulns = state.get("vulnerabilities") or []
    if not vulns:
        await _log(pid, "没有待验证漏洞，跳过动态验证", level="warning", stage_id=stage_id)
        await _stage_finish(pid, stage_id, name, "success")
        return state

    container_ready = bool(state.get("container_ready"))
    port = int(state["cfg"].get("isolation_target_port") or settings.isolation_target_port)
    if container_ready and state["cfg"].get("enable_dynamic_verify", True):
        entries = (state.get("env_result") or {}).get("entry_candidates") or []
        if not entries:
            entries = await asyncio.to_thread(tools.detect_entry_candidates, state["source_path"])
        entry = (entries or ["app.py"])[0]
        ok, detail = await asyncio.to_thread(iso.start_target_app, pid, entry, port)
        await _log(
            pid, f"目标应用启动检查（{entry}）：{detail}",
            level="info" if ok else "warning", stage_id=stage_id,
        )
        if not ok:
            container_ready = False

    sem = asyncio.Semaphore(max(1, int(state["cfg"].get("max_concurrency") or 3)))
    results = await asyncio.gather(
        *[_verify_one(pid, stage_id, v, state, container_ready, sem) for v in vulns],
        return_exceptions=True,
    )
    state["vulnerabilities"] = [r for r in results if isinstance(r, dict)]

    if _should_stop(pid):
        await _stage_finish(pid, stage_id, name, "stopped")
        state["stopped"] = True
    else:
        await _stage_finish(pid, stage_id, name, "success")
    return state


# ---------------------------------------------------------------------------
# 阶段 4：攻击路径与报告
# ---------------------------------------------------------------------------

def _vulns_brief(vulns: list[dict]) -> str:
    lines = []
    for v in vulns:
        lines.append(
            f"- {v.get('vuln_code')} | {v.get('vuln_title')} | 类型:{v.get('vuln_type')} | "
            f"风险:{v.get('risk_level')} | 位置:{v.get('file_path')}:{v.get('line_number')} | "
            f"验证:{v.get('verify_status')} | 影响:{v.get('impact_text') or ''}"
        )
    return "\n".join(lines) or "（无）"


async def _paths_worker(pid: int, stage_id: int, state: dict) -> list[dict]:
    role = roles.ROLE_REPORTER
    wid = await _worker_start(pid, stage_id, role, "整理攻击路径")
    tokens = 0
    try:
        user_prompt = (
            f"项目：{state['project_name']}\n任务：{state['task_content']}\n\n"
            f"漏洞清单：\n{_vulns_brief(state.get('vulnerabilities') or [])}\n\n"
            "请把相关漏洞组合为攻击路径，输出 JSON：{\"paths\":[{\"path_title\":..., "
            "\"path_summary\":..., \"final_impact_text\":..., \"steps\":[{\"vuln_code\":..., "
            "\"step_text\":...}]}]}"
        )
        result, tokens = await llm.complete_json(
            "attack_path", roles.ROLES[role]["system"], user_prompt, state["cfg"]
        )
        add_tokens(pid, tokens)
        raw_paths = [p for p in (result.get("paths") or []) if isinstance(p, dict)]
    except Exception as exc:  # noqa: BLE001
        await _log(
            pid, f"攻击路径模型失败，使用本地分组：{exc}",
            level="warning", stage_id=stage_id, worker_id=wid,
        )
        raw_paths = []

    def save(db):
        vulns = vuln_service.list_vulnerabilities(db, pid)
        generated = raw_paths or vuln_service.build_fallback_paths(vulns)
        saved = vuln_service.save_attack_paths(db, pid, generated, vulns)
        return [vuln_service.path_dict(p) for p in saved]

    saved = await _run_db(save)
    await _chat(pid, role, f"生成 {len(saved)} 条攻击路径", "result")
    await _worker_finish(pid, wid, role, "success", summary=f"攻击路径 {len(saved)} 条", tokens=tokens)
    return saved


def _fallback_report(state: dict, paths: list[dict]) -> str:
    vulns = state.get("vulnerabilities") or []
    lines = [
        f"# {state['project_name']} 安全评估报告",
        "",
        "## 项目概述",
        f"- 源码来源：{state['source_type']} · {state['source_path']}",
        f"- 任务说明：{state['task_content'] or '（未填写）'}",
        "",
        "## 执行过程",
        "环境检查 → 代码分析 → 漏洞验证 → 报告生成。",
        "",
        "## 漏洞汇总",
        f"共 {len(vulns)} 个漏洞。",
        "",
    ]
    for v in vulns:
        lines.append(
            f"### {v.get('vuln_code')} {v.get('vuln_title')}（{v.get('risk_level')}）\n"
            f"- 位置：{v.get('file_path')}:{v.get('line_number')}\n"
            f"- 类型：{v.get('vuln_type_label') or v.get('vuln_type')}\n"
            f"- 验证状态：{v.get('verify_status')}\n"
            f"- 影响：{v.get('impact_text') or ''}\n"
            f"- 建议：{v.get('recommendation_text') or ''}\n"
        )
    lines += ["## 攻击路径", f"共 {len(paths)} 条。", ""]
    for p in paths:
        lines.append(f"- {p.get('path_code')} {p.get('path_title')}：{p.get('path_summary') or ''}")
    lines += [
        "",
        "## 风险结论",
        "请优先修复高危与严重漏洞。",
        "",
        "## 修复建议",
        "使用参数化查询、避免命令拼接、输出转义、路径规范化，并移除硬编码密钥。",
    ]
    return "\n".join(lines)


async def _report_worker(pid: int, stage_id: int, state: dict, paths: list[dict]) -> str:
    role = roles.ROLE_REPORTER
    wid = await _worker_start(pid, stage_id, role, "生成最终安全评估报告")
    tokens = 0
    try:
        await _run_db(lambda db: report_service.start_report(db, pid))
        user_prompt = (
            f"项目：{state['project_name']}\n源码：{state['source_path']}\n任务：{state['task_content']}\n\n"
            f"漏洞清单：\n{_vulns_brief(state.get('vulnerabilities') or [])}\n\n"
            f"攻击路径数量：{len(paths)}\n"
            f"攻击路径摘要：{[p.get('path_title') for p in paths]}\n\n"
            "请输出 JSON：{\"report_markdown\": \"完整 Markdown 报告\"}，报告必须包含："
            "项目概述、执行过程、漏洞汇总、攻击路径、风险结论、修复建议。"
        )
        try:
            result, tokens = await llm.complete_json(
                "report", roles.ROLES[role]["system"], user_prompt, state["cfg"]
            )
            add_tokens(pid, tokens)
            markdown_text = result.get("report_markdown") or ""
        except Exception as exc:  # noqa: BLE001
            await _log(pid, f"报告模型调用失败，使用本地汇总：{exc}", level="warning", stage_id=stage_id)
            markdown_text = ""
        if not markdown_text.strip():
            markdown_text = _fallback_report(state, paths)

        info = await _run_db(lambda db: _save_report_info(db, pid, markdown_text))
        await broker.publish(pid, {"type": "report_ready", "project_id": pid, "report_id": info["id"]})
        await _chat(pid, role, "最终安全评估报告已生成", "result")
        await _worker_finish(pid, wid, role, "success", summary=f"报告已生成（#{info['id']}）", tokens=tokens)
        return markdown_text
    except Exception as exc:  # noqa: BLE001
        await _run_db(lambda db: report_service.mark_failed(db, pid, str(exc)))
        await _worker_finish(pid, wid, role, "failed", error=str(exc), tokens=tokens)
        await _log(pid, f"报告生成失败：{exc}", level="error", stage_id=stage_id, worker_id=wid)
        raise


def _save_report_info(db, pid: int, markdown_text: str) -> dict:
    row = report_service.save_report(db, pid, markdown_text)
    return {"id": row.id, "path": row.report_file_path}


async def report_generate_node(state: dict) -> dict:
    pid = state["project_id"]
    if _should_stop(pid):
        state["stopped"] = True
        return state
    name = "report_generate"
    stage_id = await _stage_start(pid, name)

    paths = await _paths_worker(pid, stage_id, state)
    state["paths"] = paths

    if _should_stop(pid):
        await _stage_finish(pid, stage_id, name, "stopped")
        state["stopped"] = True
        return state

    markdown_text = await _report_worker(pid, stage_id, state, paths)
    state["report_markdown"] = markdown_text
    await _stage_finish(pid, stage_id, name, "success")
    return state


async def done_node(state: dict) -> dict:
    pid = state["project_id"]
    if state.get("stopped") or state.get("error"):
        return state
    stage_id = await _stage_start(pid, "done")
    await _stage_finish(pid, stage_id, "done", "success")
    return state


# ---------------------------------------------------------------------------
# 资源采样
# ---------------------------------------------------------------------------

async def resource_sampler(pid: int, stop_event: asyncio.Event, interval: int = 3) -> None:
    psutil.cpu_percent(interval=None)
    while not stop_event.is_set():
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        try:
            stats = await asyncio.to_thread(iso.container_stats, pid)
        except Exception:  # Docker 不可用时不中断采样
            stats = None
        if stats:
            cpu = stats[0]
            total_mb = max(1.0, psutil.virtual_memory().total / (1024 * 1024))
            mem = round(min(100.0, stats[1] / total_mb * 100), 2)

        try:
            data = await _run_db(
                lambda db: monitor_service.resource_dict(
                    monitor_service.add_resource(db, pid, cpu, mem, get_tokens(pid))
                )
            )
            await broker.publish(pid, {"type": "resource_usage", **data})
        except Exception as exc:  # noqa: BLE001
            logger.debug("资源采样写入失败：%s", exc)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=max(1, int(interval)))
        except asyncio.TimeoutError:
            continue
