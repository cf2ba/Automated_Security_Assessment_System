"""LangGraph 评估流程图与任务入口。"""
from __future__ import annotations

import asyncio
import logging

from langgraph.graph import END, START, StateGraph

from app.agents import orchestrator as orch
from app.agents.state import AgentState
from app.core.events import broker
from app.core.task_manager import task_manager
from app.database import SessionLocal
from app.isolation import docker as iso
from app.models import Project
from app.services import config_service, project_service, stage_service

logger = logging.getLogger(__name__)


def _route(state: dict) -> str:
    return "stop" if state.get("stopped") or state.get("error") else "continue"


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("environment_scan", orch.environment_scan_node)
    graph.add_node("code_analysis", orch.code_analysis_node)
    graph.add_node("vulnerability_verify", orch.vulnerability_verify_node)
    graph.add_node("report_generate", orch.report_generate_node)
    graph.add_node("done", orch.done_node)

    graph.add_edge(START, "environment_scan")
    graph.add_conditional_edges(
        "environment_scan", _route, {"continue": "code_analysis", "stop": END}
    )
    graph.add_conditional_edges(
        "code_analysis", _route, {"continue": "vulnerability_verify", "stop": END}
    )
    graph.add_conditional_edges(
        "vulnerability_verify", _route, {"continue": "report_generate", "stop": END}
    )
    graph.add_conditional_edges(
        "report_generate", _route, {"continue": "done", "stop": END}
    )
    graph.add_edge("done", END)
    return graph.compile()


def _load_project(project_id: int) -> dict | None:
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            return None
        return {
            "id": project.id,
            "project_name": project.project_name,
            "source_path": str(project_service.resolve_source_path(project)),
            "source_type": project.source_type,
            "task_content": project.task_content,
            "isolation_env_id": project.isolation_env_id or "",
        }
    finally:
        db.close()


def _load_config() -> dict:
    db = SessionLocal()
    try:
        return config_service.get_effective_config(db)
    finally:
        db.close()


async def _fail_before_run(project_id: int, detail: str) -> None:
    """隔离环境在启动前就失败：环境阶段置 failed，其余阶段 skipped。"""
    try:
        stage_id = await orch._stage_start(project_id, "environment_scan")
        await orch._stage_finish(project_id, stage_id, "environment_scan", "failed", detail)
        await asyncio.to_thread(
            _finish_unfinished_db, project_id, "failed"
        )
    except Exception as exc:  # 项目可能已被清理
        logger.warning("隔离失败收尾时写入阶段状态失败：%s", exc)


def _finish_unfinished_db(project_id: int, status: str) -> None:
    db = SessionLocal()
    try:
        stage_service.finish_unfinished(db, project_id, status)
    finally:
        db.close()


async def run_assessment(project_id: int) -> None:
    project = await asyncio.to_thread(_load_project, project_id)
    if not project:
        logger.error("项目 %s 不存在，无法启动评估", project_id)
        return

    cfg = await asyncio.to_thread(_load_config)
    orch.reset_tokens(project_id)

    container_ready, env_detail = await orch.prepare_isolation(
        project_id, project["source_path"], cfg
    )
    isolation_required = bool(cfg.get("isolation_required", True))
    if isolation_required and not container_ready:
        detail = env_detail or "隔离环境不可用"
        await _fail_before_run(project_id, detail)
        await asyncio.to_thread(
            project_service.update_status_db, project_id, "failed", detail, True
        )
        await broker.publish(project_id, {
            "type": "project_status", "project_id": project_id, "project_status": "failed",
            "error_message": detail,
        })
        await orch._log(project_id, f"评估任务终止：{detail}", level="error")
        return

    sampler_stop = asyncio.Event()
    sampler = asyncio.create_task(
        orch.resource_sampler(
            project_id,
            sampler_stop,
            int(cfg.get("resource_sample_seconds") or 3),
        )
    )

    final_status = "completed"
    error_message: str | None = None
    try:
        state: AgentState = {
            "project_id": project_id,
            "project_name": project["project_name"],
            "source_path": project["source_path"],
            "source_type": project["source_type"],
            "task_content": project["task_content"],
            "cfg": cfg,
            "container_ready": container_ready,
            "isolation_env_id": env_detail if container_ready else "",
            "vulnerabilities": [],
            "paths": [],
            "stopped": False,
            "error": "",
        }
        app_graph = build_graph()
        timeout = int(cfg.get("default_timeout") or 3600)
        final_state = await asyncio.wait_for(app_graph.ainvoke(state), timeout=timeout)

        if task_manager.is_stop_requested(project_id) or final_state.get("stopped"):
            final_status = "stopped"
            error_message = "用户手动停止"
        elif final_state.get("error"):
            final_status = "failed"
            error_message = final_state["error"]
        else:
            final_status = "completed"
    except asyncio.TimeoutError:
        final_status = "failed"
        error_message = "评估任务超时"
        logger.error("项目 %s 评估超时", project_id)
        await orch._log(project_id, error_message, level="error")
    except asyncio.CancelledError:
        final_status = "stopped"
        error_message = "评估任务被取消"
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("评估任务执行失败")
        final_status = "failed"
        error_message = str(exc)
        await orch._log(project_id, f"评估任务异常终止：{exc}", level="error")
    finally:
        sampler_stop.set()
        try:
            await asyncio.wait_for(sampler, timeout=10)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            sampler.cancel()
        if final_status != "completed":
            try:
                await asyncio.to_thread(_finish_unfinished_db, project_id, final_status)
            except Exception as exc:
                logger.warning("收尾阶段状态失败：%s", exc)
        try:
            # 按设计保留容器，便于事后排查；删除项目时再销毁。
            await asyncio.to_thread(iso.stop_environment, project_id)
        except Exception as exc:  # 环境清理失败不影响最终状态
            logger.warning("停止隔离环境失败：%s", exc)
        await asyncio.to_thread(
            project_service.update_status_db, project_id, final_status, error_message, True
        )
        await broker.publish(project_id, {
            "type": "project_status", "project_id": project_id,
            "project_status": final_status, "error_message": error_message,
        })
        await orch._log(project_id, f"评估任务结束：{final_status}", level="info")
