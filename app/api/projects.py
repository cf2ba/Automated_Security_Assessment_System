"""项目、阶段、角色、漏洞、攻击路径、报告、日志与资源接口。"""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.agents.graph import run_assessment
from app.agents.roles import ROLES
from app.config import settings
from app.core.errors import (
    AuthForbidden,
    DockerUnavailable,
    PathNotFound,
    ProjectNotRunning,
    ProjectRunning,
    ReportNotFound,
    ReportNotReady,
    VulnerabilityNotFound,
)
from app.core.events import broker
from app.core.security import get_current_user
from app.core.task_manager import task_manager
from app.database import SessionLocal, get_db
from app.isolation import docker as iso
from app.models import (
    AttackPath,
    Project,
    Report,
    RuntimeStage,
    User,
    Vulnerability,
    WorkerTask,
)
from app.schemas import ProjectCreate
from app.services import (
    config_service,
    monitor_service,
    project_service,
    report_service,
    stage_service,
    vuln_service,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _get_project(db: Session, project_id: int) -> Project:
    return project_service.get_project(db, project_id)


def _container_status(project_id: int) -> str:
    try:
        container = iso.get_container_by_project(project_id)
        return container.status if container else "none"
    except Exception:
        return "unavailable"


def _project_detail(db: Session, project: Project) -> dict:
    data = project_service.project_dict(project)
    report = report_service.get_latest_report(db, project.id)
    latest_stage = (
        db.query(RuntimeStage)
        .filter(RuntimeStage.project_id == project.id)
        .order_by(RuntimeStage.id.desc())
        .first()
    )
    data["counts"] = {
        "vulnerabilities": vuln_service.risk_summary(db, project.id),
        "attack_paths": db.query(AttackPath)
        .filter(AttackPath.project_id == project.id)
        .count(),
    }
    data["latest_stage"] = stage_service.stage_dict(latest_stage) if latest_stage else None
    data["report"] = {
        "report_status": report.report_status if report else None,
        "report_id": report.id if report else None,
        "error_message": report.error_message if report else None,
    }
    data["container_status"] = _container_status(project.id)
    return data


@router.post("", status_code=201)
def create_project(
    payload: ProjectCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    project = project_service.create_project(
        db,
        project_name=payload.project_name,
        source_type=payload.source_type,
        source_path=payload.source_path,
        task_content=payload.task_content,
        isolation_type=payload.isolation_type,
        created_by=user.id,
    )
    return project_service.project_dict(project, db)


@router.get("")
def list_projects(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    status: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    rows, total = project_service.paginate_projects(db, page, page_size, status, keyword)
    return {
        "items": [project_service.project_dict(p, db) for p in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{project_id}")
def get_project(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    return _project_detail(db, _get_project(db, project_id))


@router.post("/{project_id}/start")
async def start_project(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    project = _get_project(db, project_id)
    if project.project_status == "running" or task_manager.is_running(project_id):
        raise ProjectRunning("该项目的评估任务已在运行")

    cfg = config_service.get_effective_config(db)
    if cfg.get("isolation_required", True):
        available = await asyncio.to_thread(iso.docker_available)
        if not available:
            raise DockerUnavailable("Docker 不可用，无法创建隔离环境")

    info = project_service.start_run(db, project_id)
    try:
        task_manager.start(project_id, lambda: run_assessment(project_id))
    except RuntimeError as exc:
        await asyncio.to_thread(
            project_service.update_status_db, project_id, "failed", "任务启动失败", True
        )
        raise ProjectRunning("该项目的评估任务已在运行") from exc
    await broker.publish(project_id, {
        "type": "project_status", "project_id": project_id, "project_status": "running",
    })
    return info


@router.post("/{project_id}/stop")
async def stop_project(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    project = _get_project(db, project_id)
    if project.project_status != "running" and not task_manager.is_running(project_id):
        raise ProjectNotRunning("项目未在运行")

    task_manager.request_stop(project_id)
    finished = await task_manager.wait_stopped(project_id, timeout=10.0)
    if not finished:
        task_manager.cancel(project_id)
        await asyncio.sleep(0.2)
    db.refresh(project)
    if project.project_status == "running":
        project_service.stop_run(db, project_id)
        db.refresh(project)
    try:
        await asyncio.to_thread(iso.stop_environment, project_id)
    except Exception:
        pass
    await broker.publish(project_id, {
        "type": "project_status", "project_id": project_id, "project_status": "stopped",
    })
    return {
        "id": project.id,
        "project_status": project.project_status,
        "finished_at": project.last_finished_at.isoformat() if project.last_finished_at else None,
    }


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: int,
    force: bool = Query(default=False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    project = _get_project(db, project_id)
    if project.created_by not in (None, user.id) and user.role != "admin":
        raise AuthForbidden("只有创建者或管理员可以删除项目")
    if project.project_status == "running":
        if not force:
            raise ProjectRunning("项目正在运行，请先停止或使用 force=true")
        task_manager.request_stop(project_id)
        if not await task_manager.wait_stopped(project_id, timeout=10.0):
            task_manager.cancel(project_id)
            await asyncio.sleep(0.2)

    def _delete() -> None:
        local = SessionLocal()
        try:
            row = local.get(Project, project_id)
            if row:
                project_service.delete_project(local, row)
        finally:
            local.close()

    await asyncio.to_thread(_delete)
    return Response(status_code=204)


@router.get("/{project_id}/stages")
def list_stages(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    rows = (
        db.query(RuntimeStage)
        .filter(RuntimeStage.project_id == project_id)
        .order_by(RuntimeStage.id.asc())
        .all()
    )
    return {"items": [stage_service.stage_dict(r) for r in rows]}


@router.get("/{project_id}/workers")
def list_workers(
    project_id: int,
    role: str | None = Query(default=None),
    task_status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    q = db.query(WorkerTask).filter(WorkerTask.project_id == project_id)
    if role:
        q = q.filter(WorkerTask.worker_role == role)
    if task_status:
        q = q.filter(WorkerTask.task_status == task_status)
    total = q.count()
    rows = (
        q.order_by(WorkerTask.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    stage_names = {
        row.id: row.stage_name
        for row in db.query(RuntimeStage).filter(RuntimeStage.project_id == project_id).all()
    }
    items = [
        stage_service.worker_dict(r, stage_names.get(r.stage_id)) for r in rows
    ]

    all_rows = db.query(WorkerTask).filter(WorkerTask.project_id == project_id).all()
    summary = []
    for role_key, meta in ROLES.items():
        role_rows = [r for r in all_rows if r.worker_role == role_key]
        latest = role_rows[-1] if role_rows else None
        summary.append({
            "role": role_key,
            "label": meta["label"],
            "status": latest.task_status if latest else "idle",
            "latest_task_id": latest.id if latest else None,
            "success_count": sum(1 for r in role_rows if r.task_status == "success"),
            "failed_count": sum(1 for r in role_rows if r.task_status == "failed"),
        })
    return {
        "items": items,
        "role_summary": summary,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{project_id}/vulnerabilities")
def list_vulnerabilities(
    project_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    risk_level: str | None = Query(default=None),
    verify_status: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    rows, total = vuln_service.paginate_vulnerabilities(
        db, project_id, page, page_size, risk_level, verify_status, keyword
    )
    return {
        "items": [vuln_service.vuln_dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{project_id}/vulnerabilities/{vuln_id}")
def get_vulnerability(
    project_id: int,
    vuln_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    row = vuln_service.get_vulnerability(db, project_id, vuln_id)
    if not row:
        raise VulnerabilityNotFound("漏洞不存在")
    return vuln_service.vuln_dict(row, detail=True)


@router.get("/{project_id}/attack-paths")
def list_attack_paths(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    rows = vuln_service.list_attack_paths(db, project_id)
    return {"items": [vuln_service.path_dict(r) for r in rows]}


@router.get("/{project_id}/attack-paths/{path_id}")
def get_attack_path(
    project_id: int,
    path_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    row = vuln_service.get_attack_path(db, project_id, path_id)
    if not row:
        raise PathNotFound("攻击路径不存在")
    return vuln_service.path_dict(row)


@router.get("/{project_id}/report")
def get_report(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    row = report_service.get_latest_report(db, project_id)
    if not row:
        raise ReportNotFound("报告尚未生成")
    if row.report_status != "ready":
        raise ReportNotReady(
            "报告生成中" if row.report_status == "generating" else "报告生成失败",
            {"report_status": row.report_status, "error_message": row.error_message},
        )
    data = report_service.report_dict(row, include_html=True)
    data["download_url"] = f"/api/projects/{project_id}/report/download?format=html"
    return data


@router.get("/{project_id}/report/download")
def download_report(
    project_id: int,
    format: str = Query(default="html", pattern="^(html|md)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    _get_project(db, project_id)
    row = report_service.get_latest_report(db, project_id)
    if not row:
        raise ReportNotFound("报告尚未生成")
    if row.report_status != "ready":
        raise ReportNotReady("报告尚未就绪")
    if format == "md":
        path = settings.report_dir / str(project_id) / "report.md"
        media = "text/markdown"
        filename = f"report-{project_id}.md"
    else:
        path = Path(row.report_file_path or "")
        media = "text/html"
        filename = f"report-{project_id}.html"
    if not path.exists():
        raise ReportNotFound("报告文件不存在")
    return FileResponse(path, media_type=media, filename=filename)


@router.get("/{project_id}/logs")
def list_logs(
    project_id: int,
    limit: int = Query(default=200, ge=1, le=1000),
    after_id: int = Query(default=0, ge=0),
    level: str | None = Query(default=None),
    stage_id: int | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    rows = monitor_service.list_logs(db, project_id, limit, after_id, level, stage_id)
    items = [monitor_service.log_dict(r) for r in rows]
    return {"items": items, "last_id": items[-1]["id"] if items else after_id}


@router.get("/{project_id}/messages")
def list_messages(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    rows = monitor_service.list_chats(db, project_id)
    return {"items": [monitor_service.chat_dict(r) for r in rows]}


@router.get("/{project_id}/resources")
def list_resources(
    project_id: int,
    limit: int = Query(default=300, ge=1, le=2000),
    since: str | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    _get_project(db, project_id)
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            since_dt = None
    rows = monitor_service.list_resources(db, project_id, limit, since_dt)
    latest = monitor_service.latest_resource(db, project_id)
    return {
        "latest": monitor_service.resource_dict(latest) if latest else None,
        "items": [monitor_service.resource_dict(r) for r in rows],
    }
