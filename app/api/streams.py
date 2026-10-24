"""WebSocket 实时订阅：鉴权、快照、断线回放与心跳。"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.events import broker
from app.database import SessionLocal
from app.models import Project, ResourceUsage, RuntimeStage, User, WorkerTask
from app.services import project_service, report_service, stage_service, vuln_service

router = APIRouter(tags=["stream"])

HEARTBEAT_SECONDS = 20


def _is_active_user(user_id: int) -> bool:
    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        return bool(user and user.status == "active")
    finally:
        db.close()


def _project_exists(project_id: int) -> bool:
    db = SessionLocal()
    try:
        return db.get(Project, project_id) is not None
    finally:
        db.close()


def _build_snapshot(project_id: int, last_seq: int) -> dict | None:
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            return None
        stages = (
            db.query(RuntimeStage)
            .filter(RuntimeStage.project_id == project_id)
            .order_by(RuntimeStage.id.asc())
            .all()
        )
        workers = (
            db.query(WorkerTask)
            .filter(WorkerTask.project_id == project_id)
            .order_by(WorkerTask.id.asc())
            .all()
        )
        latest = (
            db.query(ResourceUsage)
            .filter(ResourceUsage.project_id == project_id)
            .order_by(ResourceUsage.id.desc())
            .first()
        )
        report = report_service.get_latest_report(db, project_id)
        stage_names = {s.id: s.stage_name for s in stages}
        return {
            "type": "snapshot",
            "seq": last_seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "project": {
                "id": project.id,
                "project_name": project.project_name,
                "source_type": project.source_type,
                "source_path": project.source_path,
                "project_status": project.project_status,
                "run_no": project.run_no,
                "error_message": project.error_message,
                "last_started_at": project.last_started_at.isoformat() if project.last_started_at else None,
                "last_finished_at": project.last_finished_at.isoformat() if project.last_finished_at else None,
            },
            "stages": [stage_service.stage_dict(s) for s in stages],
            "workers": [stage_service.worker_dict(w, stage_names.get(w.stage_id)) for w in workers],
            "latest_resources": {
                "cpu_usage": latest.cpu_usage,
                "memory_usage": latest.memory_usage,
                "token_count": latest.token_count,
                "recorded_at": latest.recorded_at.isoformat() if latest and latest.recorded_at else None,
            } if latest else None,
            "report": {
                "report_status": report.report_status,
                "report_id": report.id,
            } if report else None,
            "risk_summary": vuln_service.risk_summary(db, project_id),
            "last_seq": last_seq,
            "reset": False,
        }
    finally:
        db.close()


async def _send(websocket: WebSocket, payload: dict) -> bool:
    try:
        await websocket.send_json(payload)
        return True
    except (WebSocketDisconnect, RuntimeError):
        return False


@router.websocket("/api/projects/{project_id}/stream")
async def project_stream(websocket: WebSocket, project_id: int) -> None:
    await websocket.accept()
    session = websocket.scope.get("session") or {}
    user_id = session.get("user_id")
    if not user_id or not await asyncio.to_thread(_is_active_user, int(user_id)):
        await websocket.close(code=4401)
        return
    if not await asyncio.to_thread(_project_exists, project_id):
        await websocket.close(code=4404)
        return

    try:
        after_seq = int(websocket.query_params.get("after_seq") or 0)
    except ValueError:
        after_seq = 0
    if after_seq < 0:
        after_seq = 0

    queue = broker.subscribe(project_id)
    try:
        current_seq = broker.last_seq(project_id)
        if after_seq > 0 and broker.replay_available(project_id, after_seq):
            for event in broker.events_after(project_id, after_seq):
                if not await _send(websocket, event):
                    return
        else:
            snapshot = await asyncio.to_thread(_build_snapshot, project_id, current_seq)
            if snapshot is None:
                await websocket.close(code=4404)
                return
            snapshot["reset"] = bool(after_seq > 0)
            if not await _send(websocket, snapshot):
                return
        await _send(websocket, {
            "type": "connected",
            "project_id": project_id,
            "last_seq": current_seq,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                if not await _send(websocket, {
                    "type": "heartbeat",
                    "ts": datetime.now(timezone.utc).isoformat(),
                }):
                    return
                continue
            if event.get("seq", 0) <= current_seq:
                continue
            if not await _send(websocket, event):
                return
    except WebSocketDisconnect:
        pass
    except RuntimeError:
        pass
    finally:
        broker.unsubscribe(project_id, queue)
