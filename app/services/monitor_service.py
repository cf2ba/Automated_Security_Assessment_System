"""运行日志、聊天消息与资源记录。"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.models import ChatMessage, ResourceUsage, RuntimeLog, utcnow


def log_dir(project_id: int) -> Path:
    d = settings.log_dir / str(project_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def add_log(
    db: Session,
    project_id: int,
    content: str,
    level: str = "info",
    stage_id: int | None = None,
    worker_task_id: int | None = None,
) -> RuntimeLog:
    row = RuntimeLog(
        project_id=project_id,
        stage_id=stage_id,
        worker_task_id=worker_task_id,
        log_level=level,
        log_content=content,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    try:
        with open(log_dir(project_id) / "runtime.log", "a", encoding="utf-8") as fh:
            fh.write(f"{row.created_at.isoformat()} [{level}] {content}\n")
    except OSError:
        pass
    return row


def add_chat(
    db: Session,
    project_id: int,
    worker_role: str,
    message_text: str,
    message_type: str = "info",
) -> ChatMessage:
    row = ChatMessage(
        project_id=project_id,
        worker_role=worker_role,
        message_type=message_type,
        message_text=message_text,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def add_resource(
    db: Session,
    project_id: int,
    cpu: float,
    memory: float,
    tokens: int,
) -> ResourceUsage:
    row = ResourceUsage(
        project_id=project_id,
        cpu_usage=round(float(cpu), 2),
        memory_usage=round(float(memory), 2),
        token_count=int(tokens),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_logs(
    db: Session,
    project_id: int,
    limit: int = 500,
    after_id: int = 0,
    level: str | None = None,
    stage_id: int | None = None,
) -> list[RuntimeLog]:
    q = db.query(RuntimeLog).filter(RuntimeLog.project_id == project_id)
    if after_id:
        q = q.filter(RuntimeLog.id > after_id)
    if level:
        q = q.filter(RuntimeLog.log_level == level)
    if stage_id:
        q = q.filter(RuntimeLog.stage_id == stage_id)
    return q.order_by(RuntimeLog.id.asc()).limit(limit).all()


def list_chats(db: Session, project_id: int, limit: int = 300) -> list[ChatMessage]:
    return (
        db.query(ChatMessage)
        .filter(ChatMessage.project_id == project_id)
        .order_by(ChatMessage.id.asc())
        .limit(limit)
        .all()
    )


def list_resources(
    db: Session,
    project_id: int,
    limit: int = 300,
    since: datetime | None = None,
) -> list[ResourceUsage]:
    q = db.query(ResourceUsage).filter(ResourceUsage.project_id == project_id)
    if since is not None:
        q = q.filter(ResourceUsage.recorded_at >= since)
    return q.order_by(ResourceUsage.id.asc()).limit(limit).all()


def latest_resource(db: Session, project_id: int) -> ResourceUsage | None:
    return (
        db.query(ResourceUsage)
        .filter(ResourceUsage.project_id == project_id)
        .order_by(ResourceUsage.id.desc())
        .first()
    )


def log_dict(row: RuntimeLog) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "stage_id": row.stage_id,
        "worker_task_id": row.worker_task_id,
        "log_level": row.log_level,
        "log_content": row.log_content,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def chat_dict(row: ChatMessage) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "worker_role": row.worker_role,
        "message_type": row.message_type,
        "message_text": row.message_text,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def resource_dict(row: ResourceUsage) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "cpu_usage": row.cpu_usage,
        "memory_usage": row.memory_usage,
        "token_count": row.token_count,
        "recorded_at": row.recorded_at.isoformat() if row.recorded_at else None,
    }
