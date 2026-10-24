"""阶段与角色任务的状态读写。"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Project, RuntimeStage, WorkerTask, utcnow

STAGES = ("environment_scan", "code_analysis", "vulnerability_verify", "report_generate", "done")


def create_stages(db: Session, project_id: int) -> list[RuntimeStage]:
    rows = []
    for name in STAGES:
        row = RuntimeStage(
            project_id=project_id,
            stage_name=name,
            stage_status="pending",
        )
        db.add(row)
        rows.append(row)
    db.flush()
    return rows


def get_stage(db: Session, project_id: int, stage_name: str) -> RuntimeStage | None:
    return (
        db.query(RuntimeStage)
        .filter(RuntimeStage.project_id == project_id, RuntimeStage.stage_name == stage_name)
        .first()
    )


def start_stage(db: Session, project_id: int, stage_name: str) -> int:
    row = get_stage(db, project_id, stage_name)
    if row is None:
        row = RuntimeStage(project_id=project_id, stage_name=stage_name)
        db.add(row)
    row.stage_status = "running"
    row.started_at = utcnow()
    row.finished_at = None
    row.error_message = None
    db.commit()
    db.refresh(row)
    return row.id


def finish_stage(
    db: Session,
    project_id: int,
    stage_name: str,
    status: str,
    error: str | None = None,
) -> None:
    row = get_stage(db, project_id, stage_name)
    if row is None:
        row = RuntimeStage(project_id=project_id, stage_name=stage_name)
        db.add(row)
    row.stage_status = status
    row.finished_at = utcnow()
    row.error_message = error
    db.commit()


def finish_unfinished(db: Session, project_id: int, final_status: str) -> None:
    """项目停止/失败时收尾：运行中的阶段置对应状态，未开始的阶段置 skipped。"""
    stage_status = "stopped" if final_status == "stopped" else "failed"
    stages = db.query(RuntimeStage).filter(RuntimeStage.project_id == project_id).all()
    for row in stages:
        if row.stage_status == "running":
            row.stage_status = stage_status
            row.finished_at = utcnow()
        elif row.stage_status == "pending":
            row.stage_status = "skipped"
            row.finished_at = utcnow()
    workers = (
        db.query(WorkerTask)
        .filter(WorkerTask.project_id == project_id, WorkerTask.task_status == "running")
        .all()
    )
    for row in workers:
        row.task_status = stage_status
        row.finished_at = utcnow()
    db.commit()


def start_worker(db: Session, project_id: int, stage_id: int, role: str, content: str) -> int:
    row = WorkerTask(
        project_id=project_id,
        stage_id=stage_id,
        worker_role=role,
        task_content=content,
        task_status="running",
        started_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row.id


def finish_worker(
    db: Session,
    worker_id: int,
    status: str,
    summary: str | None = None,
    error: str | None = None,
    tokens: int = 0,
) -> None:
    row = db.get(WorkerTask, worker_id)
    if not row:
        return
    row.task_status = status
    row.result_summary = summary
    row.error_message = error
    row.token_count = int(tokens or 0)
    row.finished_at = utcnow()
    db.commit()


def stage_dict(row: RuntimeStage) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "stage_name": row.stage_name,
        "stage_status": row.stage_status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "error_message": row.error_message,
    }


def worker_dict(row: WorkerTask, stage_name: str | None = None) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "stage_id": row.stage_id,
        "stage_name": stage_name,
        "worker_role": row.worker_role,
        "task_content": row.task_content,
        "task_status": row.task_status,
        "result_summary": row.result_summary,
        "error_message": row.error_message,
        "token_count": row.token_count,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


def recover_running(db: Session) -> int:
    """服务重启后把遗留的 running 记录置为 failed，不自动续跑。"""
    count = 0
    projects = db.query(Project).filter(Project.project_status == "running").all()
    for p in projects:
        p.project_status = "failed"
        p.error_message = "服务重启导致任务中断"
        p.last_finished_at = utcnow()
        count += 1
    stages = db.query(RuntimeStage).filter(RuntimeStage.stage_status == "running").all()
    for s in stages:
        s.stage_status = "failed"
        s.finished_at = utcnow()
        s.error_message = "服务重启导致任务中断"
    workers = db.query(WorkerTask).filter(WorkerTask.task_status == "running").all()
    for w in workers:
        w.task_status = "failed"
        w.finished_at = utcnow()
        w.error_message = "服务重启导致任务中断"
    if count or stages or workers:
        db.commit()
    return count
