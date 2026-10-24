"""ORM 实体：需求 2.5.8 的 11 张表，另加 system_configs 运行时配置表。"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def long_text():
    """MySQL 使用 MEDIUMTEXT，其他数据库退回 Text，避免长报告被 64KB 截断。"""
    return Text().with_variant(MEDIUMTEXT(), "mysql")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False, default="user")  # admin / user
    status = Column(String(16), nullable=False, default="active")  # active / disabled
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_name = Column(String(128), nullable=False)
    source_type = Column(String(16), nullable=False, default="local")  # local / git
    source_path = Column(Text, nullable=False)
    task_content = Column(Text, nullable=False, default="")
    project_status = Column(String(16), nullable=False, default="created", index=True)
    isolation_type = Column(String(16), nullable=False, default="docker")
    isolation_env_id = Column(String(128), nullable=True)
    run_no = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    last_started_at = Column(DateTime, nullable=True)
    last_finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class RuntimeStage(Base):
    __tablename__ = "runtime_stages"
    __table_args__ = (
        UniqueConstraint("project_id", "stage_name", name="uk_stage_project_name"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_name = Column(String(32), nullable=False)
    stage_status = Column(String(16), nullable=False, default="pending")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)


class WorkerTask(Base):
    __tablename__ = "worker_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("runtime_stages.id", ondelete="CASCADE"), nullable=False, index=True)
    worker_role = Column(String(32), nullable=False)
    task_content = Column(Text, nullable=False, default="")
    task_status = Column(String(16), nullable=False, default="pending")
    result_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    token_count = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("project_id", "vuln_code", name="uk_vuln_project_code"),
        Index("ix_vuln_project_risk", "project_id", "risk_level"),
        Index("ix_vuln_project_verify", "project_id", "verify_status"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_code = Column(String(32), nullable=False)
    vuln_title = Column(String(255), nullable=False)
    vuln_type = Column(String(64), nullable=False, default="other")
    risk_level = Column(String(16), nullable=False, default="medium")
    risk_score = Column(Float, nullable=False, default=0.0)
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    impact_text = Column(Text, nullable=True)
    condition_text = Column(Text, nullable=True)
    evidence_text = Column(long_text(), nullable=True)
    verify_status = Column(String(24), nullable=False, default="unverified")
    reproduce_steps_text = Column(Text, nullable=True)
    verify_code_text = Column(long_text(), nullable=True)
    recommendation_text = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class AttackPath(Base):
    __tablename__ = "attack_paths"
    __table_args__ = (UniqueConstraint("project_id", "path_code", name="uk_path_project_code"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    path_code = Column(String(32), nullable=False)
    path_title = Column(String(255), nullable=False)
    path_summary = Column(Text, nullable=True)
    final_impact_text = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    items = relationship(
        "AttackPathItem",
        cascade="all, delete-orphan",
        order_by="AttackPathItem.step_order",
        backref="path",
    )


class AttackPathItem(Base):
    __tablename__ = "attack_path_items"
    __table_args__ = (UniqueConstraint("path_id", "step_order", name="uk_path_item_order"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    path_id = Column(Integer, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True)
    step_order = Column(Integer, nullable=False, default=1)
    step_text = Column(Text, nullable=True)

    vuln = relationship("Vulnerability")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    worker_role = Column(String(32), nullable=False)
    message_type = Column(String(24), nullable=False, default="info")
    message_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class RuntimeLog(Base):
    __tablename__ = "runtime_logs"
    __table_args__ = (
        Index("ix_logs_project_time", "project_id", "created_at"),
        Index("ix_logs_project_level", "project_id", "log_level"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("runtime_stages.id", ondelete="SET NULL"), nullable=True)
    worker_task_id = Column(Integer, ForeignKey("worker_tasks.id", ondelete="SET NULL"), nullable=True)
    log_level = Column(String(16), nullable=False, default="info")
    log_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ResourceUsage(Base):
    __tablename__ = "resource_usages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    cpu_usage = Column(Float, nullable=False, default=0.0)
    memory_usage = Column(Float, nullable=False, default=0.0)
    token_count = Column(Integer, nullable=False, default=0)
    recorded_at = Column(DateTime, default=utcnow, nullable=False)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True)
    report_status = Column(String(16), nullable=False, default="generating")
    report_markdown = Column(long_text(), nullable=False, default="")
    report_html = Column(long_text(), nullable=False, default="")
    report_file_path = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class SystemConfig(Base):
    __tablename__ = "system_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(64), unique=True, nullable=False, index=True)
    config_value = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
