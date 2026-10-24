"""LangGraph 图状态定义。"""
from __future__ import annotations

from typing import Any, TypedDict


class AgentState(TypedDict, total=False):
    project_id: int
    project_name: str
    source_path: str
    source_type: str
    task_content: str
    cfg: dict[str, Any]
    container_ready: bool
    isolation_env_id: str
    env_result: dict[str, Any]
    plan_result: dict[str, Any]
    vulnerabilities: list[dict[str, Any]]
    paths: list[dict[str, Any]]
    report_markdown: str
    stopped: bool
    error: str
