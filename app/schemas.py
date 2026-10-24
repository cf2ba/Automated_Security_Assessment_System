"""请求/响应数据结构。"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class InitRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    status: str


class ProjectCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=128)
    source_type: Literal["local", "git"] = "local"
    source_path: str = Field(min_length=1)
    task_content: str = ""
    isolation_type: str = "docker"


class ConfigUpdate(BaseModel):
    values: dict[str, Any]


class MessageOut(BaseModel):
    message: str
    detail: Any | None = None
