"""认证与系统配置接口。"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.core.errors import (
    AuthForbidden,
    AuthRequired,
    ConfigInvalid,
    RateLimited,
    SystemAlreadyInitialized,
)
from app.core.security import get_current_user, hash_password, require_admin, verify_password
from app.database import get_db
from app.isolation import docker as iso
from app.models import User, utcnow
from app.schemas import ConfigUpdate, InitRequest, LoginRequest
from app.services import config_service

router = APIRouter(prefix="/api/system", tags=["system"])

VERSION = "1.0.0"
_LOGIN_WINDOW_SECONDS = 60
_LOGIN_MAX_FAILURES = 5
_login_failures: dict[str, deque[float]] = defaultdict(deque)


def _user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "status": user.status,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _config_response(db: Session) -> dict:
    cfg = config_service.get_config_for_display(db)
    configured = bool(cfg.pop("llm_api_key_configured", False))
    masked = cfg.pop("llm_api_key_masked", "")
    return {
        "values": cfg,
        "llm_api_key_configured": configured,
        "llm_api_key_masked": masked,
    }


def _check_login_rate(ip: str) -> None:
    now = time.time()
    bucket = _login_failures[ip]
    while bucket and now - bucket[0] > _LOGIN_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _LOGIN_MAX_FAILURES:
        raise RateLimited("登录失败次数过多，请 60 秒后重试")


def _record_failure(ip: str) -> None:
    _login_failures[ip].append(time.time())


@router.get("/status")
def system_status(db: Session = Depends(get_db)) -> dict:
    return {
        "initialized": db.query(User).count() > 0,
        "version": VERSION,
        "docker_available": iso.docker_available(),
        "llm_configured": bool(settings.llm_api_key),
        "llm_mock": settings.llm_mock,
    }


@router.post("/init", status_code=201)
def system_init(payload: InitRequest, db: Session = Depends(get_db)) -> dict:
    username = payload.username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,64}", username):
        raise ConfigInvalid("用户名只能包含字母、数字、下划线，长度 3–64")
    if len(payload.password) < 8:
        raise ConfigInvalid("密码至少 8 位")

    if db.query(User).count() > 0:
        raise SystemAlreadyInitialized("系统已初始化")
    user = User(
        username=username,
        password_hash=hash_password(payload.password),
        role="admin",
        status="active",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise SystemAlreadyInitialized("系统已初始化或用户名已存在") from exc
    db.refresh(user)
    return _user_dict(user)


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    ip = request.client.host if request.client else "unknown"
    _check_login_rate(ip)
    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        _record_failure(ip)
        raise AuthRequired("用户名或密码错误")
    if user.status != "active":
        _record_failure(ip)
        raise AuthForbidden("账户已禁用")
    _login_failures.pop(ip, None)
    request.session["user_id"] = user.id
    user.last_login_at = utcnow()
    db.commit()
    db.refresh(user)
    return _user_dict(user)


@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(get_current_user)) -> Response:
    request.session.clear()
    return Response(status_code=204)


@router.get("/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return _user_dict(user)


@router.get("/config")
def get_config(user: User = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    return _config_response(db)


@router.put("/config")
def update_config(
    payload: ConfigUpdate,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    config_service.update_config(db, payload.values)
    return _config_response(db)
