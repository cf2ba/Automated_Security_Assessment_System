"""运行时系统配置：数据库 system_configs 覆盖 .env 默认值；密钥只读环境变量。"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.core.errors import ConfigInvalid, ConfigSecretNotWritable
from app.models import SystemConfig

SECRET_KEYS = {"llm_api_key"}

RANGES = {
    "isolation_target_port": (1, 65535),
    "default_timeout": (60, 86400),
    "max_concurrency": (1, 16),
    "retention_days": (1, 3650),
    "resource_sample_seconds": (1, 60),
    "max_context_chars": (1000, 500000),
    "max_read_files": (1, 500),
    "llm_timeout": (10, 1800),
}


def get_defaults() -> dict[str, Any]:
    return {
        "llm_base_url": settings.llm_base_url,
        "llm_model": settings.llm_model,
        "llm_timeout": settings.llm_timeout,
        "llm_mock": settings.llm_mock,
        "docker_image": settings.docker_image,
        "isolation_target_port": settings.isolation_target_port,
        "isolation_required": settings.isolation_required,
        "enable_dynamic_verify": settings.enable_dynamic_verify,
        "default_timeout": settings.default_timeout,
        "max_concurrency": settings.max_concurrency,
        "retention_days": settings.retention_days,
        "resource_sample_seconds": settings.resource_sample_seconds,
        "max_context_chars": settings.max_context_chars,
        "max_read_files": settings.max_read_files,
        "allowed_source_roots": settings.allowed_source_roots,
    }


def get_raw_config(db: Session) -> dict[str, str]:
    rows = db.query(SystemConfig).all()
    return {row.config_key: row.config_value for row in rows}


def _coerce(key: str, value: Any, default: Any) -> Any:
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return str(value) if value is not None else default


def get_effective_config(db: Session) -> dict[str, Any]:
    defaults = get_defaults()
    raw = get_raw_config(db)
    merged = dict(defaults)
    for key, value in raw.items():
        if key in defaults and key not in SECRET_KEYS:
            merged[key] = _coerce(key, value, defaults[key])
    merged["llm_api_key"] = settings.llm_api_key
    return merged


def get_value(db: Session, key: str, default: Any = None) -> Any:
    return get_effective_config(db).get(key, default)


def get_config_for_display(db: Session) -> dict[str, Any]:
    cfg = get_effective_config(db)
    cfg.pop("llm_api_key", None)
    key = settings.llm_api_key or ""
    cfg["llm_api_key_configured"] = bool(key)
    cfg["llm_api_key_masked"] = (key[:4] + "****" + key[-4:]) if len(key) > 8 else ("****" if key else "")
    return cfg


def seed_defaults(db: Session) -> int:
    """首次初始化时写入缺失的默认配置，不覆盖已有值。"""
    defaults = get_defaults()
    existing = set(get_raw_config(db))
    added = 0
    for key, value in defaults.items():
        if key in SECRET_KEYS or key in existing:
            continue
        text = "true" if value is True else "false" if value is False else str(value)
        db.add(SystemConfig(config_key=key, config_value=text))
        added += 1
    db.commit()
    return added


def update_config(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    defaults = get_defaults()
    if "llm_api_key" in values:
        raise ConfigSecretNotWritable("API Key 只能通过环境变量 LLM_API_KEY 配置，不能在页面写入")
    for key, value in values.items():
        if key not in defaults:
            raise ConfigInvalid(f"未知配置项：{key}")
        default = defaults[key]
        if key in RANGES:
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise ConfigInvalid(f"{key} 必须是整数") from exc
            low, high = RANGES[key]
            if not low <= number <= high:
                raise ConfigInvalid(f"{key} 必须在 {low}–{high} 之间")
            value = number
        elif isinstance(default, bool):
            value = _coerce(key, value, default)
        else:
            value = str(value or "").strip()

        row = db.query(SystemConfig).filter(SystemConfig.config_key == key).first()
        text = "true" if value is True else "false" if value is False else str(value)
        if row:
            row.config_value = text
        else:
            db.add(SystemConfig(config_key=key, config_value=text))
    db.commit()
    return get_config_for_display(db)
