"""SQLAlchemy 引擎与会话管理（同步 MySQL / PyMySQL）。"""
from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

_url = make_url(settings.database_url)
if _url.drivername.startswith("sqlite"):
    _engine_kwargs = {
        "connect_args": {"check_same_thread": False, "timeout": 30},
        "pool_pre_ping": True,
        "future": True,
    }
else:
    _engine_kwargs = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "pool_size": 10,
        "max_overflow": 20,
        "future": True,
    }
engine = create_engine(settings.database_url, **_engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    # 确保模型已注册
    import app.models.entities  # noqa: F401

    Base.metadata.create_all(engine)


def ensure_database_exists() -> None:
    """在目标库不存在时创建它（供初始化脚本使用）；SQLite 直接跳过。"""
    url = make_url(settings.database_url)
    if not url.drivername.startswith("mysql"):
        return
    import pymysql

    db_name = url.database or "security_assessment"
    conn = pymysql.connect(
        host=url.host or "127.0.0.1",
        port=url.port or 3306,
        user=url.username or "root",
        password=url.password or "",
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
    finally:
        conn.close()


def healthcheck() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
