"""测试环境：SQLite 临时库、临时数据目录、离线 LLM。"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="sas-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["SAS_DATA_DIR"] = str(_TMP / "data")
os.environ["LLM_MOCK"] = "true"
os.environ["ISOLATION_REQUIRED"] = "false"
os.environ["ENABLE_DYNAMIC_VERIFY"] = "false"
os.environ["RESOURCE_SAMPLE_SECONDS"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key"

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.core.events import broker  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.isolation import docker as iso  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    # 测试库中的项目 ID 可能与本机真实容器重名，禁止测试触碰 Docker。
    monkeypatch.setattr(iso, "docker_available", lambda: False)
    monkeypatch.setattr(iso, "ensure_image", lambda *a, **k: None)
    monkeypatch.setattr(iso, "create_environment", lambda *a, **k: "test-env")
    monkeypatch.setattr(iso, "start_target_app", lambda *a, **k: (False, "test skipped"))
    monkeypatch.setattr(iso, "exec_command", lambda *a, **k: (1, "test skipped"))
    monkeypatch.setattr(iso, "container_stats", lambda pid: None)
    monkeypatch.setattr(iso, "get_container_by_project", lambda pid: None)
    monkeypatch.setattr(iso, "stop_environment", lambda pid: None)
    monkeypatch.setattr(iso, "destroy_environment", lambda pid: None)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    broker.reset()
    for base in (settings.log_dir, settings.report_dir, settings.workspace_dir):
        if base.exists():
            for child in base.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
    settings.ensure_dirs()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        c.headers.update({"X-Requested-With": "XMLHttpRequest"})
        yield c


def init_and_login(client: TestClient, username: str = "admin", password: str = "Admin@12345") -> None:
    response = client.post("/api/system/init", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    response = client.post(
        "/api/system/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text


@pytest.fixture
def auth_client(client):
    init_and_login(client)
    return client
