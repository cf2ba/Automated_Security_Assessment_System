from __future__ import annotations

from pathlib import Path

from tests.conftest import init_and_login

ROOT = Path(__file__).resolve().parents[1]


def test_auth_init_login_and_status(client):
    status = client.get("/api/system/status")
    assert status.status_code == 200
    assert status.json()["initialized"] is False

    init = client.post(
        "/api/system/init", json={"username": "admin", "password": "Admin@12345"}
    )
    assert init.status_code == 201, init.text

    duplicate = client.post(
        "/api/system/init", json={"username": "admin2", "password": "Admin@12345"}
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["code"] == "SYSTEM_ALREADY_INITIALIZED"

    bad = client.post("/api/system/login", json={"username": "admin", "password": "wrong-pass"})
    assert bad.status_code == 401

    login = client.post(
        "/api/system/login", json={"username": "admin", "password": "Admin@12345"}
    )
    assert login.status_code == 200, login.text
    assert login.json()["role"] == "admin"
    assert login.json()["last_login_at"]

    me = client.get("/api/system/me")
    assert me.status_code == 200
    assert me.json()["username"] == "admin"

    logout = client.post("/api/system/logout")
    assert logout.status_code == 204
    assert client.get("/api/system/me").status_code == 401


def test_protected_endpoint_requires_login(client):
    response = client.get("/api/projects")
    assert response.status_code == 401


def test_project_crud_and_pagination(auth_client):
    source = str(ROOT / "example_project")
    created = auth_client.post(
        "/api/projects",
        json={
            "project_name": "示例项目",
            "source_type": "local",
            "source_path": source,
            "task_content": "完整评估",
            "isolation_type": "docker",
        },
    )
    assert created.status_code == 201, created.text
    project = created.json()
    assert project["project_status"] == "created"
    assert project["source_type"] == "local"
    pid = project["id"]

    listing = auth_client.get("/api/projects?page=1&page_size=10")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == pid

    detail = auth_client.get(f"/api/projects/{pid}")
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["counts"]["vulnerabilities"]["total"] == 0
    assert detail_body["counts"]["attack_paths"] == 0
    assert detail_body["report"]["report_status"] is None

    report = auth_client.get(f"/api/projects/{pid}/report")
    assert report.status_code == 404
    assert report.json()["code"] == "REPORT_NOT_FOUND"

    stages = auth_client.get(f"/api/projects/{pid}/stages")
    assert stages.status_code == 200
    assert stages.json()["items"] == []

    deleted = auth_client.delete(f"/api/projects/{pid}")
    assert deleted.status_code == 204
    assert auth_client.get(f"/api/projects/{pid}").status_code == 404


def test_csrf_header_required(auth_client):
    response = auth_client.post(
        "/api/system/config",
        json={"values": {"max_concurrency": 4}},
        headers={"X-Requested-With": ""},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "CSRF_REQUIRED"


def test_config_never_returns_api_key(auth_client):
    response = auth_client.get("/api/system/config")
    assert response.status_code == 200
    body = response.json()
    assert "llm_api_key" not in body["values"]
    assert body["llm_api_key_configured"] is False

    updated = auth_client.put(
        "/api/system/config",
        json={"values": {"max_concurrency": 4, "default_timeout": 1800}},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["values"]["max_concurrency"] == 4

    rejected = auth_client.put(
        "/api/system/config", json={"values": {"llm_api_key": "sk-xxx"}}
    )
    assert rejected.status_code == 400
    assert rejected.json()["code"] == "CONFIG_SECRET_NOT_WRITABLE"

    invalid = auth_client.put(
        "/api/system/config", json={"values": {"max_concurrency": 999}}
    )
    assert invalid.status_code == 400


def test_init_password_policy(client):
    response = client.post(
        "/api/system/init", json={"username": "admin", "password": "short"}
    )
    assert response.status_code == 422


def test_static_assets_mime_and_favicon(client):
    script = client.get("/static/js/common.js")
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("application/javascript")
    assert client.get("/favicon.ico").status_code == 204


def test_invalid_source_path(auth_client):
    response = auth_client.post(
        "/api/projects",
        json={
            "project_name": "bad",
            "source_type": "local",
            "source_path": str(ROOT / "does-not-exist"),
            "task_content": "",
            "isolation_type": "docker",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "SOURCE_PATH_INVALID"
