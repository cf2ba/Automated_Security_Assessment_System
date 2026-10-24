from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.agents import graph
from app.database import SessionLocal
from app.main import app
from app.models import Project, RuntimeStage, Vulnerability
from app.services import project_service

ROOT = Path(__file__).resolve().parents[1]
SOURCE = str(ROOT / "example_project")


@pytest.mark.asyncio
async def test_end_to_end_assessment(auth_client, monkeypatch):
    created = auth_client.post(
        "/api/projects",
        json={
            "project_name": "端到端示例",
            "source_type": "local",
            "source_path": SOURCE,
            "task_content": "重点检查 Web 入口",
            "isolation_type": "docker",
        },
    )
    assert created.status_code == 201, created.text
    pid = created.json()["id"]

    async def fake_prepare(project_id, source_path, cfg):
        return False, "测试环境跳过 Docker"

    monkeypatch.setattr(graph.orch, "prepare_isolation", fake_prepare)
    monkeypatch.setattr(graph.orch.iso, "docker_available", lambda: False)
    monkeypatch.setattr(graph.orch.iso, "container_stats", lambda project_id: None)
    monkeypatch.setattr(graph.iso, "stop_environment", lambda project_id: None)

    async def fake_sampler(project_id, stop_event, interval=3):
        await stop_event.wait()

    monkeypatch.setattr(graph.orch, "resource_sampler", fake_sampler)

    db = SessionLocal()
    try:
        project_service.start_run(db, pid)
    finally:
        db.close()

    await graph.run_assessment(pid)

    db = SessionLocal()
    try:
        project = db.get(Project, pid)
        assert project is not None
        assert project.project_status == "completed"
        assert project.run_no == 1
        stages = (
            db.query(RuntimeStage)
            .filter(RuntimeStage.project_id == pid)
            .order_by(RuntimeStage.id.asc())
            .all()
        )
        assert [s.stage_name for s in stages] == [
            "environment_scan",
            "code_analysis",
            "vulnerability_verify",
            "report_generate",
            "done",
        ]
        assert all(s.stage_status == "success" for s in stages), [
            (s.stage_name, s.stage_status, s.error_message) for s in stages
        ]
        assert db.query(Vulnerability).filter(Vulnerability.project_id == pid).count() > 0
    finally:
        db.close()

    detail = auth_client.get(f"/api/projects/{pid}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["project_status"] == "completed"
    assert body["counts"]["vulnerabilities"]["total"] > 0
    assert body["counts"]["attack_paths"] > 0
    assert body["report"]["report_status"] == "ready"

    vulns = auth_client.get(f"/api/projects/{pid}/vulnerabilities?page=1&page_size=50")
    assert vulns.status_code == 200
    assert vulns.json()["total"] > 0
    assert all("risk_score" in item for item in vulns.json()["items"])

    paths = auth_client.get(f"/api/projects/{pid}/attack-paths")
    assert paths.status_code == 200
    assert len(paths.json()["items"]) > 0

    report = auth_client.get(f"/api/projects/{pid}/report")
    assert report.status_code == 200, report.text
    assert report.json()["report_status"] == "ready"
    assert "安全评估报告" in report.json()["report_markdown"]

    download = auth_client.get(f"/api/projects/{pid}/report/download?format=md")
    assert download.status_code == 200
    assert "安全评估报告" in download.text


def test_websocket_snapshot(auth_client):
    created = auth_client.post(
        "/api/projects",
        json={
            "project_name": "WS 项目",
            "source_type": "local",
            "source_path": SOURCE,
            "task_content": "",
            "isolation_type": "docker",
        },
    )
    pid = created.json()["id"]
    with auth_client.websocket_connect(f"/api/projects/{pid}/stream?after_seq=0") as ws:
        snapshot = ws.receive_json()
        assert snapshot["type"] == "snapshot"
        assert snapshot["project"]["id"] == pid
        assert snapshot["last_seq"] == 0
        connected = ws.receive_json()
        assert connected["type"] == "connected"


def test_websocket_requires_login():
    with TestClient(app) as client:
        with client.websocket_connect("/api/projects/1/stream") as ws:
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.receive_json()
            assert exc.value.code == 4401
