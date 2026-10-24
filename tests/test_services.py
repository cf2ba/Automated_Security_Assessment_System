from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.config import settings
from app.database import SessionLocal
from app.models import (
    AttackPath,
    ChatMessage,
    Project,
    Report,
    ResourceUsage,
    RuntimeLog,
    SystemConfig,
)
from app.services import (
    config_service,
    monitor_service,
    project_service,
    report_service,
    vuln_service,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = str(ROOT / "example_project")


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _create(db, name="svc-project"):
    return project_service.create_project(
        db, name, "local", SOURCE, "test", "docker", created_by=None
    )


def test_git_source_path_keeps_url_and_resolves_workspace(db, monkeypatch):
    def fake_clone(url, dest, timeout=120):
        target = Path(dest)
        target.mkdir(parents=True, exist_ok=True)
        (target / "app.py").write_text("print('ok')", encoding="utf-8")
        return str(target)

    monkeypatch.setattr(project_service.docker_iso, "clone_repo", fake_clone)
    project = project_service.create_project(
        db,
        "git-project",
        "git",
        "https://example.com/repo.git",
        "",
        "docker",
        created_by=None,
    )
    db.refresh(project)
    assert project.source_path == "https://example.com/repo.git"
    resolved = project_service.resolve_source_path(project)
    assert resolved == settings.workspace_dir / str(project.id) / "src"
    assert (resolved / "app.py").exists()


def test_reset_runtime_data_keeps_logs_and_resources(db):
    project = _create(db, "reset-project")
    pid = project.id
    monitor_service.add_log(db, pid, "历史日志")
    monitor_service.add_resource(db, pid, 1.0, 2.0, 3)
    monitor_service.add_chat(db, pid, "code_analyst", "历史消息")
    db.add(RuntimeLog(project_id=pid, log_level="info", log_content="direct"))
    db.commit()
    assert db.query(Report).count() == 0

    info = project_service.start_run(db, pid)
    assert info["run_no"] == 1
    assert db.query(RuntimeLog).filter(RuntimeLog.project_id == pid).count() == 2
    assert db.query(ResourceUsage).filter(ResourceUsage.project_id == pid).count() == 1
    assert db.query(ChatMessage).filter(ChatMessage.project_id == pid).count() == 0
    assert db.query(Report).filter(Report.project_id == pid).count() == 0
    stages = project_service.stage_service.get_stage(db, pid, "done")
    assert stages is not None


def test_delete_project_removes_files_and_database(db):
    project = _create(db, "delete-project")
    pid = project.id
    workspace = settings.workspace_dir / str(pid)
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "marker.txt").write_text("x", encoding="utf-8")
    report_dir = settings.report_dir / str(pid)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.md").write_text("x", encoding="utf-8")
    log_dir = settings.log_dir / str(pid)
    log_dir.mkdir(parents=True, exist_ok=True)

    project_service.delete_project(db, project)
    assert db.query(Project).filter(Project.id == pid).count() == 0
    assert not workspace.exists()
    assert not report_dir.exists()
    assert not log_dir.exists()


def test_delete_project_handles_readonly_git_files(db):
    project = _create(db, "readonly-delete")
    pid = project.id
    git_dir = settings.workspace_dir / str(pid) / "src" / ".git" / "objects"
    git_dir.mkdir(parents=True)
    marker = git_dir / "pack.idx"
    marker.write_text("x", encoding="utf-8")
    os.chmod(marker, stat.S_IREAD)

    project_service.delete_project(db, project)
    assert db.query(Project).filter(Project.id == pid).count() == 0
    assert not (settings.workspace_dir / str(pid)).exists()


def test_vulnerability_dedupe_and_verification(db):
    project = _create(db, "vuln-project")
    item = {
        "vuln_title": "SQL 注入",
        "vuln_type": "sqli",
        "risk_level": "high",
        "file_path": "app.py",
        "line": 10,
        "evidence_text": "execute('...' + name)",
    }
    rows = vuln_service.save_vulnerabilities(db, project.id, [item])
    assert len(rows) == 1
    rows2 = vuln_service.save_vulnerabilities(db, project.id, [dict(item, line=11)])
    assert len(rows2) == 0
    assert db.query(vuln_service.Vulnerability).count() == 1

    row = vuln_service.list_vulnerabilities(db, project.id)[0]
    verified = vuln_service.update_verification(
        db,
        row.id,
        {"evidence_text": "poc ok"},
        "verified",
        "[动态验证通过]",
        tokens=12,
    )
    assert verified.verify_status == "verified"
    assert verified.risk_score == 8.5
    assert "poc ok" in verified.evidence_text


def test_report_is_sanitized(db):
    project = _create(db, "report-project")
    markdown_text = "# 标题\n\n<script>alert(1)</script>\n\n正常内容"
    row = report_service.save_report(db, project.id, markdown_text)
    assert row.report_status == "ready"
    html = Path(row.report_file_path).read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "正常内容" in html
    assert report_service.report_dict(row)["report_status"] == "ready"


def test_config_seed_defaults_does_not_overwrite(db):
    db.add(SystemConfig(config_key="max_concurrency", config_value="7"))
    db.commit()
    added = config_service.seed_defaults(db)
    assert added > 0
    raw = config_service.get_raw_config(db)
    assert raw["max_concurrency"] == "7"
    assert "llm_api_key" not in raw


def test_static_scan_finds_example_vulnerabilities():
    from app.agents import tools

    findings = tools.static_scan(SOURCE)
    types = {item["vuln_type"] for item in findings}
    assert len(findings) >= 3
    assert "command_injection" in types
    assert "hardcoded_secret" in types
