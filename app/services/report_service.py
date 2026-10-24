"""报告生成、HTML 消毒与文件落盘。"""
from __future__ import annotations

from pathlib import Path

import bleach
import markdown as md_lib
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Report

ALLOWED_TAGS = [
    "p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "ul", "ol", "li",
    "blockquote", "code", "pre", "table", "thead", "tbody", "tr", "th", "td", "hr", "a",
]
ALLOWED_ATTRS = {"a": ["href", "title"], "th": ["align"], "td": ["align"]}


def report_dir(project_id: int) -> Path:
    d = settings.report_dir / str(project_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _render_html(markdown_text: str) -> str:
    body = md_lib.markdown(
        markdown_text,
        extensions=["tables", "fenced_code", "sane_lists"],
    )
    body = bleach.clean(
        body,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=["http", "https", "mailto"],
        strip=True,
    )
    return (
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        "<title>安全评估报告</title>"
        "<style>body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:900px;"
        "margin:40px auto;padding:0 20px;line-height:1.7;color:#1f2937}"
        "h1,h2,h3{color:#111827}pre{background:#f3f4f6;padding:12px;border-radius:8px;overflow:auto}"
        "code{background:#f3f4f6;padding:2px 5px;border-radius:4px}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #d1d5db;padding:6px 10px}"
        "</style></head><body>"
        f"{body}</body></html>"
    )


def start_report(db: Session, project_id: int) -> Report:
    row = db.query(Report).filter(Report.project_id == project_id).first()
    if row is None:
        row = Report(
            project_id=project_id,
            report_status="generating",
            report_markdown="",
            report_html="",
        )
        db.add(row)
    else:
        row.report_status = "generating"
        row.error_message = None
    db.commit()
    db.refresh(row)
    return row


def save_report(db: Session, project_id: int, markdown_text: str) -> Report:
    d = report_dir(project_id)
    md_path = d / "report.md"
    html_path = d / "report.html"
    html_doc = _render_html(markdown_text)
    md_path.write_text(markdown_text, encoding="utf-8")
    html_path.write_text(html_doc, encoding="utf-8")

    row = db.query(Report).filter(Report.project_id == project_id).first()
    if row is None:
        row = Report(project_id=project_id)
        db.add(row)
    row.report_status = "ready"
    row.report_markdown = markdown_text
    row.report_html = html_doc
    row.report_file_path = str(html_path)
    row.error_message = None
    db.commit()
    db.refresh(row)
    return row


def mark_failed(db: Session, project_id: int, error: str) -> None:
    row = db.query(Report).filter(Report.project_id == project_id).first()
    if row is None:
        row = Report(project_id=project_id, report_markdown="", report_html="")
        db.add(row)
    row.report_status = "failed"
    row.error_message = error[:2000]
    db.commit()


def get_latest_report(db: Session, project_id: int) -> Report | None:
    return db.query(Report).filter(Report.project_id == project_id).first()


def report_dict(row: Report, include_html: bool = False) -> dict:
    data = {
        "id": row.id,
        "project_id": row.project_id,
        "report_status": row.report_status,
        "report_markdown": row.report_markdown,
        "report_file_path": row.report_file_path,
        "error_message": row.error_message,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
    if include_html:
        data["report_html"] = row.report_html
    return data
