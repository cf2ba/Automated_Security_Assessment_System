"""漏洞记录、风险评分与攻击路径持久化。"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AttackPath, AttackPathItem, Vulnerability

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RISK_BASE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.5}
TYPE_LABELS = {
    "sqli": "SQL 注入",
    "command_injection": "命令注入",
    "xss": "跨站脚本",
    "path_traversal": "路径穿越",
    "hardcoded_secret": "硬编码密钥",
    "weak_auth": "弱鉴权",
    "ssrf": "SSRF",
    "deserialization": "反序列化",
    "other": "其他风险",
}


def normalize_risk(value: str | None) -> str:
    v = (value or "medium").strip().lower()
    mapping = {
        "严重": "critical", "高危": "high", "中危": "medium", "低危": "low", "信息": "info",
        "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
    }
    return mapping.get(v, "medium")


def normalize_type(value: str | None, title: str = "") -> str:
    v = (value or "").strip().lower()
    mapping = {
        "sqli": "sqli", "sql injection": "sqli", "sql注入": "sqli",
        "command_injection": "command_injection", "command injection": "command_injection",
        "命令注入": "command_injection", "rce": "command_injection",
        "xss": "xss", "跨站脚本": "xss",
        "path_traversal": "path_traversal", "path traversal": "path_traversal",
        "路径穿越": "path_traversal", "directory traversal": "path_traversal",
        "hardcoded_secret": "hardcoded_secret", "hardcoded": "hardcoded_secret",
        "硬编码密钥": "hardcoded_secret",
        "weak_auth": "weak_auth", "weak authentication": "weak_auth", "弱鉴权": "weak_auth",
        "ssrf": "ssrf", "deserialization": "deserialization", "反序列化": "deserialization",
        "other": "other",
    }
    if v in mapping:
        return mapping[v]
    text = (title or "").lower()
    if "sql" in text:
        return "sqli"
    if "命令" in text or "command" in text:
        return "command_injection"
    if "xss" in text or "脚本" in text:
        return "xss"
    if "路径" in text or "traversal" in text:
        return "path_traversal"
    if "密钥" in text or "secret" in text:
        return "hardcoded_secret"
    if "鉴权" in text or "auth" in text:
        return "weak_auth"
    return "other"


def risk_score(level: str, verify_status: str = "unverified") -> float:
    score = RISK_BASE.get(level, 5.5)
    if verify_status == "verified":
        score += 0.5
    elif verify_status == "statically_confirmed":
        score += 0.2
    elif verify_status in ("false_positive", "failed"):
        score = max(0.0, score - 7.0)
    return round(min(10.0, max(0.0, score)), 1)


def type_label(value: str | None) -> str:
    return TYPE_LABELS.get(value or "other", value or "其他风险")


def _same_location(a: Vulnerability, data: dict) -> bool:
    if (a.file_path or "") != (data.get("file_path") or ""):
        return False
    if normalize_type(a.vuln_type, a.vuln_title) != normalize_type(
        data.get("vuln_type"), data.get("vuln_title", "")
    ):
        return False
    line = data.get("line") or data.get("line_number")
    return abs(int(a.line_number or 0) - int(line or 0)) <= 2


def save_vulnerabilities(db: Session, project_id: int, items: list[dict]) -> list[Vulnerability]:
    existing = db.query(Vulnerability).filter(Vulnerability.project_id == project_id).all()
    saved: list[Vulnerability] = []
    seq = len(existing)
    for data in items:
        if not isinstance(data, dict):
            continue
        duplicate = next((row for row in existing if _same_location(row, data)), None)
        if duplicate is not None:
            if data.get("evidence_text") and not duplicate.evidence_text:
                duplicate.evidence_text = data["evidence_text"]
            if data.get("recommendation_text") and not duplicate.recommendation_text:
                duplicate.recommendation_text = data["recommendation_text"]
            db.flush()
            continue
        seq += 1
        level = normalize_risk(data.get("risk_level"))
        vtype = normalize_type(data.get("vuln_type"), data.get("vuln_title", ""))
        line = data.get("line") or data.get("line_number")
        row = Vulnerability(
            project_id=project_id,
            vuln_code=f"VULN-{project_id}-{seq:03d}",
            vuln_title=(data.get("vuln_title") or type_label(vtype))[:255],
            vuln_type=vtype,
            risk_level=level,
            risk_score=risk_score(level),
            file_path=data.get("file_path"),
            line_number=int(line) if line else None,
            impact_text=data.get("impact_text"),
            condition_text=data.get("condition_text"),
            evidence_text=data.get("evidence_text"),
            verify_status="unverified",
            recommendation_text=data.get("recommendation_text"),
        )
        db.add(row)
        db.flush()
        existing.append(row)
        saved.append(row)
    db.commit()
    for row in saved:
        db.refresh(row)
    return saved


def save_vulnerability(db: Session, project_id: int, data: dict, seq: int) -> Vulnerability:
    """兼容旧调用：单条保存，编号由调用方给出。"""
    rows = save_vulnerabilities(db, project_id, [data])
    return rows[0] if rows else db.query(Vulnerability).filter(
        Vulnerability.project_id == project_id
    ).order_by(Vulnerability.id.desc()).first()


def update_verification(
    db: Session,
    vuln_id: int,
    data: dict,
    verify_status: str,
    evidence_prefix: str = "",
    tokens: int = 0,
) -> Vulnerability | None:
    row = db.get(Vulnerability, vuln_id)
    if not row:
        return None
    row.verify_status = verify_status
    if data.get("impact_text"):
        row.impact_text = data["impact_text"]
    evidence = data.get("evidence_text") or ""
    if evidence_prefix:
        evidence = f"{evidence_prefix}\n{evidence}".strip()
    if evidence:
        row.evidence_text = evidence
    if data.get("reproduce_steps_text"):
        row.reproduce_steps_text = data["reproduce_steps_text"]
    if data.get("verify_code_text"):
        row.verify_code_text = data["verify_code_text"]
    row.risk_score = risk_score(row.risk_level, verify_status)
    db.commit()
    db.refresh(row)
    return row


def list_vulnerabilities(
    db: Session,
    project_id: int,
    risk_level: str | None = None,
    verify_status: str | None = None,
    keyword: str | None = None,
) -> list[Vulnerability]:
    q = db.query(Vulnerability).filter(Vulnerability.project_id == project_id)
    if risk_level:
        q = q.filter(Vulnerability.risk_level == risk_level)
    if verify_status:
        q = q.filter(Vulnerability.verify_status == verify_status)
    if keyword:
        like = f"%{keyword}%"
        q = q.filter(
            (Vulnerability.vuln_title.like(like))
            | (Vulnerability.file_path.like(like))
            | (Vulnerability.vuln_code.like(like))
        )
    rows = q.all()
    return sorted(rows, key=lambda r: (RISK_ORDER.get(r.risk_level, 9), r.id))


def paginate_vulnerabilities(
    db: Session,
    project_id: int,
    page: int = 1,
    page_size: int = 20,
    risk_level: str | None = None,
    verify_status: str | None = None,
    keyword: str | None = None,
) -> tuple[list[Vulnerability], int]:
    rows = list_vulnerabilities(db, project_id, risk_level, verify_status, keyword)
    start = (page - 1) * page_size
    return rows[start : start + page_size], len(rows)


def risk_summary(db: Session, project_id: int) -> dict:
    rows = db.query(Vulnerability.risk_level).filter(Vulnerability.project_id == project_id).all()
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(rows)}
    for (level,) in rows:
        if level in summary:
            summary[level] += 1
    return summary


def get_vulnerability(db: Session, project_id: int, vuln_id: int) -> Vulnerability | None:
    return (
        db.query(Vulnerability)
        .filter(Vulnerability.project_id == project_id, Vulnerability.id == vuln_id)
        .first()
    )


def vuln_dict(row: Vulnerability, detail: bool = False) -> dict:
    base = {
        "id": row.id,
        "project_id": row.project_id,
        "vuln_code": row.vuln_code,
        "vuln_title": row.vuln_title,
        "vuln_type": row.vuln_type,
        "vuln_type_label": type_label(row.vuln_type),
        "risk_level": row.risk_level,
        "risk_score": row.risk_score,
        "file_path": row.file_path,
        "line_number": row.line_number,
        "verify_status": row.verify_status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if detail:
        base.update(
            {
                "impact_text": row.impact_text,
                "condition_text": row.condition_text,
                "evidence_text": row.evidence_text,
                "reproduce_steps_text": row.reproduce_steps_text,
                "verify_code_text": row.verify_code_text,
                "recommendation_text": row.recommendation_text,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
        )
    return base


def build_fallback_paths(vulns: list[Vulnerability]) -> list[dict]:
    groups: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        groups.setdefault(v.vuln_type or "other", []).append(v)
    paths = []
    for idx, (vtype, group) in enumerate(groups.items(), start=1):
        steps = []
        for order, v in enumerate(group, start=1):
            steps.append({
                "vuln_code": v.vuln_code,
                "step_order": order,
                "step_text": f"利用 {v.vuln_title}（{v.file_path or '未知文件'}:{v.line_number or '?'}）",
            })
        paths.append({
            "path_title": f"{type_label(vtype)}利用链",
            "path_summary": f"由 {len(group)} 个同类型漏洞组成的攻击路径。",
            "final_impact_text": group[0].impact_text or f"可能导致{type_label(vtype)}风险被利用。",
            "steps": steps,
        })
        if idx >= 5:
            break
    return paths


def save_attack_paths(
    db: Session,
    project_id: int,
    paths: list[dict],
    vulns: list[Vulnerability],
) -> list[AttackPath]:
    by_title = {v.vuln_title: v for v in vulns}
    by_code = {v.vuln_code: v for v in vulns}
    current = db.query(AttackPath).filter(AttackPath.project_id == project_id).count()
    saved: list[AttackPath] = []
    for idx, p in enumerate(paths, start=1):
        if not isinstance(p, dict):
            continue
        code = f"PATH-{project_id}-{current + idx:03d}"
        path = AttackPath(
            project_id=project_id,
            path_code=code,
            path_title=(p.get("path_title") or f"攻击路径 {idx}")[:255],
            path_summary=p.get("path_summary"),
            final_impact_text=p.get("final_impact_text"),
        )
        db.add(path)
        db.flush()
        max_score = 0.0
        steps = p.get("steps") or []
        for order, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            vuln = by_code.get(step.get("vuln_code") or "") or by_title.get(step.get("vuln_title") or "")
            if vuln:
                max_score = max(max_score, vuln.risk_score or 0.0)
            db.add(AttackPathItem(
                path_id=path.id,
                vuln_id=vuln.id if vuln else None,
                step_order=order,
                step_text=step.get("step_text"),
            ))
        path.risk_score = max_score
        db.flush()
        saved.append(path)
    db.commit()
    for path in saved:
        db.refresh(path)
    return saved


def list_attack_paths(db: Session, project_id: int) -> list[AttackPath]:
    return (
        db.query(AttackPath)
        .filter(AttackPath.project_id == project_id)
        .order_by(AttackPath.id.asc())
        .all()
    )


def get_attack_path(db: Session, project_id: int, path_id: int) -> AttackPath | None:
    return (
        db.query(AttackPath)
        .filter(AttackPath.project_id == project_id, AttackPath.id == path_id)
        .first()
    )


def path_dict(row: AttackPath) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "path_code": row.path_code,
        "path_title": row.path_title,
        "path_summary": row.path_summary,
        "final_impact_text": row.final_impact_text,
        "risk_score": row.risk_score,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "items": [
            {
                "id": item.id,
                "vuln_id": item.vuln_id,
                "vuln_code": item.vuln.vuln_code if item.vuln else None,
                "vuln_title": item.vuln.vuln_title if item.vuln else None,
                "step_order": item.step_order,
                "step_text": item.step_text,
            }
            for item in row.items
        ],
    }
