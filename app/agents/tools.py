"""源码读取、目录遍历、关键字搜索、静态规则与入口识别。"""
from __future__ import annotations

import os
import re
from pathlib import Path

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".idea", ".vscode", "target", "vendor", ".next",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".go", ".rb",
    ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".kt", ".scala", ".swift",
    ".sql", ".html", ".htm", ".jsp", ".vue", ".xml", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bat",
    ".txt", ".md", ".properties", ".gradle", ".pom",
}

SENSITIVE_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}

KEYWORDS = [
    "execute(", "executemany(", "os.system", "os.popen", "subprocess",
    "eval(", "exec(", "pickle.loads", "yaml.load", "innerHTML", "render_template_string",
    "open(", "../", "pickle", "SECRET", "password", "token", "hidden",
    "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "shell=True", "request.args",
    "request.form", "req.query", "dangerouslySetInnerHTML",
]

SECRET_LINE = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']([^\"']{6,})[\"']"
)

STATIC_RULES = [
    {
        "pattern": re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\b.*(%\s*\(|\+\s*[A-Za-z_]|\{[A-Za-z_])"),
        "type": "sqli",
        "level": "high",
        "title": "SQL 注入",
        "condition": "SQL 语句通过拼接或格式化加入变量。",
        "impact": "攻击者可能读取、篡改或删除数据库数据。",
        "recommendation": "使用参数化查询，禁止拼接 SQL。",
    },
    {
        "pattern": re.compile(r"(execute|executemany)\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*\+)"),
        "type": "sqli",
        "level": "high",
        "title": "SQL 注入",
        "condition": "用户可控内容被拼接进 SQL 语句。",
        "impact": "攻击者可能读取、篡改或删除数据库数据。",
        "recommendation": "使用参数化查询，禁止拼接 SQL。",
    },
    {
        "pattern": re.compile(r"os\.(system|popen)\s*\("),
        "type": "command_injection",
        "level": "critical",
        "title": "命令注入",
        "condition": "用户输入进入 shell 命令。",
        "impact": "攻击者可能在服务器上执行任意命令。",
        "recommendation": "使用参数列表调用子进程，避免 shell 拼接并做白名单校验。",
    },
    {
        "pattern": re.compile(r"subprocess\.(run|call|Popen).*shell\s*=\s*True"),
        "type": "command_injection",
        "level": "critical",
        "title": "命令注入（shell=True）",
        "condition": "subprocess 使用 shell=True 且命令包含用户输入。",
        "impact": "攻击者可能执行任意系统命令。",
        "recommendation": "设置 shell=False 并传入参数列表。",
    },
    {
        "pattern": re.compile(r"(render_template_string|innerHTML\s*=|dangerouslySetInnerHTML)"),
        "type": "xss",
        "level": "medium",
        "title": "跨站脚本（XSS）",
        "condition": "用户输入未转义即写入 HTML。",
        "impact": "攻击者可能注入脚本、窃取会话或诱导用户操作。",
        "recommendation": "对输出进行上下文相关转义，使用框架默认转义。",
    },
    {
        "pattern": re.compile(r"[\"'][^\"']*<[A-Za-z][^>]*>[^\"']*[\"']\s*\+"),
        "type": "xss",
        "level": "medium",
        "title": "跨站脚本（XSS）",
        "condition": "HTML 字符串与变量直接拼接后输出。",
        "impact": "攻击者可能注入脚本、窃取会话或诱导用户操作。",
        "recommendation": "使用模板引擎自动转义，避免拼接 HTML。",
    },
    {
        "pattern": re.compile(r"(send_file\s*\(|open\s*\(\s*os\.path\.join|os\.path\.join\s*\(|Path\s*\(.*request)"),
        "type": "path_traversal",
        "level": "high",
        "title": "路径穿越",
        "condition": "用户可控文件名直接参与路径拼接。",
        "impact": "攻击者可能读取服务器任意文件。",
        "recommendation": "规范化路径并校验必须位于允许目录内。",
    },
    {
        "pattern": re.compile(r"(?i)(SECRET_KEY|API_KEY|ADMIN_TOKEN|PASSWORD)\s*=\s*[\"'][^\"']{6,}[\"']"),
        "type": "hardcoded_secret",
        "level": "high",
        "title": "硬编码密钥",
        "condition": "密钥或令牌直接写在源码中。",
        "impact": "源码泄露后攻击者可伪造会话或访问受保护资源。",
        "recommendation": "从环境变量或密钥管理服务读取，并定期轮换。",
    },
    {
        "pattern": re.compile(r"(token\s*[!=]=\s*[\"']|token\s*[!=]=\s*[A-Z_]+|request\.args\.get\(\s*[\"']token)"),
        "type": "weak_auth",
        "level": "high",
        "title": "弱鉴权",
        "condition": "使用固定 token 或简单参数判断权限。",
        "impact": "攻击者可能绕过认证访问管理功能。",
        "recommendation": "使用服务端会话与强随机令牌，实施最小权限控制。",
    },
    {
        "pattern": re.compile(r"debug\s*=\s*True"),
        "type": "other",
        "level": "low",
        "title": "调试模式开启",
        "condition": "应用以调试模式运行。",
        "impact": "可能泄露堆栈与配置信息，增加攻击面。",
        "recommendation": "生产环境关闭 debug 并限制错误信息输出。",
    },
    {
        "pattern": re.compile(r"(eval|exec)\s*\(|pickle\.loads\s*\(|yaml\.load\s*\("),
        "type": "deserialization",
        "level": "high",
        "title": "危险反序列化/动态执行",
        "condition": "不可信数据进入动态执行或反序列化接口。",
        "impact": "可能导致远程代码执行。",
        "recommendation": "避免对不可信数据使用 eval/exec/不安全反序列化。",
    },
]


def _is_sensitive(path: Path) -> bool:
    return path.name in SENSITIVE_NAMES or path.suffix.lower() in SENSITIVE_SUFFIXES


def _is_text(path: Path) -> bool:
    return (
        path.suffix.lower() in TEXT_EXTENSIONS
        or path.name in ("Dockerfile", "Makefile", ".env.example")
    ) and not _is_sensitive(path)


def iter_source_files(root: str, max_files: int = 400) -> list[str]:
    base = Path(root)
    if not base.is_dir():
        return []
    result: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath) / name
            if not _is_text(p):
                continue
            try:
                if p.stat().st_size > 2 * 1024 * 1024:
                    continue
            except OSError:
                continue
            result.append(str(p.relative_to(base)))
            if len(result) >= max_files:
                return result
    return result


def redact_secrets(text: str) -> str:
    def _replace(match: re.Match) -> str:
        value = match.group(2)
        masked = value[:4] + "****" if len(value) > 8 else "****"
        return match.group(0).replace(value, masked)

    return SECRET_LINE.sub(_replace, text)


def read_text(root: str, rel_path: str, max_chars: int = 20000, redact: bool = True) -> str:
    p = (Path(root) / rel_path).resolve()
    base = Path(root).resolve()
    try:
        p.relative_to(base)
    except ValueError:
        return "(拒绝读取：路径越界)"
    if _is_sensitive(p):
        return "(拒绝读取：敏感文件)"
    try:
        data = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"(读取失败：{exc})"
    if redact:
        data = redact_secrets(data)
    if len(data) > max_chars:
        data = data[:max_chars] + "\n...(内容已截断)"
    return data


def search_keywords(root: str, keywords: list[str] | None = None, max_hits: int = 120) -> str:
    keywords = keywords or KEYWORDS
    base = Path(root)
    hits: list[str] = []
    for rel in iter_source_files(root):
        try:
            text = (base / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            low = line.lower()
            for kw in keywords:
                if kw.lower() in low:
                    hits.append(f"{rel}:{lineno}: {redact_secrets(line.strip())[:200]}")
                    break
            if len(hits) >= max_hits:
                return "\n".join(hits)
    return "\n".join(hits)


def collect_context(
    root: str,
    focus_files: list[str] | None,
    budget_chars: int = 90000,
    max_files: int = 40,
) -> str:
    files = iter_source_files(root)
    if not files:
        return "(未发现可读源码文件)"
    ordered: list[str] = []
    for f in focus_files or []:
        if f in files:
            ordered.append(f)
    for f in files:
        if f not in ordered:
            ordered.append(f)
    ordered = ordered[:max_files]

    parts = ["## 源码文件清单\n" + "\n".join(files[:200])]
    used = len(parts[0])
    for rel in ordered:
        content = read_text(root, rel)
        chunk = f"\n\n### 文件：{rel}\n```\n{content}\n```"
        if used + len(chunk) > budget_chars:
            parts.append(f"\n\n### 文件：{rel}\n(因上下文预算已省略)")
            continue
        parts.append(chunk)
        used += len(chunk)
    return "".join(parts)


def static_scan(root: str, max_files: int = 120, max_findings: int = 50) -> list[dict]:
    """确定性规则扫描，作为模型分析的补充与失败兜底。"""
    base = Path(root)
    findings: list[dict] = []
    for rel in iter_source_files(root, max_files=max_files):
        if Path(rel).suffix.lower() not in {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", ".rb"}:
            continue
        try:
            text = (base / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            for rule in STATIC_RULES:
                if rule["pattern"].search(line):
                    findings.append({
                        "vuln_title": rule["title"],
                        "vuln_type": rule["type"],
                        "risk_level": rule["level"],
                        "file_path": rel,
                        "line": lineno,
                        "impact_text": rule["impact"],
                        "condition_text": rule["condition"],
                        "evidence_text": stripped[:500],
                        "recommendation_text": rule["recommendation"],
                    })
                    break
            if len(findings) >= max_findings:
                return findings
    return findings


def detect_entry_candidates(root: str) -> list[str]:
    names = {"app.py", "main.py", "run.py", "manage.py", "wsgi.py", "server.py", "index.js", "server.js"}
    found = [f for f in iter_source_files(root) if Path(f).name in names]
    return found[:5]
