"""OpenAI 兼容 LLM 客户端（默认 DeepSeek），支持结构化 JSON 输出与离线 mock。"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)


class LLMError(RuntimeError):
    pass


def _strip_json(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def parse_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(_strip_json(text))
    except json.JSONDecodeError as exc:  # 再尝试一次宽松修复
        cleaned = _strip_json(text).replace("\n", " ")
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            raise LLMError(f"模型返回内容不是合法 JSON：{exc}") from exc


async def complete_json(
    kind: str,
    system: str,
    user: str,
    cfg: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """返回 (结构化结果, 消耗 token 数)。"""
    if cfg.get("llm_mock"):
        logger.info("LLM mock 模式：kind=%s", kind)
        return mock_response(kind, user), 0
    api_key = cfg.get("llm_api_key") or ""
    if not api_key:
        raise LLMError("未配置 LLM API Key，请在系统配置页填写或设置 LLM_API_KEY")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=cfg.get("llm_base_url") or "https://api.deepseek.com",
        timeout=float(cfg.get("llm_timeout") or 300),
    )
    resp = await client.chat.completions.create(
        model=cfg.get("llm_model") or "deepseek-chat",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.1,
    )
    content = resp.choices[0].message.content or ""
    tokens = int(resp.usage.total_tokens) if getattr(resp, "usage", None) else 0
    return parse_json(content), tokens


# --------------------------------------------------------------------------
# 离线 mock：仅在 llm_mock=true 时启用，用于无 Key 环境下跑通完整链路
# --------------------------------------------------------------------------

def mock_response(kind: str, prompt: str) -> dict[str, Any]:
    if kind == "env_scan":
        return {
            "summary": "已完成源码目录遍历与环境检查（mock）。",
            "language": "Python",
            "entry_candidates": ["app.py"],
            "dependencies": ["flask"],
            "environment_ok": True,
            "notes": "mock 模式未实际调用 Docker 检查。",
        }
    if kind == "ops":
        return {
            "summary": "隔离环境已就绪（mock）。",
            "environment_ok": True,
            "docker_status": "available",
            "recommendation": "保持默认并发与超时配置。",
        }
    if kind == "plan_analysis":
        return {
            "strategy": "优先分析 Web 入口与数据库/命令执行相关代码（mock）。",
            "focus_files": ["app.py"],
            "risk_areas": ["SQL 注入", "命令注入", "XSS", "路径穿越", "硬编码密钥"],
        }
    if kind == "analyze_code":
        return {
            "vulnerabilities": [
                {
                    "vuln_title": "SQL 注入",
                    "risk_level": "high",
                    "file_path": "app.py",
                    "line": 45,
                    "impact_text": "攻击者可拼接恶意 SQL 读取或篡改数据库数据。",
                    "condition_text": "用户可控的 username 参数被直接拼接到 SQL 语句。",
                    "evidence_text": "cursor.execute(\"SELECT * FROM users WHERE username = '\" + username + \"'\")",
                    "recommendation_text": "使用参数化查询。",
                },
                {
                    "vuln_title": "命令注入",
                    "risk_level": "critical",
                    "file_path": "app.py",
                    "line": 62,
                    "impact_text": "攻击者可在服务器上执行任意系统命令。",
                    "condition_text": "host 参数未经校验直接传入 os.popen。",
                    "evidence_text": "os.popen('ping -c 1 ' + host)",
                    "recommendation_text": "避免拼接 shell 命令，使用参数列表并做白名单校验。",
                },
                {
                    "vuln_title": "反射型 XSS",
                    "risk_level": "medium",
                    "file_path": "app.py",
                    "line": 78,
                    "impact_text": "攻击者可注入脚本窃取用户会话。",
                    "condition_text": "q 参数未经转义直接返回 HTML。",
                    "evidence_text": "return '<h1>搜索结果：' + q + '</h1>'",
                    "recommendation_text": "对输出进行 HTML 转义。",
                },
                {
                    "vuln_title": "路径穿越",
                    "risk_level": "high",
                    "file_path": "app.py",
                    "line": 91,
                    "impact_text": "攻击者可读取服务器任意文件。",
                    "condition_text": "filename 参数直接拼接到 open() 路径。",
                    "evidence_text": "open(os.path.join('files', filename)).read()",
                    "recommendation_text": "规范化路径并限制在允许目录内。",
                },
                {
                    "vuln_title": "硬编码密钥与弱鉴权",
                    "risk_level": "high",
                    "file_path": "app.py",
                    "line": 12,
                    "impact_text": "密钥泄露可导致会话伪造。",
                    "condition_text": "SECRET_KEY 硬编码且管理接口仅校验固定 token。",
                    "evidence_text": "SECRET_KEY = 'dev-secret-123'; ADMIN_TOKEN = 'admin'",
                    "recommendation_text": "从环境变量/密钥管理服务读取，使用强鉴权。",
                },
            ]
        }
    if kind == "verify":
        return {
            "verified": True,
            "verify_status": "verified",
            "impact_text": "mock 模式下确认该漏洞可被利用。",
            "evidence_text": "mock PoC 执行成功标记 SAS_POC_SUCCESS。",
            "reproduce_steps_text": "1. 启动示例应用\n2. 执行验证脚本\n3. 观察 SAS_POC_SUCCESS 输出",
            "verify_code_text": (
                "import sys\n"
                "print('SAS_POC_SUCCESS: mock verification')\n"
                "sys.exit(0)\n"
            ),
        }
    if kind == "attack_path":
        return {
            "paths": [
                {
                    "path_title": "从 SQL 注入到数据库数据泄露",
                    "path_summary": "利用登录接口 SQL 注入绕过认证并读取用户数据。",
                    "final_impact_text": "数据库敏感信息泄露。",
                    "vuln_titles": ["SQL 注入"],
                    "steps": [
                        {"vuln_title": "SQL 注入", "step_text": "在 username 参数注入 ' OR '1'='1 绕过认证。"}
                    ],
                },
                {
                    "path_title": "命令注入导致服务器沦陷",
                    "path_summary": "通过 ping 接口注入系统命令。",
                    "final_impact_text": "服务器被完全控制。",
                    "vuln_titles": ["命令注入"],
                    "steps": [
                        {"vuln_title": "命令注入", "step_text": "在 host 参数注入 ; id 执行任意命令。"}
                    ],
                },
            ]
        }
    if kind == "report":
        return {
            "report_markdown": (
                "# 自动化安全评估报告（mock）\n\n"
                "## 项目概述\n本报告由自动化安全评估系统生成，当前为离线 mock 模式。\n\n"
                "## 执行过程\n环境检查 → 代码分析 → 漏洞验证 → 报告生成。\n\n"
                "## 漏洞汇总\n共发现 5 个漏洞，其中高危/严重漏洞需优先修复。\n\n"
                "## 攻击路径\n见攻击路径页面。\n\n"
                "## 风险结论\n系统整体风险较高。\n\n"
                "## 修复建议\n使用参数化查询、避免命令拼接、输出转义、路径规范化。\n"
            )
        }
    return {"result": "mock"}
