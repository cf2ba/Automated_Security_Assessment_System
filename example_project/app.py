"""示例目标项目：一个故意包含多种安全漏洞的 Flask 应用。

仅用于自动化安全评估系统的演示，请勿用于生产环境。
"""
from __future__ import annotations

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# [漏洞] 硬编码密钥
SECRET_KEY = "dev-secret-123"
ADMIN_TOKEN = "admin"

_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
_conn.execute("INSERT INTO users (username, password) VALUES ('alice', 'alice123')")
_conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'S3cretAdmin!')")
_conn.commit()


@app.route("/")
def index():
    return "Vulnerable Demo App. Try /login, /search, /ping, /download, /admin"


@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    # [漏洞] SQL 注入：直接拼接用户输入
    query = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    try:
        row = _conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        return f"database error: {exc}", 500
    if row:
        return f"welcome {row[1]}"
    return "login failed", 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # [漏洞] 反射型 XSS：未转义直接输出
    return "<html><body><h1>搜索结果：" + q + "</h1></body></html>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [漏洞] 命令注入：用户输入直接进入 shell
    output = os.popen("echo PING " + host).read()
    return f"<pre>{output}</pre>"


@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    # [漏洞] 路径穿越：未限制目录
    path = os.path.join("files", filename)
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        return f"read error: {exc}", 404


@app.route("/admin")
def admin():
    # [漏洞] 弱鉴权：固定 token 且可预测
    if request.args.get("token") != ADMIN_TOKEN:
        return "forbidden", 403
    return "admin panel: all users"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), threaded=True)
