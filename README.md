# 自动化安全评估系统

基于 FastAPI + LangGraph + Docker 隔离环境的自动化安全评估系统。支持本地目录 / Git 仓库导入、多角色评估流程、容器内动态验证、WebSocket 实时监控和 Markdown/HTML 报告。

## 1. 环境要求

| 依赖 | 版本 / 说明 |
| --- | --- |
| Python | 3.11+（本项目在 3.14 下验证） |
| Docker | Docker Desktop / Engine，能够运行 Linux 容器 |
| MySQL | 8.0，可直接使用 `docker-compose.yml` |
| LLM | OpenAI 兼容接口（默认 DeepSeek）；也可用 mock 模式联调 |

## 2. 安装

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## 3. 配置

```bash
copy .env.example .env      # Linux/macOS: cp .env.example .env
```

至少确认以下配置：

- `SECRET_KEY`：会话签名密钥，生产环境务必改为随机值。
- `DATABASE_URL`：默认连接 `127.0.0.1:3307`（compose 中 MySQL 映射端口）。
- `LLM_API_KEY`：真实评估必填；API Key 只从环境变量读取，系统配置页不可写入。
- `LLM_MOCK`：无 Key 时可设为 `true` 做链路验证，此时不会调用真实模型，PoC 为固定 mock 脚本。

修改 `.env` 后需要重启后端。

## 4. 启动

```bash
# 1. 启动 MySQL（容器名 sas-mysql，端口 3307）
docker compose up -d mysql
docker compose ps

# 2. 建库、建表并补齐默认配置（不会覆盖已有配置）
python scripts/init_db.py

# 3. 构建隔离环境镜像
python scripts/build_image.py

# 4. 启动 Web 服务
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

浏览器访问 <http://127.0.0.1:8000/>。首次访问时登录页会显示“初始化管理员”，创建账户后即可新建项目。接口文档位于 <http://127.0.0.1:8000/docs>。

## 5. 使用流程

1. 新建项目：选择本地目录或 Git 地址。本地路径必须是服务端可访问的目录；Git 仓库在创建时克隆到 `data/workspace/{project_id}/src`。
2. 启动评估：自动创建容器 `sas-env-{project_id}`（源码只读挂载、禁用网络、限制资源），依次执行环境检查 → 代码分析 → 漏洞验证 → 报告生成。
3. 实时监控：WebSocket 推送阶段、角色、日志、资源与漏洞事件；断线自动重连并回放未接收事件。
4. 查看结果：漏洞列表、攻击路径、Markdown/HTML 报告下载。
5. 删除项目：级联删除容器、工作区、报告、日志与数据库记录。

运行数据（日志、资源采样）在重新评估时保留，业务产物（漏洞、路径、报告、聊天、阶段、角色记录）会清理后重建。

## 6. 测试

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

测试使用临时 SQLite 数据库、mock LLM 和 fake Docker，不会污染本地 MySQL 或创建真实容器。

## 7. 常见问题

- **`docker compose up` 端口冲突**：`3307` 被占用时修改 `docker-compose.yml` 的端口映射与 `.env` 的 `DATABASE_URL`。
- **无法连接 Docker**：确认 Docker Desktop 已启动；评估启动接口会在 Docker 不可用且 `ISOLATION_REQUIRED=true` 时直接报错。
- **镜像构建失败**：多为 `apt-get`/`pip` 网络超时，重试 `python scripts/build_image.py`；脚本会输出构建日志末尾。
- **真实模型不可用**：系统会退化为规则静态扫描并继续生成报告，但漏洞验证可能标记为未验证；检查 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`。
- **本地源码路径被拒绝**：检查 `ALLOWED_SOURCE_ROOTS`（分号分隔）；留空表示不限制。

## 8. 关键目录

```
app/api/            REST 与 WebSocket 接口
app/agents/         LangGraph 流程、角色编排、LLM 客户端与静态扫描
app/services/       项目、阶段、漏洞、报告、监控、配置业务逻辑
app/isolation/      Docker 隔离环境
app/static/         前端页面
scripts/            初始化、镜像构建脚本
tests/              接口、服务与流程测试
data/               运行数据（workspace / reports / runtime_logs）
```
