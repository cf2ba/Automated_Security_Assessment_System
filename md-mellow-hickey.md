# 自动化安全评估系统 — 实现计划

## Context

需求来自 [自动化安全评估系统.md](自动化安全评估系统.md)：面向源码项目的自动化安全评估系统，支持项目接入、隔离分析、漏洞发现、漏洞验证、攻击路径整理和报告输出，交付「前端 + 后端 + 数据库初始化脚本 + 示例项目 + 接口说明 + 完整演示链路」。

当前目录为空（仅需求文档），是全新项目。本计划基于与用户逐一确认后的技术选型，目标是交付一个**本机即可跑通完整演示**的系统。

## 已确认的技术选型

| 维度 | 决策 |
|---|---|
| 分析引擎 | LLM 多智能体（真实调用） |
| 模型接入 | OpenAI 兼容接口（可切换），默认 **DeepSeek**（deepseek-chat / deepseek-reasoner） |
| 后端 | Python 3.11 + FastAPI |
| 前端 | 静态 HTML + 原生 JS（由 FastAPI 托管），WebSocket 做实时监控 |
| 数据库 | MySQL（SQLAlchemy ORM），提供初始化脚本 |
| 隔离环境 | Docker 容器（每项目一容器，源码只读挂载） |
| 目标语言 | Python（示例项目 = 带故意漏洞的 Flask 应用） |
| 智能体编排 | LangChain / LangGraph |
| 漏洞验证 | 动态执行 PoC + 静态推理兜底 |
| 部署 | 本机 uvicorn 跑后端；Docker 分别跑 MySQL 与隔离容器 |

**默认/自行裁定的实现细节**（计划评审时可改）：
- 登录态用 **HttpOnly Session Cookie**（`POST /api/system/login` 建会话，其余接口校验会话）。
- 任务调度用 **进程内 asyncio 任务管理器**（单实例演示足够，不引入 Celery/Redis）。
- 源码读取在宿主机只读读取并喂给 LLM；Docker 容器用于「命令执行 + 动态验证 + 起示例应用」，源码以只读卷挂载进容器。
- token_count 取 LLM 响应的真实 usage；cpu/memory 用 `psutil` 采样后端进程 + `docker stats`。

## 架构总览

```
浏览器(静态HTML+JS) ──HTTP/REST──► FastAPI 后端
                    ──WS/stream──►   ├─ 认证模块(session)
                                     ├─ 项目模块
                                     ├─ 调度模块(进程内 asyncio + LangGraph 状态机)
                                     ├─ 多智能体(6角色, OpenAI兼容 client)
                                     ├─ 隔离环境模块(docker-py)
                                     ├─ 漏洞/攻击路径/报告/监控模块
                                     └─ SQLAlchemy ──► MySQL
调度器 ──docker-py──► Docker: 每项目一个隔离容器(源码只读挂载 /workspace/{id})
```

## 目录结构

```
Automated_Security_Assessment_System/
├─ app/
│  ├─ main.py                # FastAPI 入口，静态托管 + 路由注册
│  ├─ config.py              # pydantic-settings，读 .env
│  ├─ database.py            # SQLAlchemy engine/session
│  ├─ models/                # 11 张表 ORM（见下）
│  ├─ schemas/               # Pydantic 请求/响应模型
│  ├─ api/                   # 路由（按模块拆分）
│  │  ├─ auth.py  projects.py  stages.py  vulns.py
│  │  ├─ paths.py  reports.py  logs.py  resources.py  stream.py
│  ├─ core/
│  │  ├─ security.py         # 密码哈希(bcrypt) + session
│  │  ├─ task_manager.py     # 进程内 asyncio 任务生命周期
│  │  └─ llm.py              # OpenAI 兼容 client 工厂 + usage 统计
│  ├─ agents/
│  │  ├─ graph.py            # LangGraph StateGraph：阶段推进
│  │  ├─ roles.py            # 6 类角色的 system prompt + 工具集
│  │  ├─ tools.py            # read_file/list_dir/search/run_command/save_vuln 等
│  │  └─ state.py            # 图状态定义
│  ├─ isolation/
│  │  ├─ docker.py           # 容器创建/启动/停止/销毁、只读挂载、exec 命令
│  │  └─ image_build.py      # 构建 assessment-runner 镜像
│  ├─ services/              # 业务逻辑：项目/漏洞/路径/报告/监控
│  └─ static/                # 前端 HTML/CSS/JS
├─ scripts/
│  ├─ init_db.py             # 建库建表 + 种子示例数据
│  └─ build_image.py
├─ example_project/          # 带故意漏洞的 Flask 应用（SQL注入/命令注入/XSS/路径穿越/硬编码密钥）
├─ Dockerfile                # 隔离容器基础镜像
├─ .env.example              # DB、DeepSeek base_url/api_key/model、并发数、超时等
├─ requirements.txt
└─ README.md                 # 启动步骤 + 接口说明 + 演示链路
```

## 数据模型（11 表，见需求 2.5.8，ORM 映射）

`users`、`projects`、`runtime_stages`、`worker_tasks`、`vulnerabilities`、`attack_paths`、`attack_path_items`、`chat_messages`、`runtime_logs`、`resource_usages`、`reports`。字段完全按需求文档，统一加索引：`projects(project_status)`、`vulnerabilities(project_id, risk_level)`、`runtime_logs(project_id, created_at)` 等。`reports` 存 `report_markdown` + `report_html` + `report_file_path`。

## 角色 ↔ 阶段映射（6 角色 / 5 阶段）

| 阶段 | 参与角色 | 产出 |
|---|---|---|
| `environment_scan` | `环境检查` + `运维辅助`（并行） | 环境信息、依赖清单、容器就绪 |
| `code_analysis` | `通用处理`（拆解分发）+ `代码分析` | 漏洞候选 → 写 `vulnerabilities` |
| `vulnerability_verify` | `漏洞验证`（每个候选一个 worker_task） | 动态 PoC / 静态兜底，更新 `verify_status` |
| `report_generate` | `报告整理` | 攻击路径 + 最终报告 |
| `done` | — | 终态 |

每个 worker_task 独立记录（task_content/result_summary/started_at/finished_at/error），可回溯到 project + stage。每类角色有专属 system prompt 和工具子集。角色在执行中向 `chat_messages` 写入进展（供实时监控页展示），并经 WS 推送。

## LangGraph 编排

- `StateGraph` 节点 = 阶段；`AgentState` 携带 `project_id`、当前阶段、累积漏洞、攻击路径候选、错误信息。
- 每个阶段节点内部：按上面映射生成 `worker_tasks` → 对每个角色做一次 LLM 调用（OpenAI 兼容 client，带工具调用）→ 落库 + 推送 WS 状态 → 检查 `stop` 标记（停止时当前阶段不再推进，已存数据保留）。
- 漏洞/攻击路径/报告用 **structured output（JSON）** 对齐表结构，由调度器确定性落库。
- 并发数取自系统配置，限制同一阶段并行 worker 数。

## 隔离环境（Docker）

- 基础镜像 `Dockerfile`：`python:3.11-slim` + flask + git + curl，供 `docker build -t assessment-runner`。
- 项目启动 → `docker run`：`-v <source>:/src:ro`（只读）、`-v workspace/{id}:/workspace`、分配独立容器名/编号。
- 命令执行经 `docker exec`；动态验证时在容器内起示例 Flask 应用并跑 PoC。
- 删除项目 → 停/删容器 + 删除 `runtime_logs/{id}`、`reports/{id}`、`workspace/{id}`。
- 系统配置页可维护隔离环境配置、默认超时、并发数、保留天数。

## 前端（9 页，静态 + 原生 JS）

登录 / 项目列表 / 项目创建 / 项目详情 / 实时监控（WS 订阅 `stage_status`/`worker_status`/`chat_message`/`runtime_log`/`resource_usage`/`vulnerability_found`/`report_ready`）/ 漏洞列表 / 攻击路径 / 报告 / 系统配置。共用 `static/js/api.js`（fetch 封装 + WS 客户端）与 `static/css/style.css`。

## 接口（16 个，见需求 2.5.10）

按文档实现全部：`/api/system/init`、`/api/system/login`、项目 CRUD + start/stop、stages、workers、vulnerabilities、attack-paths、report、logs、resources，以及 `WS /api/projects/{id}/stream`。补齐 `/api/system/config`（系统配置读取/更新）。

## 示例项目（example_project/）

Flask 应用，含 5 类故意漏洞：SQL 注入、命令注入、反射型 XSS、路径穿越、硬编码密钥/弱鉴权，并附一段说明。用于完整演示链路（接入 → 分析 → 验证 → 报告）。

## 实施顺序

1. 骨架：`config/database/models/schemas` + `init_db.py` + `.env.example` + requirements。
2. 认证 + 项目 + 系统配置接口（含 session）。
3. Docker 隔离模块 + 镜像构建脚本。
4. LLM client + LangGraph 编排 + 6 角色 + 工具集 + 调度器 + WS 推送。
5. 漏洞/攻击路径/报告/日志/资源服务与接口。
6. 前端 9 页 + WS 实时监控。
7. 示例项目 + `README.md`（启动步骤 + 接口说明 + 演示链路）。

## 验证（端到端）

1. `docker build` 隔离镜像；`docker run` 起 MySQL；`python scripts/init_db.py`；`uvicorn app.main:app`。
2. 初始化管理员 → 登录 → 创建项目（接入 `example_project`）→ 启动任务。
3. 在实时监控页看到阶段推进、角色状态、聊天消息、日志滚动、资源变化。
4. 任务完成后：漏洞列表含 5 类漏洞且验证状态正确、攻击路径生成、报告可预览/下载。
5. 停止任务验证当前阶段不再推进但数据保留；删除项目验证级联删除与目录清理。
6. 全链路对照需求 2.5.13 验收标准逐条确认。

## 前置依赖（需在实现前确认用户环境具备）

- Docker Desktop（Windows）可运行；本机 Python 3.11+；MySQL 可经 Docker 拉起；DeepSeek API key（OpenAI 兼容 base_url）。
