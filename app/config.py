"""全局配置：优先读取环境变量 / .env，运行时配置再叠加数据库中的 system_configs。"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "自动化安全评估系统"
    secret_key: str = "sas-dev-secret-change-me"
    database_url: str = (
        "mysql+pymysql://root:root@127.0.0.1:3307/security_assessment?charset=utf8mb4"
    )

    # LLM（OpenAI 兼容接口，默认 DeepSeek）
    llm_base_url: str = "https://api.deepseek.com"
    llm_api_key: str = ""
    llm_model: str = "deepseek-chat"
    llm_timeout: int = 300
    # 离线演示开关：为 true 时不真正调用模型，返回内置结构化结果
    llm_mock: bool = False

    # 隔离环境
    docker_image: str = "assessment-runner:latest"
    dockerfile_dir: str = str(BASE_DIR / "docker")
    isolation_target_port: int = 5000
    isolation_required: bool = True
    enable_dynamic_verify: bool = True

    # 运行时默认值（可在系统配置页覆盖，写入 system_configs）
    default_timeout: int = 3600
    max_concurrency: int = 3
    retention_days: int = 30
    resource_sample_seconds: int = 3

    data_dir: str = str(STATE_DIR)
    max_context_chars: int = 90000
    max_read_files: int = 40
    # 分号分隔；为空表示开发模式不限制
    allowed_source_roots: str = ""

    @property
    def log_dir(self) -> Path:
        return Path(self.data_dir) / "runtime_logs"

    @property
    def report_dir(self) -> Path:
        return Path(self.data_dir) / "reports"

    @property
    def workspace_dir(self) -> Path:
        return Path(self.data_dir) / "workspace"

    @property
    def allowed_source_root_list(self) -> list[Path]:
        roots = [p.strip() for p in self.allowed_source_roots.split(";") if p.strip()]
        return [Path(p).resolve() for p in roots]

    def ensure_dirs(self) -> None:
        for p in (self.log_dir, self.report_dir, self.workspace_dir, Path(self.data_dir) / "logs"):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
if os.getenv("SAS_DATA_DIR"):
    settings.data_dir = os.getenv("SAS_DATA_DIR")
_data_path = Path(settings.data_dir)
if not _data_path.is_absolute():
    settings.data_dir = str((BASE_DIR / _data_path).resolve())
_dockerfile_path = Path(settings.dockerfile_dir)
if not _dockerfile_path.is_absolute():
    settings.dockerfile_dir = str((BASE_DIR / _dockerfile_path).resolve())
settings.ensure_dirs()
