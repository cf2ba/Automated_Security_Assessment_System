"""数据库初始化脚本：创建数据库、建表、准备数据目录。

用法：
    python scripts/init_db.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.database import SessionLocal, create_all, ensure_database_exists  # noqa: E402
from app.services import config_service  # noqa: E402


def main() -> None:
    settings.ensure_dirs()
    print(f"[1/4] 数据目录已准备：{settings.data_dir}")
    ensure_database_exists()
    print("[2/4] 数据库已确认存在")
    create_all()
    print("[3/4] 数据表已创建（users / projects / runtime_stages / worker_tasks / "
          "vulnerabilities / attack_paths / attack_path_items / chat_messages / "
          "runtime_logs / resource_usages / reports / system_configs）")
    db = SessionLocal()
    try:
        added = config_service.seed_defaults(db)
    finally:
        db.close()
    print(f"[4/4] 系统配置默认值已补齐（新增 {added} 项，已有配置未覆盖）")
    print("\n完成。启动后端：uvicorn app.main:app --reload --port 8000")
    print("首次访问前端后，在登录页创建管理员账户。")


if __name__ == "__main__":
    main()
