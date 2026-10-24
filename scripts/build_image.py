"""构建隔离环境基础镜像 assessment-runner:latest。

用法：
    python scripts/build_image.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.isolation import docker as iso  # noqa: E402


def main() -> None:
    try:
        iso.ensure_image(settings.docker_image, settings.dockerfile_dir)
    except iso.IsolationError as exc:
        print(f"构建失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"镜像已就绪：{settings.docker_image}")


if __name__ == "__main__":
    main()
