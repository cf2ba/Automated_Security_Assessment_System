"""进程内评估任务生命周期管理（单实例演示足够）。"""
from __future__ import annotations

import asyncio
from typing import Callable, Coroutine, Any


class TaskManager:
    def __init__(self) -> None:
        self._tasks: dict[int, asyncio.Task] = {}
        self._stop_events: dict[int, asyncio.Event] = {}

    def is_running(self, project_id: int) -> bool:
        task = self._tasks.get(project_id)
        return bool(task and not task.done())

    def start(self, project_id: int, factory: Callable[[], Coroutine[Any, Any, Any]]) -> None:
        if self.is_running(project_id):
            raise RuntimeError("该项目的评估任务已在运行")
        self._stop_events[project_id] = asyncio.Event()
        task = asyncio.create_task(factory(), name=f"assessment-{project_id}")
        self._tasks[project_id] = task

        def _cleanup(_t: asyncio.Task) -> None:
            self._tasks.pop(project_id, None)
            self._stop_events.pop(project_id, None)

        task.add_done_callback(_cleanup)

    def request_stop(self, project_id: int) -> bool:
        event = self._stop_events.get(project_id)
        if event is None:
            return False
        event.set()
        return True

    def is_stop_requested(self, project_id: int) -> bool:
        event = self._stop_events.get(project_id)
        return bool(event and event.is_set())

    async def wait_stopped(self, project_id: int, timeout: float = 10.0) -> bool:
        task = self._tasks.get(project_id)
        if not task:
            return True
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return False
        except Exception:
            return True
        return True

    def cancel(self, project_id: int) -> None:
        task = self._tasks.get(project_id)
        if task and not task.done():
            task.cancel()


task_manager = TaskManager()
