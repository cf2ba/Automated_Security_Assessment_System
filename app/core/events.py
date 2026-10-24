"""进程内实时事件广播：每项目单调 seq + 500 条环形历史，支持断线回放。"""
from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

HISTORY_SIZE = 500


class EventBroker:
    def __init__(self) -> None:
        self._subscribers: dict[int, set[asyncio.Queue]] = defaultdict(set)
        self._seq: dict[int, int] = defaultdict(int)
        self._history: dict[int, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=HISTORY_SIZE)
        )

    def subscribe(self, project_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers[project_id].add(q)
        return q

    def unsubscribe(self, project_id: int, q: asyncio.Queue) -> None:
        self._subscribers[project_id].discard(q)
        if not self._subscribers[project_id]:
            self._subscribers.pop(project_id, None)

    def reset(self) -> None:
        """仅供测试/单实例重启使用，清空所有订阅与历史。"""
        self._subscribers.clear()
        self._seq.clear()
        self._history.clear()

    def last_seq(self, project_id: int) -> int:
        return self._seq.get(project_id, 0)

    def events_after(self, project_id: int, after_seq: int) -> list[dict[str, Any]]:
        return [dict(e) for e in self._history.get(project_id, ()) if e.get("seq", 0) > after_seq]

    def replay_available(self, project_id: int, after_seq: int) -> bool:
        """请求的 seq 是否仍在历史窗口内。"""
        if after_seq <= 0:
            return True
        history = self._history.get(project_id)
        if not history:
            return after_seq >= self.last_seq(project_id)
        return history[0].get("seq", 0) <= after_seq + 1

    async def publish(self, project_id: int, event: dict[str, Any]) -> dict[str, Any]:
        seq = self._seq[project_id] + 1
        self._seq[project_id] = seq
        payload = dict(event)
        payload["seq"] = seq
        payload.setdefault("project_id", project_id)
        payload.setdefault("ts", datetime.now(timezone.utc).isoformat())
        self._history[project_id].append(payload)
        for q in list(self._subscribers.get(project_id, ())):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
        return payload


broker = EventBroker()
