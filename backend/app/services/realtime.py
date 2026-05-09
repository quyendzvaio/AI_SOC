import asyncio
from collections.abc import AsyncIterator
from typing import Any

import orjson


class RealtimeBroker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, event: dict[str, Any]) -> None:
        stale: list[asyncio.Queue[dict[str, Any]]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                stale.append(queue)
        for queue in stale:
            self._subscribers.discard(queue)

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)


broker = RealtimeBroker()


def sse(event_name: str, payload: dict[str, Any]) -> bytes:
    data = orjson.dumps(payload).decode("utf-8")
    return f"event: {event_name}\ndata: {data}\n\n".encode("utf-8")
