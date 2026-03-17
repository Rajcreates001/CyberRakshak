import asyncio
from typing import Any
from typing import Set

from fastapi import WebSocket


class WebsocketManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast_json(self, payload: dict[str, Any]) -> None:
        async with self._lock:
            stale = []
            for websocket in self._connections:
                try:
                    await websocket.send_json(payload)
                except Exception:
                    stale.append(websocket)

            for websocket in stale:
                self._connections.discard(websocket)
