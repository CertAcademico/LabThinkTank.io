"""
In-process SSE (Server-Sent Events) event bus for real-time CTI updates.

Usage (publish side, e.g. from a feed fetcher or log ingest handler):

    from services.live_service import live_service
    live_service.publish("ioc_added", {"ioc": "1.2.3.4", "type": "IP", ...})

Usage (subscribe side, inside a FastAPI SSE endpoint):

    import asyncio, json
    from fastapi import Request
    from fastapi.responses import StreamingResponse

    @app.get("/live/feed")
    async def live_feed(request: Request):
        queue = live_service.subscribe()
        async def gen():
            # replay history so new clients see recent events
            for ev in live_service.get_history():
                yield f"data: {json.dumps(ev)}\\n\\n"
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=20)
                        yield f"data: {json.dumps(ev)}\\n\\n"
                    except asyncio.TimeoutError:
                        yield ": heartbeat\\n\\n"
            finally:
                live_service.unsubscribe(queue)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                  headers={"Cache-Control": "no-cache",
                                           "X-Accel-Buffering": "no"})
"""
import asyncio
import json
from collections import deque
from datetime import datetime, timezone


class LiveService:
    """Thread-safe-ish SSE event bus backed by asyncio.Queue per client."""

    def __init__(self, history_size: int = 300) -> None:
        self._clients: list[asyncio.Queue] = []
        self._history: deque[dict] = deque(maxlen=history_size)

    # ── Subscription management ────────────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1_000)
        self._clients.append(q)
        return q

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        try:
            self._clients.remove(queue)
        except ValueError:
            pass

    # ── Publishing ─────────────────────────────────────────────────────────────

    def publish(self, event_type: str, data: dict) -> None:
        """
        Broadcast *data* to all connected SSE clients and store in history.

        event_type examples: "ioc_added", "feed_synced", "log_ingested"
        """
        event = {
            "type": event_type,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            **data,
        }
        self._history.append(event)
        dead: list[asyncio.Queue] = []
        for q in list(self._clients):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    # ── History ────────────────────────────────────────────────────────────────

    def get_history(self, limit: int = 100) -> list[dict]:
        items = list(self._history)
        return items[-limit:]

    def client_count(self) -> int:
        return len(self._clients)


# Module-level singleton — import this everywhere
live_service = LiveService()
