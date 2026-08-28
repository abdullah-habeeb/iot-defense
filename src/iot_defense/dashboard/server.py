"""FastAPI dashboard server — SSE event bus, static file serving, state endpoint."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from iot_defense.demo.controller import DemoController

# ── Paths ──────────────────────────────────────────────────────────────────────
_STATIC_DIR = Path("/home/abdullah/iot-defense/data/dashboard/static")
_STATIC_DIR.mkdir(parents=True, exist_ok=True)
_STATE_FILE = Path("/home/abdullah/iot-defense/data/dashboard/state.json")

# Ensure state file exists before first request
if not _STATE_FILE.exists():
    _STATE_FILE.write_text(json.dumps({"phase": "IDLE"}), encoding="utf-8")

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="IoT Defense Dashboard",
    description="Residential IoT Cyber Defense Demonstrator",
    version="1.0.0",
)

# Singleton controller — shared across all SSE streams and the /state endpoint
controller = DemoController()

# Mount static files (index.html, dashboard.js, style.css)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
async def read_root() -> FileResponse:
    """Serve the dashboard SPA."""
    return FileResponse(str(_STATIC_DIR / "index.html"))


@app.get("/state")
async def get_state() -> JSONResponse:
    """Return the latest persisted state snapshot."""
    try:
        data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        return JSONResponse(content=data)
    except (OSError, json.JSONDecodeError):
        return JSONResponse(content={"phase": "IDLE"})


# How often /stream polls state.json for changes made by an external process
# (e.g. the demo controller run separately under sudo for Mininet). This is the
# only channel available across process boundaries — the in-process event_queue
# only carries updates from a DemoController living in this same server process.
_STATE_POLL_SECONDS = 0.4
_STATE_POLL_TICKS_PER_KEEPALIVE = int(15.0 / _STATE_POLL_SECONDS)


@app.get("/stream")
async def message_stream(request: Request) -> StreamingResponse:
    """SSE endpoint — broadcasts every state update as a data event.

    Two independent sources feed this stream so it works whether the demo
    runs inside this server process or as a separate sudo-elevated process
    (required for Mininet):
      1. The in-process controller.event_queue, for same-process updates.
      2. Polling state.json's mtime, for updates written by any other
         process — this is the only channel that crosses process boundaries.
    """

    async def event_generator():
        last_sent: str | None = None
        last_mtime: float | None = None

        # Send current state immediately on connect
        try:
            last_sent = json.dumps(controller.state, default=str)
            yield f"data: {last_sent}\n\n"
        except Exception:  # noqa: BLE001
            yield f"data: {{}}\n\n"
        try:
            last_mtime = _STATE_FILE.stat().st_mtime
        except OSError:
            last_mtime = None

        idle_ticks = 0
        while True:
            if await request.is_disconnected():
                break

            sent_this_tick = False

            # 1) Drain any in-process queue events (non-blocking).
            try:
                state = controller.event_queue.get_nowait()
                payload = json.dumps(state, default=str)
                yield f"data: {payload}\n\n"
                last_sent = payload
                sent_this_tick = True
            except asyncio.QueueEmpty:
                pass
            except Exception:  # noqa: BLE001
                break

            # 2) Check state.json for changes made by any process.
            try:
                mtime = _STATE_FILE.stat().st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    text = _STATE_FILE.read_text(encoding="utf-8")
                    json.loads(text)  # guard against a mid-write partial read
                    if text != last_sent:
                        yield f"data: {text}\n\n"
                        last_sent = text
                        sent_this_tick = True
            except (OSError, json.JSONDecodeError):
                pass

            if sent_this_tick:
                idle_ticks = 0
            else:
                idle_ticks += 1
                if idle_ticks >= _STATE_POLL_TICKS_PER_KEEPALIVE:
                    yield ": keepalive\n\n"
                    idle_ticks = 0

            await asyncio.sleep(_STATE_POLL_SECONDS)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
