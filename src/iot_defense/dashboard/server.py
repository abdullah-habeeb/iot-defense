"""FastAPI dashboard server — SSE event bus, static file serving, state endpoint."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.demo.controller import DemoController

# ── Paths ──────────────────────────────────────────────────────────────────────
_REPO_ROOT = Path("/home/abdullah/iot-defense")
_STATIC_DIR = _REPO_ROOT / "data" / "dashboard" / "static"
_STATIC_DIR.mkdir(parents=True, exist_ok=True)
_STATE_FILE = _REPO_ROOT / "data" / "dashboard" / "state.json"
# The venv's own python3, not sys.executable -- this process is already
# running inside that venv (uvicorn is installed there), but spelling it
# out explicitly here matches the one, sole sudoers rule every other real
# Mininet entry point in this project already depends on: passwordless
# sudo is scoped to exactly this interpreter path, not to "whatever
# python launched the caller".
_VENV_PYTHON = _REPO_ROOT / ".venv" / "bin" / "python3"

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


@app.get("/attacks")
async def list_attacks() -> JSONResponse:
    """The registry's own attack keys and display labels -- the dashboard's
    run-trigger control builds its options from this, not a hand-maintained
    list, so it can never drift out of sync with what's actually registered."""
    return JSONResponse(
        content=[{"key": key, "label": scenario.label} for key, scenario in ATTACK_SCENARIOS.items()]
    )


# Guards the one real Mininet network this project's every live entry point
# already assumes is exclusive -- a second concurrent run would collide on
# the same fixed switch/host names in config/topology.yaml. Holds the
# subprocess handle, not just a boolean, so /run/status can report whether
# the process genuinely exited (poll()) rather than trusting a flag no one
# ever cleared.
_active_run: dict[str, Any] = {"process": None, "attack": None}
_run_lock = asyncio.Lock()


@app.post("/run")
async def trigger_run(request: Request) -> JSONResponse:
    """Launch one real demo run for a registered attack key -- the same
    `sudo .venv/bin/python3 -m iot_defense.demo.controller --attack <key>`
    every real live-verification in this project's own history has used
    from a terminal, just started from this endpoint instead. The demo
    controller's own writes to state.json are what /stream already picks
    up from any process, so nothing else here needs to know how a run
    actually progresses.

    The attack key is validated against ATTACK_SCENARIOS before it ever
    reaches a shell -- never pass a request body value into a command
    unchecked, even when the surrounding call is a fixed argv list (no
    shell=True, no string interpolation) that isn't itself injectable.
    """
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse(status_code=400, content={"error": "Request body must be JSON."})

    attack = body.get("attack") if isinstance(body, dict) else None
    if attack not in ATTACK_SCENARIOS:
        return JSONResponse(
            status_code=400,
            content={"error": f"Unknown attack key: {attack!r}.", "valid_keys": sorted(ATTACK_SCENARIOS)},
        )

    async with _run_lock:
        current = _active_run["process"]
        if current is not None and current.returncode is None:
            return JSONResponse(
                status_code=409,
                content={"error": f"A run ({_active_run['attack']}) is already in progress.", "attack": _active_run["attack"]},
            )
        process = await asyncio.create_subprocess_exec(
            "sudo", "-n", str(_VENV_PYTHON), "-m", "iot_defense.demo.controller", "--attack", attack,
            cwd=str(_REPO_ROOT),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        _active_run["process"] = process
        _active_run["attack"] = attack

    return JSONResponse(content={"status": "started", "attack": attack})


@app.get("/run/status")
async def run_status() -> JSONResponse:
    """Whether a triggered run is still in flight -- the frontend polls this
    to know when it's safe to offer another run, rather than guessing from
    a fixed timeout that would be wrong for every attack's real, very
    different duration (icmp_flood ~4s vs. mqtt_flood ~110s)."""
    process = _active_run["process"]
    running = process is not None and process.returncode is None
    return JSONResponse(content={"running": running, "attack": _active_run["attack"] if running else None})


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

        # Send current state immediately on connect. state.json (not the
        # in-process controller.state) is the authoritative source here: a
        # demo run under sudo lives in a separate process, so the in-process
        # object never changes during a real run. On a fresh connection mid
        # or after a demo, sending the stale in-process snapshot first would
        # briefly overwrite the correct data with a leftover IDLE state
        # until the next poll cycle corrected it.
        try:
            last_sent = _STATE_FILE.read_text(encoding="utf-8")
            json.loads(last_sent)  # validate before trusting a partial write
            yield f"data: {last_sent}\n\n"
        except (OSError, json.JSONDecodeError):
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
            #
            # last_mtime is only committed AFTER a successful read+parse,
            # not as soon as a changed mtime is observed -- a real bug
            # found by watching a live demo run visibly freeze mid-stream
            # (stuck on an early phase in the browser while state.json,
            # confirmed separately, had already reached "CLEANUP"). During
            # a burst of rapid writes (several phase transitions can land
            # within a few hundred ms), a poll tick can catch a *mid-write*
            # file: json.loads() raises, correctly caught below -- but if
            # last_mtime had already been advanced to that mtime, the next
            # tick's `mtime != last_mtime` check is now false even though
            # this update was never actually sent, so the stream never
            # retries it and permanently stalls one state behind. Keeping
            # last_mtime at its old value until the read genuinely
            # succeeds means the very next tick (0.4s later, by which time
            # the write has finished) retries and catches up correctly.
            try:
                mtime = _STATE_FILE.stat().st_mtime
                if mtime != last_mtime:
                    text = _STATE_FILE.read_text(encoding="utf-8")
                    json.loads(text)  # guard against a mid-write partial read
                    last_mtime = mtime
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
