"""The small web service the protected box offers, and the proof it stays up.

A phone (or any browser) opens this page and it checks in every two seconds. That
does two jobs in a live demo:

* It is the "normal user". The page turns red the moment a response stops it
  from reaching the box, so a response that also hurts legitimate users is
  visible to the whole room, not just in a log.
* It identifies who is legitimate. A device that has completed real
  HTTP check-ins is trusted and added to the never-block list. A scanner that
  merely knocks on the port never completes a request, so it never qualifies.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Protected device</title>
<style>
  body{margin:0;font-family:system-ui,sans-serif;background:#0a0c10;color:#e2e8f4;display:grid;place-items:center;min-height:100vh;text-align:center}
  .card{padding:2rem 1.5rem;max-width:22rem}
  .state{font-size:2.6rem;font-weight:800;letter-spacing:.04em;margin:.4rem 0}
  .ok{color:#22c55e}.bad{color:#ef4444}
  .meta{color:#8a9bbf;font-size:.95rem;line-height:1.6}
</style></head>
<body><div class="card">
  <div class="meta">Protected device</div>
  <div id="state" class="state ok">ONLINE</div>
  <div class="meta" id="meta">connecting&hellip;</div>
</div>
<script>
let ok = 0, failed = 0;
async function check() {
  const state = document.getElementById('state'), meta = document.getElementById('meta');
  try {
    const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 1500);
    const r = await fetch('/ping', {cache: 'no-store', signal: ctl.signal}); clearTimeout(timer);
    const j = await r.json(); ok++;
    state.textContent = 'ONLINE'; state.className = 'state ok';
    meta.textContent = 'Last reply ' + new Date(j.t * 1000).toLocaleTimeString() + ' - ' + ok + ' replies, ' + failed + ' missed';
  } catch (e) {
    failed++; state.textContent = 'NO RESPONSE'; state.className = 'state bad';
    meta.textContent = ok + ' replies, ' + failed + ' missed';
  }
}
check(); setInterval(check, 2000);
</script></body></html>
"""


class LegitService:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, clock: Callable[[], float] = time.time) -> None:
        self.host, self.port, self.clock = host, port, clock
        self._requests: deque[tuple[float, str]] = deque(maxlen=20_000)
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ── bookkeeping ───────────────────────────────────────────────────────────
    def record(self, client_ip: str) -> None:
        with self._lock:
            self._requests.append((self.clock(), client_ip))

    def served_since(self, seconds: float, exclude: set[str] | frozenset[str] = frozenset()) -> int:
        cutoff = self.clock() - seconds
        with self._lock:
            return sum(1 for t, ip in self._requests if t >= cutoff and ip not in exclude)

    def trusted_clients(self, min_requests: int = 2, within_seconds: float = 120.0) -> set[str]:
        cutoff = self.clock() - within_seconds
        counts: dict[str, int] = {}
        with self._lock:
            for t, ip in self._requests:
                if t >= cutoff:
                    counts[ip] = counts.get(ip, 0) + 1
        return {ip for ip, n in counts.items() if n >= min_requests}

    # ── server ────────────────────────────────────────────────────────────────
    def start(self) -> int:
        service = self

        class Handler(BaseHTTPRequestHandler):
            # Keep-alive: the page's polling reuses one TCP connection instead of opening a new
            # one each time, which on the wire would look like a stream of connection attempts.
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                if self.path.startswith("/ping"):
                    service.record(self.client_address[0])
                    body = json.dumps({"ok": True, "t": service.clock()}).encode()
                    content_type = "application/json"
                else:
                    body, content_type = PAGE.encode(), "text/html; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up (a page reload, a phone locking); nothing to report

            def log_message(self, *_args: object) -> None:  # keep the terminal for the defender's own output
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name="legit-service", daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
