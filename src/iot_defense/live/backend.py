"""Real firewall responses for the host this system is protecting.

The lab executor acts on Mininet hosts. This acts on the machine it runs on,
through iptables, with three safeguards the lab never needed because nothing
there could lock anyone out:

* Everything lives in one dedicated chain (IOTDEF), hooked only to the one
  network interface under protection. The management interface (the one the
  SSH tunnel uses) is never touched, and removing the chain removes every
  rule this module ever added.
* Addresses that must never be blocked (the box itself, trusted devices, the
  gateway) are refused before any command runs, and are also given RETURN
  rules ahead of every block, so even a mistaken rule cannot match them.
* Every block expires. A Python timer removes it, and, where the kernel has
  the `time` match, the rule itself stops matching at the deadline even if
  this process has died.

Only responses with a faithful single-host meaning are implemented. A policy
that proposes anything else (a decoy, for instance, needs a second machine) is
set aside by the pipeline, not approximated.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from iot_defense.defense.decision import DefenseAction

CHAIN = "IOTDEF"
COMMENT_PREFIX = "iotdef"
SUPPORTED_ACTIONS = frozenset(
    {
        DefenseAction.ALLOW,
        DefenseAction.ALERT,
        DefenseAction.FORENSIC_CAPTURE,
        DefenseAction.BLOCK_SOURCE,
        DefenseAction.THROTTLE,
    }
)
# Why each other response is unavailable here, in one sentence for the dashboard. Every action not in SUPPORTED_ACTIONS
# must have one (a test checks), so a proposal that is set aside always says why.
UNAVAILABLE_REASONS = {
    DefenseAction.QUARANTINE: "Needs default-deny on outgoing traffic too; this firewall only filters incoming traffic, and that is not built yet.",
    DefenseAction.ISOLATE: "Would take this machine's own network link down, cutting off its legitimate users as well; not implemented here.",
    DefenseAction.DECOY: "Needs a second machine to redirect the attacker to; the live defender is one machine.",
    DefenseAction.BANDWIDTH_CAP: "Caps the attacker's own network link, which a single protected machine does not control.",
    DefenseAction.RESET_SESSIONS: "Kills established connections; not implemented on the live defender.",
}

Runner = Callable[[list[str]], tuple[int, str]]


class UnsafeTargetError(ValueError):
    """Refusal to act on an address that must never be blocked."""


def run_command(args: list[str]) -> tuple[int, str]:
    completed = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
    return completed.returncode, (completed.stdout + completed.stderr)


def _stamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class IptablesBackend:
    supported_actions = SUPPORTED_ACTIONS

    def __init__(
        self,
        iface: str,
        protected_ips: Iterable[str],
        *,
        allowlist: Iterable[str] = (),
        runner: Runner | None = None,
        ttl_seconds: float = 60.0,
        throttle_rate_per_second: int = 10,
        clock: Callable[[], float] = time.time,
        evidence_dir: str | Path = "data/live/evidence",
    ) -> None:
        self.iface = iface
        self.protected_ips = frozenset(protected_ips)
        self.allowlist: set[str] = set(allowlist)
        self.run = runner or run_command
        self.ttl = float(ttl_seconds)
        self.throttle_rate = int(throttle_rate_per_second)
        self.clock = clock
        self.evidence_dir = Path(evidence_dir)
        self.kernel_expiry = False
        self._active: dict[str, dict[str, Any]] = {}  # source ip -> rule record
        self._installed = False

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def _ipt(self, *args: str) -> tuple[int, str]:
        return self.run(["iptables", "-w", "5", *args])

    def setup(self) -> None:
        """Create the chain, hook it to the protected interface, and shield the allowlist."""
        self.teardown()
        for args in (("-N", CHAIN), ("-I", "INPUT", "1", "-i", self.iface, "-j", CHAIN)):
            code, out = self._ipt(*args)
            if code != 0:
                raise RuntimeError(f"iptables {' '.join(args)} failed: {out.strip()}")
        self._installed = True
        for address in sorted(self.allowlist | self.protected_ips):
            self._ipt("-A", CHAIN, "-s", address, "-m", "comment", "--comment", f"{COMMENT_PREFIX}:allow:{address}", "-j", "RETURN")
        # Is the kernel `time` match available? If so, a rule outlives a dead process only until its deadline.
        probe = ["-A", CHAIN, "-s", "192.0.2.1", "-m", "time", "--utc", "--datestop", "2099-01-01T00:00:00", "-j", "RETURN"]
        code, _ = self._ipt(*probe)
        self.kernel_expiry = code == 0
        if self.kernel_expiry:
            self._ipt("-D", *probe[1:])

    def teardown(self) -> None:
        """Remove the hook and the chain, and with them every rule added here."""
        for _ in range(8):  # the hook may have been added more than once by an earlier crash
            code, _ = self._ipt("-D", "INPUT", "-i", self.iface, "-j", CHAIN)
            if code != 0:
                break
        self._ipt("-F", CHAIN)
        self._ipt("-X", CHAIN)
        self._active.clear()
        self._installed = False

    restore_all = teardown

    # ── safety ────────────────────────────────────────────────────────────────
    def guard(self, address: str) -> str:
        """Return `address` if it is safe to act on, else raise UnsafeTargetError."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UnsafeTargetError(f"{address!r} is not an IP address") from exc
        if ip.version != 4 or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise UnsafeTargetError(f"{address} is not a routable IPv4 peer")
        if address in self.protected_ips:
            raise UnsafeTargetError(f"{address} is this machine")
        if address in self.allowlist:
            raise UnsafeTargetError(f"{address} is on the never-block list")
        return address

    def trust(self, address: str) -> None:
        """Add an address to the never-block list while running (a device that
        has proven itself legitimate). If it was somehow blocked, release it."""
        if address in self.allowlist or address in self.protected_ips:
            return
        self.allowlist.add(address)
        record = self._active.pop(address, None)
        if record is not None:
            self._ipt("-D", CHAIN, *record["rule"])
        if self._installed:
            self._ipt("-I", CHAIN, "1", "-s", address, "-m", "comment", "--comment", f"{COMMENT_PREFIX}:allow:{address}", "-j", "RETURN")

    # ── responses ─────────────────────────────────────────────────────────────
    def _rule(self, address: str, kind: str, match: list[str], expires: float) -> list[str]:
        spec = ["-s", address, "-m", "comment", "--comment", f"{COMMENT_PREFIX}:{kind}:{address}"]
        if self.kernel_expiry:
            spec += ["-m", "time", "--utc", "--datestop", _stamp(expires)]
        return spec + match + ["-j", "DROP"]

    def _install(self, address: str, kind: str, match: list[str]) -> dict[str, Any]:
        self.guard(address)
        if not self._installed:
            raise RuntimeError("backend is not set up; call setup() first")
        now = self.clock()
        if address in self._active:
            record = self._active[address]
            record["expires"] = now + self.ttl  # refresh; the existing rule's kernel deadline still bounds it
            return {**self.describe(record), "already_active": True}
        expires = now + self.ttl
        rule = self._rule(address, kind, match, expires)
        code, out = self._ipt("-A", CHAIN, *rule)
        if code != 0:
            raise RuntimeError(f"could not install {kind} rule for {address}: {out.strip()}")
        record = {"ip": address, "kind": kind, "rule": rule, "installed": now, "expires": expires}
        self._active[address] = record
        return {**self.describe(record), "already_active": False}

    def block_source(self, address: str) -> dict[str, Any]:
        return self._install(address, "block", [])

    def throttle(self, address: str) -> dict[str, Any]:
        name = "iotdef_" + hashlib.sha1(address.encode()).hexdigest()[:6]  # hashlimit names are capped at 15 chars
        match = [
            "-m", "hashlimit", "--hashlimit-above", f"{self.throttle_rate}/second", "--hashlimit-burst", str(self.throttle_rate),
            "--hashlimit-mode", "srcip", "--hashlimit-name", name,
        ]
        details = self._install(address, "throttle", match)
        details["rate"] = f"{self.throttle_rate}/second"
        return details

    def save_evidence(self, address: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        """FORENSIC_CAPTURE on a single host: keep the packets seen from this
        source, change nothing on the network."""
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        path = self.evidence_dir / f"{int(self.clock())}_{address}.jsonl"
        path.write_text("".join(json.dumps(e, default=str) + "\n" for e in events), encoding="utf-8")
        return {"operation": "forensic_capture", "pcap_path": str(path), "packets": len(events)}

    def describe(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "operation": record["kind"],
            "source_ip": record["ip"],
            "mechanism": "iptables",
            "chain": CHAIN,
            "interface": self.iface,
            "expires_in_s": max(0.0, round(record["expires"] - self.clock(), 1)),
            "kernel_expiry": self.kernel_expiry,
        }

    # ── upkeep ────────────────────────────────────────────────────────────────
    def active_sources(self) -> set[str]:
        return set(self._active)

    def expire_due(self) -> list[str]:
        """Remove rules whose time is up; returns the addresses released."""
        now = self.clock()
        released = []
        for address, record in list(self._active.items()):
            if now >= record["expires"]:
                self._ipt("-D", CHAIN, *record["rule"])
                del self._active[address]
                released.append(address)
        return released

    def counters(self) -> dict[str, dict[str, int]]:
        """Packets and bytes each active rule has dropped, read from the kernel."""
        code, out = self._ipt("-L", CHAIN, "-n", "-v", "-x")
        if code != 0:
            return {}
        totals: dict[str, dict[str, int]] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 9 or not parts[0].isdigit() or "DROP" not in parts[2]:
                continue
            if f"{COMMENT_PREFIX}:" not in line:
                continue
            address = parts[7]
            entry = totals.setdefault(address, {"packets": 0, "bytes": 0})
            entry["packets"] += int(parts[0])
            entry["bytes"] += int(parts[1])
        return totals

    def snapshot(self) -> list[dict[str, Any]]:
        counted = self.counters()
        return [
            {**self.describe(record), "packets_dropped": counted.get(address, {}).get("packets", 0),
             "bytes_dropped": counted.get(address, {}).get("bytes", 0)}
            for address, record in self._active.items()
        ]

