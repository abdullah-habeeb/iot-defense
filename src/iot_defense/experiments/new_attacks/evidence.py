"""The evidence report: a demo-ready page generated from the artefacts, never typed.

    python -m iot_defense.experiments.new_attacks.evidence [--server] [--out DIR]

Every number and every status below is computed from files that exist in the repository or on GitHub: the frozen pre-registration
and its manifest, the hash-chained run log, the raw measured rows, the git history and (with --server) GitHub's own record of when
commits were pushed and comments posted. Anyone can re-run this script and get the same report.

What it can and cannot show is stated in the report itself. It makes tampering detectable (changed files, an edited row, a priors
commit that postdates a measurement); it cannot prove that the people who wrote the priors had not seen the results, which rests
on their declaration in the pre-registration and on the order of the timestamps.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import subprocess
from pathlib import Path
from typing import Any

from iot_defense.experiments.new_attacks import analyze, common, measure, prereg
from iot_defense.experiments.new_attacks.scenarios import NEW_ATTACK_KEYS

PASS, FAIL, WARN, UNVERIFIED = "PASS", "FAIL", "WARN", "UNVERIFIED"
FREEZE_REL = "config/experiments/new_attacks/FREEZE.json"
PREREG_REL = "config/experiments/new_attacks/preregistration.yaml"
ROWS_REL = "data/experiments/new_attacks/rows.jsonl"


def parse_time(text: str | None) -> dt.datetime | None:
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = dt.datetime.strptime(text, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def commit_facts(path: str, root: Path | None = None) -> dict[str, Any]:
    sha = common.git("log", "-1", "--format=%H", "--", path, root=root)
    if not sha:
        return {"path": path, "commit": None}
    return {"path": path, "commit": sha, "author_time": common.git("show", "-s", "--format=%aI", sha, root=root),
            "committer_time": common.git("show", "-s", "--format=%cI", sha, root=root),
            "subject": common.git("show", "-s", "--format=%s", sha, root=root)}


def github_evidence(owner_repo: str, commits: dict[str, str | None], pr: int | None) -> dict[str, Any]:
    """GitHub's own timestamps: PushEvents containing each commit, and PR comments that quote it. None where unavailable."""
    out: dict[str, Any] = {"available": False, "push_times": {}, "comment_times": {}}

    def api(path: str) -> Any:
        try:
            done = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=False, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        return json.loads(done.stdout) if done.returncode == 0 and done.stdout.strip() else None

    events = api(f"repos/{owner_repo}/events?per_page=100")
    comments = api(f"repos/{owner_repo}/issues/{pr}/comments?per_page=100") if pr else None
    out["available"] = events is not None or comments is not None
    for label, sha in commits.items():
        if not sha:
            continue
        for event in events or []:
            payload = event.get("payload") or {}
            shas = {c.get("sha") for c in payload.get("commits", [])} | {payload.get("head")}
            if event.get("type") == "PushEvent" and sha in shas:
                out["push_times"][label] = event.get("created_at")
                break
        for comment in comments or []:
            if sha in (comment.get("body") or ""):
                out["comment_times"][label] = comment.get("created_at")
                break
    return out


def gather(root: Path | None = None, *, server: bool = False, pr: int | None = None, owner_repo: str | None = None) -> dict[str, Any]:
    root = root or common.REPO_ROOT
    manifest_path = root / FREEZE_REL
    rows_path = root / ROWS_REL
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    log = common.read_jsonl(root / "data/experiments/new_attacks/run_log.jsonl")
    rows = common.read_jsonl(rows_path)
    facts: dict[str, Any] = {
        "manifest": manifest,
        "freeze_commit": commit_facts(FREEZE_REL, root),
        "prereg_commit": commit_facts(PREREG_REL, root),
        "rows_commit": commit_facts(ROWS_REL, root),
        "run_log": log,
        "rows": rows,
        "rows_sha256": common.sha256_file(rows_path) if rows_path.exists() else None,
        "smoke": common.read_jsonl(root / "data/experiments/new_attacks/smoke_log.jsonl"),
        "git_head": common.git("rev-parse", "HEAD", root=root),
        "drift": prereg.verify_freeze(manifest_path, root) if manifest else ["not frozen"],
        "results_stored": json.loads((root / "data/experiments/new_attacks/results.json").read_text(encoding="utf-8"))
        if (root / "data/experiments/new_attacks/results.json").exists() else None,
        "github": None,
    }
    if server and owner_repo:
        facts["github"] = github_evidence(owner_repo, {"freeze": facts["freeze_commit"].get("commit"),
                                                       "rows": facts["rows_commit"].get("commit")}, pr)
    return facts


def _check(ident: str, text: str, status: str, detail: str) -> dict[str, str]:
    return {"id": ident, "claim": text, "status": status, "detail": detail}


def run_checks(facts: dict[str, Any], *, spec: dict[str, Any] | None, recomputed: dict[str, Any] | None) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    manifest, rows, log = facts["manifest"], facts["rows"], facts["run_log"]
    measured = sorted(t for t in (parse_time(r.get("measured_at")) for r in rows) if t)
    first_row, last_row = (measured[0], measured[-1]) if measured else (None, None)
    freeze_time = parse_time(facts["freeze_commit"].get("committer_time"))
    prereg_time = parse_time(facts["prereg_commit"].get("committer_time"))

    checks.append(_check("E1", "Every file that decides, generates or grades is byte-identical to the frozen manifest",
                         PASS if not facts["drift"] else FAIL, "; ".join(facts["drift"]) or f"{len(manifest['files'])} files and the priors/objective sections match"))
    problems = prereg.validate(spec, _base_model(), require_ready=True) if spec else ["no pre-registration"]
    declaration = (spec or {}).get("blind_declaration", {})
    checks.append(_check("E2", "The pre-registration is complete and declares who wrote the priors and that they had seen no measurement of the new attacks",
                         PASS if not problems else FAIL,
                         "; ".join(problems) or f"priors by {declaration.get('priors_author')}, playbook by {declaration.get('playbook_author')}, "
                         f"saw outcome table: {declaration.get('saw_outcome_table')}"))
    ordered = bool(prereg_time and freeze_time and first_row and prereg_time <= freeze_time < first_row)
    checks.append(_check("E3", "Git order: the priors were committed, then frozen, then the first response was measured",
                         PASS if ordered else (UNVERIFIED if not measured else FAIL),
                         f"priors {facts['prereg_commit'].get('committer_time')} -> freeze {facts['freeze_commit'].get('committer_time')} -> first row "
                         f"{first_row.isoformat() if first_row else 'none'} (local git and local clock: this check can be forged by editing either)"))
    github = facts.get("github") or {}
    server_times = [parse_time(t) for t in (github.get("push_times", {}).get("freeze"), github.get("comment_times", {}).get("freeze")) if t]
    if server_times and first_row:
        checks.append(_check("E4", "GitHub's own clock agrees that the freeze was published before the first measurement",
                             PASS if min(server_times) < first_row else FAIL,
                             f"GitHub recorded the freeze at {min(server_times).isoformat()}; first row {first_row.isoformat()}"))
    else:
        checks.append(_check("E4", "GitHub's own clock agrees that the freeze was published before the first measurement", UNVERIFIED,
                             "no GitHub push event or PR comment for the freeze commit was available (re-run with --server after posting the freeze comment)"))
    started = [r for r in log if r.get("event") == "started"]
    empty_before = bool(manifest and not manifest["rows_state"]["exists"] or (manifest and manifest["rows_state"]["lines"] == 0))
    first_run_empty = bool(started and started[0]["rows_lines_before"] == 0)
    checks.append(_check("E5", "No measured row existed when the pre-registration was frozen",
                         PASS if empty_before and first_run_empty else FAIL,
                         f"manifest rows_state={manifest['rows_state'] if manifest else None}; first run began with "
                         f"{started[0]['rows_lines_before'] if started else 'n/a'} rows"))
    chain_ok, chain_detail = _verify_chain(log, facts["rows_sha256"], len(rows))
    checks.append(_check("E6", "The run log is an unbroken hash chain and the rows file is exactly what the logged runs produced (append-only)",
                         PASS if chain_ok else FAIL, chain_detail))
    shape = _shape(rows)
    checks.append(_check("E7", "Every primary block is complete (3 blocks x 11 measurements per attack) with no failed probe",
                         PASS if shape["primary_complete"] and not shape["probe_errors"] else FAIL,
                         f"rows per attack and block: {shape['counts']}; probe errors: {shape['probe_errors']}"))
    finished = [r for r in log if r.get("event") == "finished"]
    window_ok = bool(started and finished and measured and parse_time(started[0]["started_at"]) <= first_row and last_row <= parse_time(finished[-1]["finished_at"]))
    checks.append(_check("E8", "Every row's timestamp lies inside a logged measurement run", PASS if window_ok else FAIL,
                         f"runs {len(started)}; rows {first_row.isoformat() if first_row else '-'} .. {last_row.isoformat() if last_row else '-'}"))
    checks.append(_check("E9", "The 693-row benchmark the old priors were validated on is unchanged since the freeze",
                         PASS if manifest and not any("main_outcome_table" in d for d in facts["drift"]) else FAIL,
                         f"sha256 {manifest['main_outcome_table_sha256'][:16] if manifest else '-'}..."))
    if recomputed is not None and facts["results_stored"] is not None:
        same = _strip(recomputed) == _strip(facts["results_stored"])
        checks.append(_check("E10", "Recomputing the result from the raw rows right now reproduces the stored result", PASS if same else FAIL,
                             "identical" if same else "the stored results.json differs from a fresh computation"))
    else:
        checks.append(_check("E10", "Recomputing the result from the raw rows right now reproduces the stored result", UNVERIFIED, "no stored result or no rows"))
    smoke_ok = all(s.get("actions_applied") == ["ALLOW"] and s.get("blind_safe") for s in facts["smoke"])
    checks.append(_check("E11", "The pre-freeze smoke test applied no response (so it could not leak how any response performs)",
                         PASS if facts["smoke"] and smoke_ok else (UNVERIFIED if not facts["smoke"] else FAIL),
                         f"{len(facts['smoke'])} smoke run(s); actions applied: {sorted({a for s in facts['smoke'] for a in s.get('actions_applied', [])})}"))
    if facts["rows_commit"].get("commit") and last_row:
        committed = parse_time(facts["rows_commit"].get("committer_time"))
        checks.append(_check("E12", "The measured rows were committed after they were measured, unchanged",
                             PASS if committed and committed >= last_row and not _rows_dirty(facts) else FAIL,
                             f"rows commit {facts['rows_commit'].get('committer_time')}"))
    else:
        checks.append(_check("E12", "The measured rows were committed after they were measured, unchanged", UNVERIFIED, "rows.jsonl is not committed yet"))
    ntp = sorted({str(r.get("ntp_synchronized")) for r in started})
    checks.append(_check("E13", "The machine's clock was NTP-synchronised during every run", PASS if ntp == ["yes"] else (UNVERIFIED if not started else WARN),
                         f"timedatectl reported {ntp}; hosts {sorted({r.get('hostname') for r in started})}"))
    return checks


def _base_model() -> dict[str, Any]:
    from iot_defense.defense.objective import load_policy_section

    return load_policy_section("game_model")


def _rows_dirty(facts: dict[str, Any]) -> bool:
    committed = common.git("show", f"{facts['rows_commit']['commit']}:{ROWS_REL}")
    return bool(committed) and common.sha256_text(committed + "\n") != facts["rows_sha256"] and common.sha256_text(committed) != facts["rows_sha256"]


def _verify_chain(log: list[dict[str, Any]], rows_sha256: str | None, rows_count: int) -> tuple[bool, str]:
    if not log:
        return False, "no run log"
    previous = measure.GENESIS
    expected_rows_sha: str | None = None
    for index, record in enumerate(log):
        if record.get("prev_record_sha256") != previous:
            return False, f"record {index} does not match the hash of the record before it"
        if record["event"] == "started":
            if expected_rows_sha is not None and record["rows_sha256_before"] != expected_rows_sha:
                return False, f"run {index}: the rows file changed between runs outside any logged run"
        elif record["event"] == "finished":
            expected_rows_sha = record["rows_sha256_after"]
        previous = common.sha256_text(common.canonical_json(record))
    if expected_rows_sha != rows_sha256:
        return False, "the rows file on disk is not the file the last logged run produced"
    return True, f"{len(log)} records chained; final rows sha256 {str(rows_sha256)[:16]}... ({rows_count} rows)"


def _shape(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, dict[int, int]] = {}
    for row in rows:
        counts.setdefault(row["condition"], {}).setdefault(int(row["rep"]), 0)
        counts[row["condition"]][int(row["rep"])] += 1
    primary_complete = all(all(counts.get(key, {}).get(rep) == analyze.BLOCK_ROWS for rep in analyze.PRIMARY_REPS) for key in NEW_ATTACK_KEYS)
    return {"counts": counts, "primary_complete": primary_complete, "probe_errors": sum(1 for r in rows if r.get("probe_error"))}


def _strip(result: dict[str, Any]) -> str:
    return common.canonical_json({k: v for k, v in result.items() if k not in ("generated_at", "freeze_checked")})


# ── rendering ────────────────────────────────────────────────────────────────

STATUS_COLOUR = {PASS: "#16a34a", FAIL: "#dc2626", WARN: "#d97706", UNVERIFIED: "#6b7280"}
LIMITS = (
    "Two attacks are a demonstration, not statistics: two passes cannot support more than 'it worked on both' (a 95% Wilson interval for 2 of 2 is 34% to 100%). "
    "It is read together with the leave-one-attack-out result on the 20 known attacks, not instead of it.",
    "The new attacks run in the same five-host Mininet lab, scripted, with the true label supplied to every policy. Detection of the new attacks is not tested.",
    "The lab lets the defender reach responses a real home cannot (a rate cap on the attacker's own link, a quarantine of a device), as for the 20 known attacks.",
    "Each response was measured 3 times per attack; differences of a few tenths of a utility point between responses are within measurement noise, which is why the report also lists the responses that are practically tied with the best.",
    "Blindness of the priors rests on the authors' declaration and on the order of timestamps. The report makes later tampering detectable; it cannot prove what a person had seen.",
    "PPO could not take part: its observation cannot represent an unseen attack label.",
)


def _svg_bars(entry: dict[str, Any], policies: dict[str, Any]) -> str:
    means = sorted(entry["mean_utility"].items(), key=lambda kv: -kv[1])
    width, row, left = 640, 24, 150
    scale = (width - left - 60) / max(10.0, max(m for _, m in means))
    marks = {}
    for name, label in (("stackelberg", "S"), ("rule_based", "R")):
        marks.setdefault(policies[name]["action"], []).append(label)
    parts = [f'<svg viewBox="0 0 {width} {row * len(means) + 8}" role="img" aria-label="Measured utility of each response" xmlns="http://www.w3.org/2000/svg">']
    for i, (action, mean) in enumerate(means):
        y = 4 + i * row
        colour = "#16a34a" if action == entry["best_action"] else "#64748b"
        parts.append(f'<text x="0" y="{y + 15}" font-size="12" fill="currentColor">{html.escape(action)}</text>')
        parts.append(f'<rect x="{left}" y="{y + 3}" width="{max(1.0, mean * scale):.1f}" height="{row - 8}" rx="3" fill="{colour}"/>')
        tag = " ".join({"S": "Stackelberg", "R": "playbook"}[m] for m in marks.get(action, []))
        parts.append(f'<text x="{left + max(1.0, mean * scale) + 6:.1f}" y="{y + 15}" font-size="12" fill="currentColor">{mean:.2f}{(" ◀ " + tag) if tag else ""}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_html(facts: dict[str, Any], checks: list[dict[str, str]], result: dict[str, Any] | None, spec: dict[str, Any] | None) -> str:
    e = html.escape
    verdict = result["criteria"]["overall"] if result else "NOT MEASURED YET"
    colour = {"PASS": "#16a34a", "FAIL": "#dc2626"}.get(verdict, "#6b7280")
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in (PASS, FAIL, WARN, UNVERIFIED)}
    css = ("body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0;line-height:1.5}"
           "main{max-width:980px;margin:0 auto;padding:24px 16px 80px}h1{font-size:28px;margin:8px 0}h2{margin-top:36px;border-bottom:1px solid #334155;padding-bottom:6px}"
           "table{border-collapse:collapse;width:100%;font-size:14px;margin:12px 0}th,td{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top}"
           "th{background:#1e293b}code{background:#1e293b;padding:1px 4px;border-radius:3px;font-size:13px}.pill{display:inline-block;padding:1px 8px;border-radius:99px;color:#fff;font-size:12px;font-weight:600}"
           ".banner{border-radius:10px;padding:16px;margin:16px 0;color:#fff}.muted{color:#94a3b8}.card{background:#1e293b;border-radius:10px;padding:12px 16px;margin:12px 0}"
           ".tl{border-left:3px solid #475569;margin-left:8px;padding-left:16px}.tl div{margin:10px 0}svg{width:100%;max-width:640px;color:#e2e8f0}")
    out = [f"<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>New-attack transfer evidence</title><style>{css}</style><main>"]
    out.append("<h1>Does Stackelberg transfer to attacks nobody measured?</h1>")
    out.append("<p class='muted'>Pre-registered test on two new attacks. Generated by a script from the repository's own artefacts; "
               f"repository head <code>{e(facts['git_head'][:10])}</code>.</p>")
    out.append(f"<div class='banner' style='background:{colour}'><b>Pre-registered verdict: {e(verdict)}</b>")
    if result:
        crit = result["criteria"]
        out.append(f"<br>{crit['passed']} of {crit['of']} attacks meet the criteria fixed before measuring: Stackelberg regret ≤ {crit['stackelberg_max_regret']}"
                   + (" and not worse than the playbook" if crit["not_worse_than_playbook_required"] else "") + ".")
    out.append(f"<br>Evidence checks: {counts[PASS]} pass, {counts[FAIL]} fail, {counts[WARN]} warn, {counts[UNVERIFIED]} unverified.</div>")
    out.append("<h2>1. The question and how it was fixed in advance</h2>")
    if spec:
        out.append(f"<div class='card'>{e(str(spec.get('claim', '')).strip())}</div>")
        crit = spec.get("success_criteria", {})
        out.append(f"<p>Success criteria, committed before any measurement: Stackelberg's regret on each new attack ≤ <b>{e(str(crit.get('stackelberg_max_regret')))}</b> utility points"
                   f" and {'not worse than' if crit.get('stackelberg_not_worse_than_playbook') else 'no requirement relative to'} the rule-based playbook.</p>")
    out.append("<h2>2. Timeline</h2><div class='tl'>")
    for when, what, source in _timeline(facts):
        out.append(f"<div><b>{e(when)}</b> &nbsp;{e(what)} <span class='muted'>[{e(source)}]</span></div>")
    out.append("</div>")
    if spec:
        out.append("<h2>3. What was written before measuring</h2>")
        decl = spec.get("blind_declaration", {})
        out.append(f"<p>Priors written by <b>{e(str(decl.get('priors_author')))}</b>, playbook by <b>{e(str(decl.get('playbook_author')))}</b> on {e(str(decl.get('date_written')))}. "
                   f"Declared: saw any measurement of the new attacks = <b>{e(str(decl.get('saw_new_attack_measurements')))}</b>; saw the 693-row benchmark = <b>{e(str(decl.get('saw_outcome_table')))}</b>.</p>")
        for key in NEW_ATTACK_KEYS:
            entry = spec["attacks"][key]
            out.append(f"<div class='card'><b>{e(key)}</b><br>{e(str(entry.get('mechanism', '')).strip())}<br><br>"
                       f"Mechanism class: <code>{e(str(entry['attack_class']))}</code> — {e(str(entry.get('class_rationale', '')).strip())}<br>"
                       f"Playbook response: <code>{e(str(entry['playbook_response']))}</code> — {e(str(entry.get('playbook_rationale', '')).strip())}<br>"
                       f"Nearest known attack: <code>{e(str(entry.get('nearest_known_attack')))}</code>")
            if entry["attack_class"] == "NEW":
                nc = entry["new_class"]
                out.append("<table><tr><th>Response</th><th>Containment prior</th><th>Written reason</th></tr>")
                for action, value in nc["containment_prior"].items():
                    out.append(f"<tr><td>{e(action)}</td><td>{value}</td><td>{e(str(nc['rationale'].get(action, '')))}</td></tr>")
                out.append("</table>")
            out.append("</div>")
    if result:
        out.append("<h2>4. What was measured, and how the policies did</h2>")
        for key in NEW_ATTACK_KEYS:
            entry = result["primary"].get(key)
            if not entry or entry["status"] != "OK":
                out.append(f"<p>{e(key)}: incomplete.</p>")
                continue
            verdict_key = result["criteria"]["per_attack"][key]["verdict"]
            out.append(f"<h3>{e(key)} <span class='pill' style='background:{STATUS_COLOUR.get(verdict_key, '#6b7280')}'>{e(verdict_key)}</span></h3>")
            out.append(f"<p>Best measured response: <b>{e(entry['best_action'])}</b> ({entry['best_mean']:.2f}). Practically tied (within {result['tie_band']}): {e(', '.join(entry['tied_with_best']))}.</p>")
            out.append(_svg_bars(entry, entry["policies"]))
            out.append("<table><tr><th>Policy</th><th>Chose</th><th>Its utility</th><th>Regret</th><th>Rank of 10</th><th>Regret per block</th></tr>")
            for name in analyze.POLICIES:
                p = entry["policies"][name]
                out.append(f"<tr><td>{e(analyze.POLICY_LABELS[name])}</td><td>{e(p['action'])}</td><td>{'-' if p['mean'] is None else format(p['mean'], '.2f')}</td>"
                           f"<td>{'-' if p['regret'] is None else format(p['regret'], '.2f')}</td><td>{p['rank'] or '-'}</td><td>{e(str(p['regret_by_block']))}</td></tr>")
            out.append("</table>")
        ref = result["known_reference"]["mean_regret"]
        out.append(f"<p class='muted'>Sanity check: the same code on the 21 known situations gives mean regret {ref['stackelberg']} (Stackelberg) and {ref['rule_based']} (playbook); "
                   "EVALUATION.md reports 0.042 and 2.996.</p>")
        out.append("<h3>How wrong were the priors?</h3><table><tr><th>Attack</th><th>Mean absolute error (utility points)</th><th>Largest miss</th></tr>")
        for key, acc in result["prior_accuracy"].items():
            out.append(f"<tr><td>{e(key)}</td><td>{acc['mean_absolute_error']}</td><td>{e(acc['largest_error_action'])} ({acc['error_by_action'][acc['largest_error_action']]:+})</td></tr>")
        out.append("</table>")
        out.append(f"<p><b>PPO:</b> {e(result['ppo'])}</p>")
    out.append("<h2>5. Evidence that nothing was invented or altered</h2><table><tr><th>#</th><th>Check</th><th>Status</th><th>Detail</th></tr>")
    for c in checks:
        out.append(f"<tr><td>{c['id']}</td><td>{e(c['claim'])}</td><td><span class='pill' style='background:{STATUS_COLOUR[c['status']]}'>{c['status']}</span></td><td>{e(c['detail'])}</td></tr>")
    out.append("</table>")
    out.append("<h2>6. What this does not show</h2><ul>" + "".join(f"<li>{e(item)}</li>" for item in LIMITS) + "</ul>")
    out.append("<h2>7. Check it yourself</h2><pre><code>git clone https://github.com/abdullah-habeeb/iot-defense &amp;&amp; cd iot-defense\n"
               "python -m iot_defense.experiments.new_attacks.analyze      # recompute every number from the raw rows\n"
               "python -m iot_defense.experiments.new_attacks.evidence --server   # regenerate this page and re-run every check\n"
               "sha256sum data/experiments/new_attacks/rows.jsonl config/experiments/new_attacks/preregistration.yaml</code></pre></main></html>")
    return "".join(out)


def _timeline(facts: dict[str, Any]) -> list[tuple[str, str, str]]:
    events: list[tuple[dt.datetime, str, str, str]] = []

    def add(when: str | None, what: str, source: str) -> None:
        parsed = parse_time(when)
        if parsed:
            events.append((parsed, what, source, when or ""))

    add(facts["prereg_commit"].get("committer_time"), f"Priors and playbook committed ({facts['prereg_commit'].get('commit', '')[:8]})", "git")
    add(facts["freeze_commit"].get("committer_time"), f"Freeze manifest committed ({facts['freeze_commit'].get('commit', '')[:8]})", "git")
    github = facts.get("github") or {}
    add(github.get("push_times", {}).get("freeze"), "GitHub received the push containing the freeze", "GitHub server")
    add(github.get("comment_times", {}).get("freeze"), "Freeze hash posted as a PR comment", "GitHub server")
    for record in facts["run_log"]:
        if record["event"] == "started":
            add(record["started_at"], f"Measurement run started (rows before: {record['rows_lines_before']})", "run log")
        else:
            add(record["finished_at"], f"Measurement run finished (+{record['new_rows']} rows)", "run log")
    times = sorted(t for t in (parse_time(r.get("measured_at")) for r in facts["rows"]) if t)
    if times:
        add(times[0].strftime("%Y-%m-%dT%H:%M:%S%z"), "First measured row", "rows file")
        add(times[-1].strftime("%Y-%m-%dT%H:%M:%S%z"), "Last measured row", "rows file")
    add(facts["rows_commit"].get("committer_time"), f"Raw rows committed ({(facts['rows_commit'].get('commit') or '')[:8]})", "git")
    add(github.get("push_times", {}).get("rows"), "GitHub received the push containing the rows", "GitHub server")
    events.sort(key=lambda item: item[0])
    return [(raw, what, source) for _, what, source, raw in events]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", action="store_true", help="also query GitHub for push and comment timestamps (needs the gh CLI)")
    parser.add_argument("--pr", type=int, default=1)
    parser.add_argument("--repo", default="abdullah-habeeb/iot-defense")
    parser.add_argument("--out", default=str(common.DATA_DIR))
    args = parser.parse_args()
    facts = gather(server=args.server, pr=args.pr, owner_repo=args.repo)
    spec = prereg.load() if common.PREREG_PATH.exists() else None
    recomputed = None
    if spec and facts["rows"] and not facts["drift"]:
        try:
            recomputed = analyze.analyze(common.ROWS_PATH)
        except ValueError:
            recomputed = None
    checks = run_checks(facts, spec=spec, recomputed=recomputed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    page = render_html(facts, checks, recomputed or facts["results_stored"], spec)
    (out / "evidence_report.html").write_text(page, encoding="utf-8")
    (out / "evidence_checks.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
    for c in checks:
        print(f"{c['id']:4s} {c['status']:10s} {c['claim']}")
    print(f"\nwrote {out / 'evidence_report.html'}")


if __name__ == "__main__":
    main()
