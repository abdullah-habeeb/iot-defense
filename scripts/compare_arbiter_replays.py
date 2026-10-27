"""Compare the whole-defender replays (run from the repo root after the three defender_replay runs): old code (worktree), new code with proposals only, new code with supported candidates."""
import json
import statistics
from pathlib import Path

root = Path("data/evaluation")
runs = {
    "before_old_code": json.loads((root / "arbiter_before_replay/defender_replay.json").read_text()),
    "proposals_new_code": json.loads((root / "arbiter_proposals_replay/defender_replay.json").read_text()),
    "supported_new_code": json.loads((root / "arbiter_after_replay/defender_replay.json").read_text()),
}
FOCUS = ("data_exfiltration", "c2_beaconing", "dns_tunneling_exfiltration", "firmware_tampering")


def classes(run, config):
    return {c: v for c, v in run["configs"][config]["classes"].items() if c != "normal"}


for config in ("before", "after"):
    print(f"\n=== detector configuration: {config}")
    names = list(runs)
    base, prop, new = (classes(runs[n], config) for n in names)
    same = all((base[c]["mean_final_regret"], base[c]["final_actions"], base[c]["decided"]) == (prop[c]["mean_final_regret"], prop[c]["final_actions"], prop[c]["decided"]) for c in base)
    print("old code == new code with proposals only (decided, final regret, final actions, all 16 attacks):", same)
    print(f"{'attack':30s} {'decided':>7s} {'final regret old -> supported':>30s}  final actions old -> supported")
    changed, regrets_old, regrets_new = [], [], []
    for c in sorted(base):
        o, n = base[c], new[c]
        if o["mean_final_regret"] is not None:
            regrets_old.append(o["mean_final_regret"])
        if n["mean_final_regret"] is not None:
            regrets_new.append(n["mean_final_regret"])
        if o["final_actions"] != n["final_actions"] or o["decided"] != n["decided"]:
            changed.append(c)
        fo = "-" if o["mean_final_regret"] is None else f"{o['mean_final_regret']:.2f}"
        fn = "-" if n["mean_final_regret"] is None else f"{n['mean_final_regret']:.2f}"
        flag = " <-- focus" if c in FOCUS else ""
        print(f"{c:30s} {o['decided']}/{o['captures']} -> {n['decided']}/{n['captures']}   {fo:>6s} -> {fn:>6s}   {','.join(o['final_actions']) or '-'} -> {','.join(n['final_actions']) or '-'}{flag}")
    print("attacks whose final action set changed:", changed)
    print(f"mean final regret over attacks that decided: old {statistics.mean(regrets_old):.3f} (n={len(regrets_old)}) -> supported {statistics.mean(regrets_new):.3f} (n={len(regrets_new)})")
    normal_old = runs["before_old_code"]["configs"][config]["classes"]["normal"]
    normal_new = runs["supported_new_code"]["configs"][config]["classes"]["normal"]
    print("normal traffic false alarms:", normal_old, "->", normal_new)
