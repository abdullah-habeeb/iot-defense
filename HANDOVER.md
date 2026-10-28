# Handover: read this first (written 2026-10-28)

Everything needed to continue this project with a different person or a different AI assistant. If you are an AI assistant: read this
file, then `README.md`, then `EVALUATION.md` ("Measured-outcome results" and the sections after it). Do not rely on anything not in the repo.

## 1. What the project is
A residential-IoT cyber-defense research prototype (a college major project, BMSIT&M). A virtual home network (Mininet, 5 hosts) is attacked
with 20 kinds of attack; ten defensive responses were each applied to each attack and **measured** (the 693-row "record book",
`data/outcomes/outcome_table.jsonl`). Three response-selection policies are graded against it: a rule-based playbook, a Stackelberg
(leader-follower) game model built from written mechanism priors, and PPO. An evidence-based arbiter and a live defender (real `iptables`
rules) sit on top.

## 2. What the evidence says, and what must NOT be claimed
- Playbook: mean regret 2.996, best response in 4 of 21 situations. Stackelberg (priors only, no measurements): regret 0.042, best in 20 of 21. The same priors without the attacker's reaction: 0.549.
- Trained on measurements, PPO and Stackelberg **tie** in live paired trials (p = 0.69). **Never claim "Stackelberg is the best strategy".** PPO trained on the table it is graded on is circular (labelled PPO-R).
- Arbiter now scores every response the device can perform (fresh live trials: +0.443 utility per trial, 95% CI [+0.326, +0.565]).
- Detector: names all 16 single-source lab attacks (development-set result), but does **not** transfer: about 17 to 21 firewall actions per hour on a benign IoT-23 Amazon Echo; command-and-control never named a beacon.
- Pre-registered new-attack test (2026-10-27): two unseen attacks, priors written blind and frozen before measuring. **PASS on both, 13/13 evidence checks.** But the blind playbook tied (Stackelberg did not beat a good playbook), the attacker-reaction structure was not tested, the priors' numbers were often wrong, and n = 2. Details and limits: `EVALUATION.md` ("Transfer to two attacks nobody had measured").
- Always state limits: 3 repetitions per cell, one virtual lab, scripted attackers, priors written by authors who knew the lab, nothing measured on physical IoT hardware. Report in-sample and circular results as such. Never invent numbers.

## 3. State of the repository
- Repo `abdullah-habeeb/iot-defense`, branch **`outcome-based-policy-eval`**, PR #1 (base `main`) is **open and not merged**; merging is the owner's decision. Tag `demo-ready-final-2026-10-28` marks the final demo-ready state (all 1022 tests pass on a fresh clone).
- Public IoT-23 captures (581 MB, CC BY 4.0) are assets of the GitHub release `data-iot23-v1`; `scripts/fetch_iot23.sh` downloads and verifies them.
- Test suite: **1022 tests**, need no Mininet and no root: `pytest -q` (6 to 8 minutes on 2 vCPUs; do not run two copies at once on a 3 GB machine, it froze the VM once).

## 4. Setting up from a fresh clone
```bash
git clone https://github.com/abdullah-habeeb/iot-defense && cd iot-defense
git checkout outcome-based-policy-eval
python3.12 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python3 -m pytest -q          # 1022 passed
```
Code, tests, the measured tables, all small result files, the trained models (`models/`), the ML datasets and the lab pcaps are in git.
Anything that creates a Mininet network (lab measurement, the dashboard's "Run attack") needs Linux with Mininet 2.3.0, Open vSwitch and
root: the original machine is an Ubuntu 24.04 VirtualBox VM (Python 3.12.3). Nothing about the VM is in git except what is documented here
and in `docs/LIVE_DEMO.md`. The dashboard's run button also needs a machine-local sudoers rule (`NOPASSWD` for `.venv/bin/python3`); on
another machine run the controller from a terminal instead: `sudo .venv/bin/python3 -m iot_defense.demo.controller --attack <key>`.

## 5. The demos
- **Live physical demo** (laptop VM defender + a second laptop running nmap): exact commands in `docs/handover/Live_Reconnaissance_Attack.txt`; background in `docs/LIVE_DEMO.md`. Needs both laptops on the same Wi-Fi (not college Wi-Fi; a phone hotspot works).
- **Simulation dashboard**: `PYTHONPATH=src uvicorn iot_defense.dashboard.server:app --host 127.0.0.1 --port 8000`, then `http://localhost:8000/` (Mininet tab) and `/live` (physical demo tab).
- **New-attack evidence report**: `docs/handover/new_attack_reports/evidence_report_REAL.html` (a watermarked SYNTHETIC sample is NOT included, to avoid confusion). Regenerate: `.venv/bin/python3 -m iot_defense.experiments.new_attacks.evidence --server`.

## 6. Rules for whoever continues
- **Do not edit the frozen files** listed in `src/iot_defense/experiments/new_attacks/common.py` (`FROZEN_FILES`, including `config/policies.yaml`). Evidence check E1 and `measure`/`analyze` will fail; a change is a new experiment with a new freeze.
- Commits: **never add a `Co-Authored-By` or any AI attribution line** (the owner had them stripped before). Use `git add -- <paths>` and check `git diff --cached --name-only` before each commit.
- Git-ignored files (`*.jsonl`, `data/evaluation/`, `models/`) need `git add -f`; keep each file under 1 MB unless the owner approves.
- Do not write TeX or Python containing backslashes through shell heredocs in some agent tools (they get mangled); write files with a file tool and run them.
- `gh pr edit` fails on this repo (classic-projects GraphQL bug); use `gh api -X PATCH repos/abdullah-habeeb/iot-defense/pulls/1 -F body=@file.md`.
- Sudo on the VM is the owner's: ask them to start any Mininet run. Confirm before anything public or hard to reverse.

## 7. What is not finished (see `docs/handover/IoT_Defense_TODO.md`)
1. `docs/handover/paper_draft/paper.tex` (6-page IEEE draft, compiled once; builds with Tectonic, needs `\usepackage[T1]{fontenc}`) predates the arbiter fix and the new-attack result; update, recompile, fill the red placeholders (co-authors, guide, repository URL), verify every reference against its publisher page. References were written from memory.
2. Optional: 3 confirmatory blocks for the new attacks (`measure --reps 6 --phase confirmatory`, about 13 minutes, sudo), real-hardware slice, per-device detector baselines, distributed-attack captures.
3. The 75-page report, review deck and SDG sheet name team members and are **not in this public repo** (personal details); the owner holds them privately.

## 8. Starter prompt for a new AI session
> I am continuing a research project. The repo is https://github.com/abdullah-habeeb/iot-defense (branch `outcome-based-policy-eval`). Read `HANDOVER.md`,
> then `README.md` and `EVALUATION.md`. Rules: report only measured numbers, label in-sample or circular results, never claim "Stackelberg is best",
> never edit the frozen files, never add AI attribution to commits, and ask before any public or irreversible action. My task now is: <describe it>.
