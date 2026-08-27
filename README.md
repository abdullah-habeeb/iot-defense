# IoT Defense

## Purpose
This project implements a modular, agent-based cyber-defense framework for residential IoT networks. The initial foundation is intentionally scoped to a working vertical slice that demonstrates the end-to-end flow:

Mininet IoT Network -> Monitoring Agent -> Feature Extraction -> Detection Agent -> Decision Agent -> Response / Deception -> Observability / Metrics.

## Current architecture
- Mininet network simulation
- Monitoring agent for packet observations
- Feature extraction pipeline
- Rule-based detection layer
- Decision agent for response selection
- Response/deception handlers
- Logging and metrics collection

## Environment
- Ubuntu 24.04.4 LTS
- Python 3.12.3
- Mininet 2.3.0
- Open vSwitch 3.3.9

## Current implementation status
The prototype now includes a validated Mininet traffic-to-response vertical slice, configurable Stackelberg policy reasoning, and a small CPU-only PPO policy trained on a standalone decision simulator. PPO does not train against Mininet traffic and does not execute responses; the live runner compares RuleBased, Stackelberg, and PPO decisions while retaining the existing response path.

The PPO environment uses a deterministic normalized security-context observation and a four-action mapping: `ALLOW=0`, `ALERT=1`, `ISOLATE=2`, and `DECOY=3`. Reward coefficients are modelling assumptions, not objective security values. Train a short model with:

```bash
python -m iot_defense.simulation.train_ppo --timesteps 512 --output models/ppo_defense
```

The generated model is ignored by Git. `PPODefensePolicy` fails clearly when it is absent unless an explicit fallback policy is provided. The trained policy should not be interpreted as learning real-world attacker behaviour or general autonomous cyber defense.

## Planned future components
- Random Forest / SVM detection models
- Broader learned detection and evaluation datasets
- PPO policy evaluation against measured scenarios
- Richer honeypot and deception flows
- Enhanced evaluation metrics and dashboards

## Virtual environment
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
```

## Run tests
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
pytest -q
```
