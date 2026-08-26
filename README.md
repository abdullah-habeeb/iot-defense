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
This repository is in the foundation stage. The initial implementation focuses on a minimal, testable prototype that is extensible for future ML, Stackelberg, and RL components without overbuilding the system upfront.

## Planned future components
- Random Forest / SVM detection models
- Stackelberg strategy layer
- PPO reinforcement learning integration
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
