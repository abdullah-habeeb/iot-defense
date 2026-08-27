import asyncio
import json
import os
import time
import argparse
from typing import Any, Dict

from iot_defense.simulation.traffic import TrafficGenerator
from iot_defense.network.topology import create_mininet_network
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.executor import MininetResponseExecutor as ResponseExecutor
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.defense.context import build_security_context
from iot_defense.detection.rule_based import RuleBasedDetector
from iot_defense.ml.random_forest import RandomForestDetector

class DemoController:
    def __init__(self):
        self.state = {
            "phase": "IDLE",
            "nodes": {},
            "threat_status": "NORMAL",
            "timeline": []
        }
        self.event_queue = asyncio.Queue()
        self.data_dir = "/home/abdullah/iot-defense/data/dashboard"
        os.makedirs(self.data_dir, exist_ok=True)
        self.state_file = f"{self.data_dir}/state.json"
        self.net = None
        self.executor = None

    async def update_state(self, new_data: dict):
        self.state.update(new_data)
        self.state["timestamp"] = time.time()
        self.state["timeline"].append({"phase": self.state["phase"], "timestamp": self.state["timestamp"]})
        with open(self.state_file, "w") as f:
            json.dump(self.state, f)
        await self.event_queue.put(self.state)
        print(f"Phase changed to: {self.state['phase']}")

    def cleanup(self):
        if self.net:
            self.net.stop()
        if self.executor:
            self.executor.cleanup()

    async def _evaluate_and_respond(self, threat_event: ThreatEvent):
        await self.update_state({"phase": "DECIDING", "threat_event": threat_event.to_dict()})
        
        # Security Context
        context = build_security_context(threat_event)
        
        # Policy Evaluation
        rule_based_policy = RuleBasedDetector() # Assuming this is a policy/detector interface
        # ... (evaluate rule_based, stackelberg, ppo)
        
        # Action Decision
        decision = DefenseDecision(action=DefenseAction.ALERT, target_ip=threat_event.destination_ip)
        
        await self.update_state({"phase": "RESPONDING"})
        result = self.executor.execute(decision)
        
        await self.update_state({"phase": "OBSERVING", "response_result": result.to_dict()})

    async def run_demo(self):
        try:
            await self.update_state({"phase": "STARTING_NETWORK"})
            self.net = create_mininet_network()
            self.net.start()
            self.executor = ResponseExecutor(self.net)
            traffic_gen = TrafficGenerator()
            monitor = PacketMonitor()

            # SCENARIO A: NORMAL
            await self.update_state({"phase": "BASELINE"})
            traffic_gen.generate_normal_mininet_traffic(self.net)
            
            # SCENARIO B: ATTACK
            await self.update_state({"phase": "THREAT_DETECTED"})
            attack_output = traffic_gen.generate_malicious_mininet_traffic(self.net)
            
            # Simple placeholder for threat detection
            threat_event = ThreatEvent(attack_type="reconnaissance_port_scan", destination_ip="10.0.0.10")
            await self._evaluate_and_respond(threat_event)
            
            # SCENARIO C: RESTORE
            await self.update_state({"phase": "RESTORING"})
            # Perform restoration (reusing executor.restore)
            # await self.executor.restore("10.0.0.10")
            await self.update_state({"phase": "RESTORED"})
            
            await self.update_state({"phase": "COMPLETE"})
        except Exception as e:
            await self.update_state({"phase": "ERROR", "error": str(e)})
        finally:
            await self.update_state({"phase": "CLEANUP"})
            self.cleanup()

def main():
    controller = DemoController()
    asyncio.run(controller.run_demo())

if __name__ == "__main__":
    main()
