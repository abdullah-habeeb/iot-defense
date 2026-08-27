import unittest
import json
import os
from unittest.mock import MagicMock
from iot_defense.demo.controller import DemoController

class TestDemoController(unittest.TestCase):
    def setUp(self):
        self.controller = DemoController()
        # Mocking file paths
        self.controller.data_dir = "/tmp/iot-defense-demo"
        os.makedirs(self.controller.data_dir, exist_ok=True)
        self.controller.state_file = f"{self.controller.data_dir}/state.json"

    def test_state_serialization(self):
        # Initial state
        self.assertEqual(self.controller.state["phase"], "IDLE")
        
        # Update state
        new_data = {"phase": "BASELINE"}
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.controller.update_state(new_data))
        
        # Check file persistence
        with open(self.controller.state_file, "r") as f:
            persisted_state = json.load(f)
            self.assertEqual(persisted_state["phase"], "BASELINE")
            self.assertIn("timestamp", persisted_state)

if __name__ == "__main__":
    unittest.main()
