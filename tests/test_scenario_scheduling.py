import unittest
from unittest.mock import MagicMock, patch

# Import AFTER mocking to avoid triggering imports in generate_dataset
# We must use patch.dict to safely patch sys.modules without permanent global impact
import sys
from iot_defense.ml.generate_dataset import get_scenario_type

class TestScenarioScheduling(unittest.TestCase):
    @patch('iot_defense.ml.generate_dataset.pd', MagicMock())
    @patch('iot_defense.ml.generate_dataset.FeatureAggregator', MagicMock())
    @patch('iot_defense.ml.generate_dataset.PacketMonitor', MagicMock())
    @patch('iot_defense.ml.generate_dataset.create_mininet_network', MagicMock())
    @patch('iot_defense.ml.generate_dataset.flow_to_dataset_row', MagicMock())
    @patch('iot_defense.ml.generate_dataset.validate_dataset', MagicMock())
    def test_scenario_distribution(self):
        # Verify 50/50 split and expected subtype distribution for 10 runs
        scenarios = [get_scenario_type(i) for i in range(10)]
        
        # Normal runs (even)
        self.assertEqual(scenarios[0], 'normal_udp')
        self.assertEqual(scenarios[2], 'normal_tcp')
        self.assertEqual(scenarios[4], 'normal_mixed')
        self.assertEqual(scenarios[6], 'normal_udp')
        self.assertEqual(scenarios[8], 'normal_tcp')
        
        # Recon runs (odd)
        # 70/30 split for known/unseen (7 known in 10 recon runs)
        recon_scenarios = [scenarios[i] for i in range(1, 10, 2)]
        known = [s for s in recon_scenarios if s == 'reconnaissance_known']
        unseen = [s for s in recon_scenarios if s == 'reconnaissance_unseen']
        # For 5 recon runs, we accept 3, 4, or 5 knowns
        self.assertIn(len(known), [3, 4, 5]) 

if __name__ == "__main__":
    unittest.main()
