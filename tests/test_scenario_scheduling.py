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
        # Verify the 3-way normal/reconnaissance/dos_flood split and expected
        # subtype distribution for 15 runs (5 of each top-level scenario).
        scenarios = [get_scenario_type(i) for i in range(15)]

        # Normal runs (run_number % 3 == 0) cycle udp/tcp/mixed
        self.assertEqual(scenarios[0], 'normal_udp')
        self.assertEqual(scenarios[3], 'normal_tcp')
        self.assertEqual(scenarios[6], 'normal_mixed')
        self.assertEqual(scenarios[9], 'normal_udp')
        self.assertEqual(scenarios[12], 'normal_tcp')

        # DoS flood runs (run_number % 3 == 2)
        for i in range(2, 15, 3):
            self.assertEqual(scenarios[i], 'dos_flood')

        # Recon runs (run_number % 3 == 1) -- 70/30 split for known/unseen
        recon_scenarios = [scenarios[i] for i in range(1, 15, 3)]
        for s in recon_scenarios:
            self.assertIn(s, ('reconnaissance_known', 'reconnaissance_unseen'))
        known = [s for s in recon_scenarios if s == 'reconnaissance_known']
        # For 5 recon runs, we accept 3, 4, or 5 knowns
        self.assertIn(len(known), [3, 4, 5])

    @patch('iot_defense.ml.generate_dataset.pd', MagicMock())
    @patch('iot_defense.ml.generate_dataset.FeatureAggregator', MagicMock())
    @patch('iot_defense.ml.generate_dataset.PacketMonitor', MagicMock())
    @patch('iot_defense.ml.generate_dataset.create_mininet_network', MagicMock())
    @patch('iot_defense.ml.generate_dataset.flow_to_dataset_row', MagicMock())
    @patch('iot_defense.ml.generate_dataset.validate_dataset', MagicMock())
    def test_all_three_top_level_scenarios_appear_over_a_larger_sample(self):
        scenarios = {get_scenario_type(i) for i in range(60)}
        top_level = {s.split('_')[0] for s in scenarios}
        self.assertIn('normal', top_level)
        self.assertIn('reconnaissance', {s.split('_')[0] for s in scenarios if s.startswith('reconnaissance')})
        self.assertIn('dos', top_level)

if __name__ == "__main__":
    unittest.main()
