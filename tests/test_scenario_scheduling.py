import unittest
from unittest.mock import MagicMock, patch

# Import AFTER mocking to avoid triggering imports in generate_dataset
# We must use patch.dict to safely patch sys.modules without permanent global impact
import sys
from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.ml.generate_dataset import _DATASET_GENERATION_UNSUPPORTED, get_scenario_type

# Bucket 0 is always normal; every other bucket is one registered attack, in
# registry order -- this grows automatically as ATTACK_SCENARIOS grows, so
# these tests don't hardcode a specific attack count. What each bucket's
# own sub-scenario values look like is still attack-specific (matching
# generate_dataset.py's own documented convention), so ATTACK_ASSERTIONS
# below needs one entry added per newly registered attack.
NUM_BUCKETS = 1 + len(ATTACK_SCENARIOS)
ATTACK_KEYS = list(ATTACK_SCENARIOS.keys())

def _assert_reconnaissance_bucket(case: unittest.TestCase, values: list[str]) -> None:
    for value in values:
        case.assertIn(value, ("reconnaissance_known", "reconnaissance_unseen"))


def _assert_fixed_value_bucket(expected: str):
    def _assert(case: unittest.TestCase, values: list[str]) -> None:
        for value in values:
            case.assertEqual(value, expected)

    return _assert


ATTACK_ASSERTIONS = {
    "reconnaissance": _assert_reconnaissance_bucket,
    "dos": _assert_fixed_value_bucket("dos_flood"),
    "brute_force": _assert_fixed_value_bucket("brute_force"),
    "exfiltration": _assert_fixed_value_bucket("exfiltration"),
    "exploit": _assert_fixed_value_bucket("exploit_payload_injection"),
    # These ten were registered for the live detection/decision/response
    # pipeline without extending generate_dataset.py's own bespoke
    # per-attack dispatch (see get_scenario_type()'s docstring for why:
    # deliberately deferred, since none of them are ever consulted by the
    # RF model this dataset trains). Every one of their buckets must
    # consistently return the unsupported sentinel, not silently fall
    # through to some other scenario's dispatch branch.
    "syn_flood": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "icmp_flood": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "slow_loris": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "dns_amplification": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "dns_tunneling": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "mqtt_flood": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "firmware_tampering": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "buffer_overflow": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "replay_attack": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
    "rogue_beacon": _assert_fixed_value_bucket(_DATASET_GENERATION_UNSUPPORTED),
}

# Keys whose dataset-generation dispatch is deliberately not yet
# implemented (see ATTACK_ASSERTIONS above) -- their scenario values are
# the unsupported sentinel, not a name derived from the attack key, so
# test_all_registered_scenarios_appear_over_a_larger_sample's "does this
# key's own name appear in the scenario set" check doesn't apply to them.
_DATASET_GENERATION_DEFERRED_KEYS = {
    "syn_flood", "icmp_flood", "slow_loris", "dns_amplification",
    "dns_tunneling", "mqtt_flood", "firmware_tampering", "buffer_overflow",
    "replay_attack", "rogue_beacon",
}


class TestScenarioScheduling(unittest.TestCase):
    @patch('iot_defense.ml.generate_dataset.pd', MagicMock())
    @patch('iot_defense.ml.generate_dataset.FeatureAggregator', MagicMock())
    @patch('iot_defense.ml.generate_dataset.PacketMonitor', MagicMock())
    @patch('iot_defense.ml.generate_dataset.create_mininet_network', MagicMock())
    @patch('iot_defense.ml.generate_dataset.flow_to_dataset_row', MagicMock())
    @patch('iot_defense.ml.generate_dataset.validate_dataset', MagicMock())
    def test_scenario_distribution(self):
        # Five runs per bucket, generically over however many buckets are
        # currently registered.
        runs = NUM_BUCKETS * 5
        scenarios = [get_scenario_type(i) for i in range(runs)]

        # Bucket 0 (normal) cycles udp/tcp/mixed in order.
        normal_scenarios = [scenarios[i] for i in range(0, runs, NUM_BUCKETS)]
        expected_cycle = ["normal_udp", "normal_tcp", "normal_mixed"]
        for index, value in enumerate(normal_scenarios):
            self.assertEqual(value, expected_cycle[index % 3])

        # Every other bucket is one registered attack, in registry order.
        for offset, key in enumerate(ATTACK_KEYS, start=1):
            bucket_values = [scenarios[i] for i in range(offset, runs, NUM_BUCKETS)]
            assertion = ATTACK_ASSERTIONS.get(key)
            self.assertIsNotNone(
                assertion,
                f"No ATTACK_ASSERTIONS entry for newly registered attack key {key!r} -- add one.",
            )
            assertion(self, bucket_values)

    @patch('iot_defense.ml.generate_dataset.pd', MagicMock())
    @patch('iot_defense.ml.generate_dataset.FeatureAggregator', MagicMock())
    @patch('iot_defense.ml.generate_dataset.PacketMonitor', MagicMock())
    @patch('iot_defense.ml.generate_dataset.create_mininet_network', MagicMock())
    @patch('iot_defense.ml.generate_dataset.flow_to_dataset_row', MagicMock())
    @patch('iot_defense.ml.generate_dataset.validate_dataset', MagicMock())
    def test_all_registered_scenarios_appear_over_a_larger_sample(self):
        scenarios = {get_scenario_type(i) for i in range(NUM_BUCKETS * 20)}
        top_level = {s.split('_')[0] for s in scenarios}
        self.assertIn('normal', top_level)
        for key in ATTACK_KEYS:
            if key in _DATASET_GENERATION_DEFERRED_KEYS:
                self.assertIn(_DATASET_GENERATION_UNSUPPORTED, scenarios)
                continue
            # Every registered attack's own top-level prefix (its key, or
            # for multi-word keys the first underscore-separated segment)
            # must appear somewhere in the generated scenario set.
            self.assertIn(key.split('_')[0], top_level)


if __name__ == "__main__":
    unittest.main()
