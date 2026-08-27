from pathlib import Path

import yaml

from iot_defense.network.topology import TopologyConfig


def test_topology_config_loads_expected_hosts():
    config = TopologyConfig(Path("config/topology.yaml"))
    hosts = config.hosts

    assert [host["name"] for host in hosts] == ["sensor", "camera", "smart_plug", "attacker", "decoy"]
    assert [host["ip"] for host in hosts] == [
        "10.0.0.10/24",
        "10.0.0.20/24",
        "10.0.0.30/24",
        "10.0.0.100/24",
        "10.0.0.200/24",
    ]


def test_topology_config_yaml_is_valid():
    with Path("config/topology.yaml").open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    assert data["topology"]["switch"]["name"] == "s1"
    assert len(data["topology"]["hosts"]) == 5
