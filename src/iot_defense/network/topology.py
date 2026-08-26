"""Reusable Mininet topology definition for the IoT lab."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

try:
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch
    from mininet.topo import Topo

    MININET_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - exercised only when Mininet is unavailable
    Mininet = None  # type: ignore[assignment]
    OVSKernelSwitch = None  # type: ignore[assignment]
    Topo = object  # type: ignore[misc,assignment]
    MININET_AVAILABLE = False


class TopologyConfig:
    """Load and expose topology parameters from the YAML config file."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        base = Path(__file__).resolve().parents[3]
        self.config_path = Path(config_path) if config_path else base / "config" / "topology.yaml"
        self._data = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        with self.config_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    @property
    def name(self) -> str:
        return self._data.get("topology", {}).get("name", "iot-home-lab")

    @property
    def hosts(self) -> list[dict[str, Any]]:
        return self._data.get("topology", {}).get("hosts", [])

    @property
    def switch(self) -> dict[str, Any]:
        return self._data.get("topology", {}).get("switch", {})

    @property
    def links(self) -> list[str]:
        return self._data.get("topology", {}).get("links", [])

    @property
    def traffic(self) -> dict[str, Any]:
        return self._data.get("topology", {}).get("traffic", {})


class IoTTopology(Topo):
    """Create a small residential IoT lab topology backed by OVSKernelSwitch."""

    def __init__(self, config: TopologyConfig | None = None, **opts: Any) -> None:
        if not MININET_AVAILABLE:
            raise RuntimeError("Mininet is not available in the active Python environment.")
        super().__init__(**opts)
        self.config = config or TopologyConfig()
        self._build_topology()

    def _build_topology(self) -> None:
        switch_name = self.config.switch.get("name", "s1")
        self.addSwitch(switch_name, cls=OVSKernelSwitch, failMode="standalone")

        for host in self.config.hosts:
            name = host.get("name")
            ip = host.get("ip")
            if not name:
                continue
            self.addHost(name, ip=ip, defaultRoute=None)
            self.addLink(name, switch_name)


def create_mininet_network(config_path: str | Path | None = None) -> Mininet:
    """Build and return a Mininet network instance using the project topology config."""
    if not MININET_AVAILABLE:
        raise RuntimeError("Mininet is required to create the simulated network.")
    config = TopologyConfig(config_path)
    topo = IoTTopology(config=config)
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller=None, autoSetMacs=True, autoStaticArp=True)
    return net
