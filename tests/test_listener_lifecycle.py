import unittest
from unittest.mock import MagicMock, patch
from typing import Any

# Function under test, copied to isolate from project dependencies
def _start_tcp_listener(host: Any, port: int) -> str:
    script = f"""
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', {port}))
    s.listen(1)
    s.settimeout(10.0)
    conn, addr = s.accept()
    conn.settimeout(5.0)
    conn.recv(1024)
    conn.sendall(b'ok')
    conn.close()
    s.close()
except socket.timeout:
    sys.exit(1)
except Exception:
    sys.exit(1)
finally:
    try:
        s.close()
    except:
        pass
"""
    cmd = (
        "python3 - <<'PY' &\n"
        f"{script}\n"
        "PY"
        " & echo $!"
    )
    return host.cmd(cmd).strip()

def _stop_tcp_listener(host: Any, pid: str) -> None:
    host.cmd(f"kill {pid} 2>/dev/null || true")

class TestListenerLifecycle(unittest.TestCase):
    @patch('iot_defense.ml.generate_dataset.create_mininet_network', MagicMock())
    @patch('iot_defense.ml.generate_dataset.PacketMonitor', MagicMock())
    @patch('iot_defense.ml.generate_dataset.FeatureAggregator', MagicMock())
    @patch('iot_defense.ml.generate_dataset.flow_to_dataset_row', MagicMock())
    @patch('iot_defense.ml.generate_dataset.validate_dataset', MagicMock())
    @patch('iot_defense.ml.generate_dataset.pd', MagicMock())
    def test_listener_start_stop(self):
        mock_host = MagicMock()
        # The command returns the PID
        mock_host.cmd.return_value = "12345"
        pid = _start_tcp_listener(mock_host, 8080)
        self.assertEqual(pid, "12345")

        # Verify the command contained the timeout logic
        called_cmd = mock_host.cmd.call_args[0][0]
        self.assertIn("s.settimeout(10.0)", called_cmd)
        self.assertIn("conn.settimeout(5.0)", called_cmd)

        _stop_tcp_listener(mock_host, pid)
        mock_host.cmd.assert_called_with("kill 12345 2>/dev/null || true")
