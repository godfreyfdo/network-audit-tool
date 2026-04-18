import sys, os, unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scanner.nmap_scanner import NmapScanner

FAKE_HOSTS = {
    "192.168.1.1": {
        "state": "up",
        "hostnames": [{"name": "router.local"}],
        "osmatch": [{"name": "Linux 3.x", "accuracy": "91"}],
        "protos": {
            "tcp": {
                80:  {"state": "open", "name": "http",   "version": "nginx 1.18"},
                23:  {"state": "open", "name": "telnet", "version": ""},
                22:  {"state": "open", "name": "ssh",    "version": "OpenSSH 8.2"},
            }
        }
    },
    "192.168.1.10": {
        "state": "up",
        "hostnames": [{"name": ""}],
        "osmatch": [],
        "protos": {
            "tcp": {
                445:  {"state": "open", "name": "microsoft-ds",  "version": ""},
                3389: {"state": "open", "name": "ms-wbt-server", "version": ""},
            }
        }
    },
}

class FakeHostProxy:
    def __init__(self, data):
        self._data   = data
        self._protos = data.get("protos", {})
    def state(self):           return self._data.get("state", "up")
    def hostnames(self):       return self._data.get("hostnames", [{"name": ""}])
    def all_protocols(self):   return list(self._protos.keys())
    def __getitem__(self, k):
        return self._protos[k] if k in self._protos else self._data.get(k, {})
    def __contains__(self, k): return k in self._data or k in self._protos


def _make_nm(hosts_data):
    snapshot = dict(hosts_data)
    nm = MagicMock()
    nm.all_hosts.return_value            = list(snapshot.keys())
    nm.get_nmap_last_output.return_value = "<nmaprun/>"
    nm.scan.return_value                 = None
    nm.__getitem__.side_effect           = lambda ip: FakeHostProxy(snapshot[ip])
    return nm


def _make_scanner(hosts_data=None):
    if hosts_data is None:
        hosts_data = FAKE_HOSTS
    s = NmapScanner.__new__(NmapScanner)
    s.target    = "192.168.1.0/24"
    s.arguments = "-sV -sC -O --open -T4"
    s.hosts     = []
    s.scan_time = "2025-04-12 10:00:00"
    s.nm        = _make_nm(hosts_data)
    return s


class TestNmapScanner(unittest.TestCase):

    def test_scan_returns_two_hosts(self):
        hosts = _make_scanner().parse()
        self.assertEqual(len(hosts), 2)

    def test_risky_ports_flagged(self):
        hosts = _make_scanner().parse()
        router = next(h for h in hosts if h["ip"] == "192.168.1.1")
        nums   = [p["port"] for p in router["open_ports"] if p["is_risky"]]
        self.assertIn(23, nums)
        self.assertIn(80, nums)

    def test_ssh_not_risky(self):
        hosts = _make_scanner().parse()
        router = next(h for h in hosts if h["ip"] == "192.168.1.1")
        nums   = [p["port"] for p in router["open_ports"] if p["is_risky"]]
        self.assertNotIn(22, nums)

    def test_no_hostname_detected(self):
        hosts = _make_scanner().parse()
        no_hn = [h for h in hosts if h["hostname"] == ""]
        self.assertEqual(len(no_hn), 1)
        self.assertEqual(no_hn[0]["ip"], "192.168.1.10")

    def test_hosts_sorted_by_risky_count_desc(self):
        hosts  = _make_scanner().parse()
        counts = [h["risky_port_count"] for h in hosts]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_host_dict_keys(self):
        hosts    = _make_scanner().parse()
        required = {"ip","hostname","state","os","os_accuracy",
                    "open_ports","risky_port_count","scanned_at"}
        for h in hosts:
            self.assertTrue(required.issubset(h.keys()))

    def test_port_dict_keys(self):
        hosts    = _make_scanner().parse()
        router   = next(h for h in hosts if h["ip"] == "192.168.1.1")
        required = {"port","protocol","service","version","state","is_risky","risk_info"}
        for p in router["open_ports"]:
            self.assertTrue(required.issubset(p.keys()))

    def test_summary_host_count(self):
        s = _make_scanner()
        s.hosts = s.parse()
        self.assertEqual(s.get_summary()["total_hosts"], 2)

    def test_summary_risky_count(self):
        s = _make_scanner()
        s.hosts = s.parse()
        self.assertGreaterEqual(s.get_summary()["risky_ports"], 4)

    def test_empty_network_returns_empty(self):
        hosts = _make_scanner(hosts_data={}).parse()
        self.assertEqual(hosts, [])

    def test_summary_empty_when_no_hosts(self):
        s = _make_scanner(hosts_data={})
        s.hosts = s.parse()
        self.assertEqual(s.get_summary(), {})

    def test_host_with_no_ports(self):
        data  = {"192.168.1.50": {"state":"up","hostnames":[{"name":"silent"}],
                                   "osmatch":[],"protos":{}}}
        hosts = _make_scanner(data).parse()
        self.assertEqual(hosts[0]["open_ports"], [])
        self.assertEqual(hosts[0]["risky_port_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
