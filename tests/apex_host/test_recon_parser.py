from __future__ import annotations

from apex_host.parsers.ffuf_parser import FfufParser
from apex_host.parsers.gobuster_parser import GobusterParser
from apex_host.parsers.nmap_parser import NmapParser

_NMAP_SAMPLE = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
Not shown: 997 filtered ports

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS))
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS))

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 10.05 seconds
"""

_FFUF_SAMPLE = """\
/admin                  [Status: 200, Size: 1234, Words: 100, Lines: 50, Duration: 100ms]
/login                  [Status: 200, Size: 987, Words: 80, Lines: 40, Duration: 50ms]
/secret                 [Status: 403, Size: 10, Words: 1, Lines: 1, Duration: 5ms]
"""

_GOBUSTER_SAMPLE = """\
/admin (Status: 200) [Size: 1234]
/login (Status: 302) [Size: 0]
"""


def test_nmap_creates_host_node() -> None:
    parsed = NmapParser().parse_text(_NMAP_SAMPLE, target="192.168.1.1")
    node_types = {n.type for n in parsed.node_deltas}
    assert "host" in node_types
    host = next(n for n in parsed.node_deltas if n.type == "host")
    assert host.props["ip"] == "192.168.1.1"


def test_nmap_creates_service_nodes_and_edges() -> None:
    parsed = NmapParser().parse_text(_NMAP_SAMPLE, target="192.168.1.1")
    services = [n for n in parsed.node_deltas if n.type == "service"]
    assert len(services) == 3
    ports = {s.props["port"] for s in services}
    assert ports == {"22", "80", "443"}

    ssh = next(s for s in services if s.props["port"] == "22")
    assert ssh.props["service"] == "ssh"
    assert "OpenSSH" in ssh.props["version"]

    host_id = "host:192.168.1.1"
    expose_edges = [e for e in parsed.edge_deltas if e.type == "exposes" and e.from_id == host_id]
    assert len(expose_edges) == 3


def test_nmap_handles_no_open_ports() -> None:
    parsed = NmapParser().parse_text("Nmap scan report for 10.0.0.1\nHost is up.\n", target="10.0.0.1")
    assert len(parsed.node_deltas) == 1
    assert parsed.node_deltas[0].type == "host"
    assert parsed.edge_deltas == []


def test_ffuf_creates_endpoint_nodes() -> None:
    parsed = FfufParser().parse_text(_FFUF_SAMPLE, target="http://target.local")
    endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
    assert len(endpoints) == 3
    statuses = {e.props["status"] for e in endpoints}
    assert statuses == {"200", "403"}


def test_gobuster_creates_endpoint_nodes() -> None:
    parsed = GobusterParser().parse_text(_GOBUSTER_SAMPLE, target="http://target.local")
    endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
    assert len(endpoints) == 2
    paths = {e.props["path"] for e in endpoints}
    assert paths == {"/admin", "/login"}
