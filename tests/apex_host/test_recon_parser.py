# test_recon_parser.py
# Tests for NmapParser, FfufParser, GobusterParser, CommandParser (curl), and BannerParser verifying correct EKG node/edge extraction from representative stdout samples.
from __future__ import annotations

import pytest

from apex_host.parsers.banner_parser import BannerParser
from apex_host.parsers.command_parser import CommandParser
from apex_host.parsers.ffuf_parser import FfufParser
from apex_host.parsers.gobuster_parser import GobusterParser
from apex_host.parsers.nmap_parser import NmapParser
from memfabric.types import RawObservation

# ---------------------------------------------------------------------------
# Sample outputs
# ---------------------------------------------------------------------------

_NMAP_MULTI = """\
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

_NMAP_SSH_ONLY = """\
Nmap scan report for 10.10.10.14
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Ubuntu 5+ubuntu20.04.1 (Ubuntu Linux; protocol 2.0)
"""

_NMAP_FTP = """\
Nmap scan report for 10.10.10.14
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
"""

_NMAP_TELNET = """\
Nmap scan report for 10.10.10.14
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
"""

_NMAP_HTTP = """\
Nmap scan report for 10.10.10.14
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
"""

_NMAP_NO_PORTS = "Nmap scan report for 10.0.0.1\nHost is up.\n"

_NMAP_NO_VERSION = """\
Nmap scan report for 10.10.10.14
PORT   STATE SERVICE
22/tcp open  ssh
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

_CURL_APACHE = """\
HTTP/1.1 200 OK
Date: Mon, 01 Jan 2025 12:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Length: 11321
"""

_CURL_NGINX = """\
HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
content-type: text/html; charset=utf-8
"""

_CURL_NO_SERVER = """\
HTTP/1.1 200 OK
Content-Type: text/html
"""

_SSH_BANNER = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5+ubuntu20.04.1"
_FTP_VSFTPD_BANNER = "220 (vsFTPd 3.0.3)"
_FTP_PROFTPD_BANNER = "220 ProFTPD 1.3.5e Server"
_FTP_GENERIC_BANNER = "220 FTP Service Ready"
_TELNET_BANNER = "Ubuntu 20.04.2 LTS\n\ntarget login: "
_UNKNOWN_BANNER = "MYSTERY 1.0 -- unknown protocol banner"

# ---------------------------------------------------------------------------
# NmapParser — existing tests
# ---------------------------------------------------------------------------

class TestNmapParserBasic:
    def test_creates_host_node(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_MULTI, target="192.168.1.1")
        node_types = {n.type for n in parsed.node_deltas}
        assert "host" in node_types
        host = next(n for n in parsed.node_deltas if n.type == "host")
        assert host.props["ip"] == "192.168.1.1"

    def test_creates_service_nodes_and_exposes_edges(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_MULTI, target="192.168.1.1")
        services = [n for n in parsed.node_deltas if n.type == "service"]
        assert len(services) == 3
        ports = {s.props["port"] for s in services}
        assert ports == {"22", "80", "443"}

        ssh = next(s for s in services if s.props["port"] == "22")
        assert ssh.props["service"] == "ssh"
        # raw_version holds the full nmap banner; version holds the extracted short string
        assert "OpenSSH" in ssh.props["raw_version"]

        expose_edges = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(expose_edges) == 3

    def test_handles_no_open_ports(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_NO_PORTS, target="10.0.0.1")
        assert len(parsed.node_deltas) == 1
        assert parsed.node_deltas[0].type == "host"
        assert parsed.edge_deltas == []


# ---------------------------------------------------------------------------
# NmapParser — tech node tests
# ---------------------------------------------------------------------------

class TestNmapParserTech:
    def test_ssh_produces_tech_node(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_SSH_ONLY, target="10.10.10.14")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert tech_nodes[0].props["name"] == "OpenSSH"
        assert "8.4p1" in tech_nodes[0].props["version"]

    def test_ssh_tech_node_id_is_stable(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_SSH_ONLY, target="10.10.10.14")
        tech = next(n for n in parsed.node_deltas if n.type == "tech")
        assert tech.id == "tech:10.10.10.14:openssh"

    def test_ssh_runs_edge_from_service_to_tech(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_SSH_ONLY, target="10.10.10.14")
        runs_edges = [e for e in parsed.edge_deltas if e.type == "runs"]
        assert len(runs_edges) == 1
        assert runs_edges[0].from_id == "service:10.10.10.14:22/tcp"
        tech = next(n for n in parsed.node_deltas if n.type == "tech")
        assert runs_edges[0].to_id == tech.id

    def test_ftp_vsftpd_produces_tech_node(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_FTP, target="10.10.10.14")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert tech_nodes[0].props["name"] == "vsftpd"
        assert tech_nodes[0].props["version"] == "3.0.3"

    def test_telnet_produces_tech_node(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_TELNET, target="10.10.10.14")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert "telnet" in tech_nodes[0].props["name"].lower() or "linux" in tech_nodes[0].props["name"].lower()

    def test_http_apache_produces_tech_node(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_HTTP, target="10.10.10.14")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert "Apache" in tech_nodes[0].props["name"]
        assert "2.4.41" in tech_nodes[0].props["version"]

    def test_no_version_means_no_tech_node(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_NO_VERSION, target="10.10.10.14")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech_nodes == []

    def test_multiple_services_produce_multiple_tech_nodes(self) -> None:
        parsed = NmapParser().parse_text(_NMAP_MULTI, target="192.168.1.1")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        # ssh (OpenSSH) and http/ssl-http (both Apache httpd — same tech id, deduplicated)
        tech_names = {n.props["name"] for n in tech_nodes}
        assert "OpenSSH" in tech_names
        assert any("Apache" in name for name in tech_names)


# ---------------------------------------------------------------------------
# FfufParser
# ---------------------------------------------------------------------------

class TestFfufParser:
    _TARGET = "http://target.local"

    def test_creates_endpoint_nodes(self) -> None:
        parsed = FfufParser().parse_text(_FFUF_SAMPLE, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 3
        statuses = {e.props["status"] for e in endpoints}
        assert statuses == {"200", "403"}

    def test_creates_exposes_edges(self) -> None:
        parsed = FfufParser().parse_text(_FFUF_SAMPLE, target=self._TARGET)
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(exposes) == 3

    def test_exposes_edge_from_host(self) -> None:
        parsed = FfufParser().parse_text(_FFUF_SAMPLE, target=self._TARGET)
        for edge in parsed.edge_deltas:
            assert edge.from_id == f"host:{self._TARGET}"

    def test_url_constructed_from_target_and_path(self) -> None:
        output = "/api [Status: 200, Size: 10, Words: 1, Lines: 1, Duration: 5ms]"
        parsed = FfufParser().parse_text(output, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0].props["url"] == f"{self._TARGET}/api"
        assert endpoints[0].props["path"] == "/api"

    def test_endpoint_node_has_status_prop(self) -> None:
        output = "/login [Status: 302, Size: 0, Words: 0, Lines: 0, Duration: 10ms]"
        parsed = FfufParser().parse_text(output, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert endpoints[0].props["status"] == "302"

    def test_empty_output_returns_empty_observation(self) -> None:
        parsed = FfufParser().parse_text("", target=self._TARGET)
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []

    def test_non_matching_header_lines_are_skipped(self) -> None:
        output = (
            "        /'___\\  /'___\\           /'___\\\n"
            "Starting ffuf\n"
            "/admin [Status: 200, Size: 100, Words: 5, Lines: 2, Duration: 20ms]\n"
            ":: Progress: [4614/4614]\n"
        )
        parsed = FfufParser().parse_text(output, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0].props["path"] == "/admin"

    def test_all_matched_statuses_included(self) -> None:
        output = (
            "/index.php [Status: 200, Size: 5, Words: 1, Lines: 1, Duration: 1ms]\n"
            "/robots.txt [Status: 200, Size: 20, Words: 2, Lines: 2, Duration: 1ms]\n"
            "/secret [Status: 403, Size: 0, Words: 0, Lines: 0, Duration: 1ms]\n"
            "/redirect [Status: 301, Size: 0, Words: 0, Lines: 0, Duration: 1ms]\n"
        )
        parsed = FfufParser().parse_text(output, target=self._TARGET)
        statuses = {n.props["status"] for n in parsed.node_deltas if n.type == "endpoint"}
        assert statuses == {"200", "403", "301"}


# ---------------------------------------------------------------------------
# GobusterParser
# ---------------------------------------------------------------------------

class TestGobusterParser:
    _TARGET = "http://target.local"

    def test_creates_endpoint_nodes(self) -> None:
        parsed = GobusterParser().parse_text(_GOBUSTER_SAMPLE, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 2
        paths = {e.props["path"] for e in endpoints}
        assert paths == {"/admin", "/login"}

    def test_creates_exposes_edges(self) -> None:
        parsed = GobusterParser().parse_text(_GOBUSTER_SAMPLE, target=self._TARGET)
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(exposes) == 2

    def test_exposes_edge_from_host(self) -> None:
        parsed = GobusterParser().parse_text(_GOBUSTER_SAMPLE, target=self._TARGET)
        for edge in parsed.edge_deltas:
            assert edge.from_id == f"host:{self._TARGET}"

    def test_url_constructed_from_target_and_path(self) -> None:
        output = "/admin (Status: 200) [Size: 512]"
        parsed = GobusterParser().parse_text(output, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0].props["url"] == f"{self._TARGET}/admin"
        assert endpoints[0].props["path"] == "/admin"

    def test_endpoint_node_has_status_prop(self) -> None:
        output = "/login (Status: 302) [Size: 0]"
        parsed = GobusterParser().parse_text(output, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert endpoints[0].props["status"] == "302"

    def test_empty_output_returns_empty_observation(self) -> None:
        parsed = GobusterParser().parse_text("", target=self._TARGET)
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []

    def test_non_matching_lines_are_skipped(self) -> None:
        output = (
            "Gobuster v3.1.0\n"
            "===============================================================\n"
            "/admin (Status: 200) [Size: 1024]\n"
            "===============================================================\n"
            "Finished\n"
        )
        parsed = GobusterParser().parse_text(output, target=self._TARGET)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0].props["path"] == "/admin"

    def test_multiple_statuses_included(self) -> None:
        output = (
            "/admin (Status: 200) [Size: 100]\n"
            "/secret (Status: 403) [Size: 0]\n"
            "/redirect (Status: 301) [Size: 0]\n"
        )
        parsed = GobusterParser().parse_text(output, target=self._TARGET)
        statuses = {n.props["status"] for n in parsed.node_deltas if n.type == "endpoint"}
        assert statuses == {"200", "403", "301"}


# ---------------------------------------------------------------------------
# CommandParser — curl HTTP header detection
# ---------------------------------------------------------------------------

class TestCommandParserCurl:
    def _raw(self, text: str, source: str = "curl", target: str = "10.10.10.14") -> RawObservation:
        return RawObservation(raw=text, metadata={"source": source, "target": target})

    def test_curl_apache_creates_endpoint_node(self) -> None:
        parsed = CommandParser().parse(self._raw(_CURL_APACHE))
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0].props["status"] == "200"

    def test_curl_apache_creates_tech_node_from_server_header(self) -> None:
        parsed = CommandParser().parse(self._raw(_CURL_APACHE))
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert tech_nodes[0].props["name"] == "Apache"
        assert tech_nodes[0].props["version"] == "2.4.41"

    def test_curl_creates_endpoint_to_tech_runs_edge(self) -> None:
        parsed = CommandParser().parse(self._raw(_CURL_APACHE))
        runs_edges = [e for e in parsed.edge_deltas if e.type == "runs"]
        assert len(runs_edges) == 1
        endpoint = next(n for n in parsed.node_deltas if n.type == "endpoint")
        assert runs_edges[0].from_id == endpoint.id

    def test_curl_host_to_endpoint_exposes_edge(self) -> None:
        parsed = CommandParser().parse(self._raw(_CURL_APACHE))
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(exposes) == 1
        assert exposes[0].from_id == "host:10.10.10.14"

    def test_curl_nginx_produces_nginx_tech(self) -> None:
        parsed = CommandParser().parse(self._raw(_CURL_NGINX))
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert tech_nodes[0].props["name"] == "nginx"
        assert "1.18.0" in tech_nodes[0].props["version"]

    def test_curl_no_server_header_no_tech_node(self) -> None:
        parsed = CommandParser().parse(self._raw(_CURL_NO_SERVER))
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech_nodes == []
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1

    def test_non_curl_unknown_output_becomes_knowledge_entry(self) -> None:
        raw = RawObservation(raw="some gobbledygook output", metadata={"source": "unknown_tool"})
        parsed = CommandParser().parse(raw)
        assert parsed.node_deltas == []
        assert len(parsed.proposed_knowledge) == 1
        assert parsed.proposed_knowledge[0].confidence == 0.3

    def test_empty_output_returns_empty_observation(self) -> None:
        raw = RawObservation(raw="   ", metadata={"source": "curl"})
        parsed = CommandParser().parse(raw)
        assert parsed.node_deltas == []
        assert parsed.proposed_knowledge == []


# ---------------------------------------------------------------------------
# BannerParser — nc/netcat banner detection
# ---------------------------------------------------------------------------

class TestBannerParser:
    def test_ssh_banner_creates_service_node(self) -> None:
        parsed = BannerParser().parse_text(_SSH_BANNER, target="10.10.10.14", port="22")
        services = [n for n in parsed.node_deltas if n.type == "service"]
        assert len(services) == 1
        assert services[0].props["service"] == "ssh"
        assert services[0].id == "service:10.10.10.14:22/tcp"

    def test_ssh_banner_creates_openssh_tech_node(self) -> None:
        parsed = BannerParser().parse_text(_SSH_BANNER, target="10.10.10.14", port="22")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1
        assert tech_nodes[0].props["name"] == "OpenSSH"
        assert "8.4p1" in tech_nodes[0].props["version"]

    def test_ssh_banner_creates_runs_edge(self) -> None:
        parsed = BannerParser().parse_text(_SSH_BANNER, target="10.10.10.14", port="22")
        runs_edges = [e for e in parsed.edge_deltas if e.type == "runs"]
        assert len(runs_edges) == 1

    def test_ftp_vsftpd_creates_service_and_tech(self) -> None:
        parsed = BannerParser().parse_text(_FTP_VSFTPD_BANNER, target="10.10.10.14", port="21")
        services = [n for n in parsed.node_deltas if n.type == "service"]
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(services) == 1 and services[0].props["service"] == "ftp"
        assert len(tech_nodes) == 1 and tech_nodes[0].props["name"] == "vsftpd"
        assert tech_nodes[0].props["version"] == "3.0.3"

    def test_ftp_proftpd_creates_service_and_tech(self) -> None:
        parsed = BannerParser().parse_text(_FTP_PROFTPD_BANNER, target="10.10.10.14", port="21")
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(tech_nodes) == 1 and tech_nodes[0].props["name"] == "ProFTPD"

    def test_ftp_generic_creates_service_only(self) -> None:
        parsed = BannerParser().parse_text(_FTP_GENERIC_BANNER, target="10.10.10.14", port="21")
        services = [n for n in parsed.node_deltas if n.type == "service"]
        tech_nodes = [n for n in parsed.node_deltas if n.type == "tech"]
        assert len(services) == 1 and services[0].props["service"] == "ftp"
        assert tech_nodes == []

    def test_telnet_banner_creates_telnet_service_node(self) -> None:
        parsed = BannerParser().parse_text(_TELNET_BANNER, target="10.10.10.14", port="23")
        services = [n for n in parsed.node_deltas if n.type == "service"]
        assert len(services) == 1
        assert services[0].props["service"] == "telnet"

    def test_unknown_banner_becomes_staged_knowledge_entry(self) -> None:
        parsed = BannerParser().parse_text(_UNKNOWN_BANNER, target="10.10.10.14")
        assert parsed.node_deltas == []
        assert len(parsed.proposed_knowledge) == 1
        assert parsed.proposed_knowledge[0].confidence == 0.25

    def test_empty_banner_returns_empty_observation(self) -> None:
        parsed = BannerParser().parse_text("", target="10.10.10.14")
        assert parsed.node_deltas == []
        assert parsed.proposed_knowledge == []

    def test_ssh_without_port_defaults_to_22_in_id(self) -> None:
        parsed = BannerParser().parse_text(_SSH_BANNER, target="10.10.10.14")
        services = [n for n in parsed.node_deltas if n.type == "service"]
        assert services[0].id == "service:10.10.10.14:22/tcp"
