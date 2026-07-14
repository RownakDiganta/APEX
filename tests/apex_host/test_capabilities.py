# test_capabilities.py
# Tests for capabilities_from_subgraph verifying the mapping from EKG service and endpoint nodes to planner capability names.
from __future__ import annotations

from memfabric.ids import now
from memfabric.types import Node, SubgraphView

from apex_host.planners.capabilities import Capability, capabilities_from_subgraph

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.14"
_ANCHOR = f"host:{_TARGET}"


def _subgraph(*nodes: Node) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=[], depth=2)


def _service(
    port: str,
    service: str = "",
    proto: str = "tcp",
    state: str = "open",
    version: str = "",
    confidence: float = 0.9,
) -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/{proto}",
        type="service",
        props={
            "port": port,
            "proto": proto,
            "service": service,
            "state": state,
            "version": version,
        },
        confidence=confidence,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _endpoint(url: str, status: str = "200", confidence: float = 0.8) -> Node:
    return Node(
        id=f"endpoint:{url}",
        type="endpoint",
        props={"url": url, "status": status},
        confidence=confidence,
        source="curl",
        first_seen=now(),
        last_seen=now(),
    )


def _cap_names(caps: list[Capability]) -> set[str]:
    return {c.name for c in caps}


# ---------------------------------------------------------------------------
# Empty / non-classifiable input
# ---------------------------------------------------------------------------

class TestEmptySubgraph:
    def test_empty_subgraph_returns_empty_list(self) -> None:
        sg = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)
        assert capabilities_from_subgraph(sg) == []

    def test_host_node_only_returns_empty(self) -> None:
        host = Node(
            id=f"host:{_TARGET}", type="host",
            props={"ip": _TARGET}, confidence=0.9,
            source="nmap", first_seen=now(), last_seen=now(),
        )
        assert capabilities_from_subgraph(_subgraph(host)) == []

    def test_udp_service_returns_empty(self) -> None:
        udp = _service("53", service="domain", proto="udp")
        assert capabilities_from_subgraph(_subgraph(udp)) == []

    def test_closed_service_returns_empty(self) -> None:
        closed = _service("22", service="ssh", state="closed")
        assert capabilities_from_subgraph(_subgraph(closed)) == []

    def test_filtered_service_returns_empty(self) -> None:
        filtered = _service("22", service="ssh", state="filtered")
        assert capabilities_from_subgraph(_subgraph(filtered)) == []


# ---------------------------------------------------------------------------
# Service-based capability mapping
# ---------------------------------------------------------------------------

class TestServiceCapabilities:
    def test_telnet_produces_access_validate_telnet(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("23", service="telnet")))
        assert "access_validate_telnet" in _cap_names(caps)

    def test_telnet_by_port_number_only(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("23", service="")))
        assert "access_validate_telnet" in _cap_names(caps)

    def test_ssh_produces_access_validate_ssh(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("22", service="ssh")))
        assert "access_validate_ssh" in _cap_names(caps)

    def test_ssh_by_port_number_only(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("22", service="")))
        assert "access_validate_ssh" in _cap_names(caps)

    def test_ftp_produces_access_validate_ftp(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("21", service="ftp")))
        assert "access_validate_ftp" in _cap_names(caps)

    def test_ftp_by_port_number_only(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("21", service="")))
        assert "access_validate_ftp" in _cap_names(caps)

    def test_http_produces_web_probe_and_browser_observe(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("80", service="http")))
        names = _cap_names(caps)
        assert "web_probe" in names
        assert "browser_observe" in names

    def test_https_port_produces_web_probe(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("443", service="")))
        assert "web_probe" in _cap_names(caps)

    def test_ssl_http_service_name_produces_web_probe(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("443", service="ssl/http")))
        assert "web_probe" in _cap_names(caps)

    def test_unknown_service_outside_probeworthy_ports_returns_empty(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("9999", service="unknown")))
        assert caps == []

    def test_unknown_service_on_probeworthy_port_produces_service_probe(self) -> None:
        # Port 6379 (Redis) with no service name recognised
        caps = capabilities_from_subgraph(_subgraph(_service("6379", service="")))
        assert "service_probe" in _cap_names(caps)

    def test_smb_port_445_not_probeworthy_returns_empty(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_service("445", service="microsoft-ds")))
        assert caps == []

    def test_smtp_port_25_produces_service_probe(self) -> None:
        # smtp not in specific access_validate_* categories → service_probe via port
        caps = capabilities_from_subgraph(_subgraph(_service("25", service="smtp")))
        assert "service_probe" in _cap_names(caps)


# ---------------------------------------------------------------------------
# exploit_research capability
# ---------------------------------------------------------------------------

class TestExploitResearch:
    def test_versioned_service_produces_exploit_research(self) -> None:
        node = _service("22", service="ssh", version="OpenSSH 8.4p1")
        caps = capabilities_from_subgraph(_subgraph(node))
        assert "exploit_research" in _cap_names(caps)

    def test_exploit_research_coexists_with_access_validate(self) -> None:
        node = _service("22", service="ssh", version="OpenSSH 8.4p1")
        caps = capabilities_from_subgraph(_subgraph(node))
        names = _cap_names(caps)
        assert "exploit_research" in names
        assert "access_validate_ssh" in names

    def test_no_version_means_no_exploit_research(self) -> None:
        node = _service("22", service="ssh", version="")
        caps = capabilities_from_subgraph(_subgraph(node))
        assert "exploit_research" not in _cap_names(caps)


# ---------------------------------------------------------------------------
# Endpoint-based capability mapping
# ---------------------------------------------------------------------------

class TestEndpointCapabilities:
    def test_endpoint_node_produces_web_probe(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_endpoint("http://10.10.10.14/login")))
        assert "web_probe" in _cap_names(caps)

    def test_endpoint_node_produces_browser_observe(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_endpoint("http://10.10.10.14/login")))
        assert "browser_observe" in _cap_names(caps)

    def test_https_endpoint_port_is_443(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_endpoint("https://10.10.10.14/admin")))
        web = [c for c in caps if c.name == "web_probe"]
        assert web and web[0].port == "443"

    def test_http_endpoint_port_defaults_to_80(self) -> None:
        caps = capabilities_from_subgraph(_subgraph(_endpoint("http://10.10.10.14/page")))
        web = [c for c in caps if c.name == "web_probe"]
        assert web and web[0].port == "80"


# ---------------------------------------------------------------------------
# Capability record fields
# ---------------------------------------------------------------------------

class TestCapabilityFields:
    def test_capability_carries_source_node_id(self) -> None:
        node = _service("22", service="ssh")
        caps = capabilities_from_subgraph(_subgraph(node))
        ssh_cap = next(c for c in caps if c.name == "access_validate_ssh")
        assert ssh_cap.source_node_id == node.id

    def test_capability_carries_port(self) -> None:
        node = _service("21", service="ftp")
        caps = capabilities_from_subgraph(_subgraph(node))
        ftp_cap = next(c for c in caps if c.name == "access_validate_ftp")
        assert ftp_cap.port == "21"

    def test_capability_carries_service(self) -> None:
        node = _service("23", service="telnet")
        caps = capabilities_from_subgraph(_subgraph(node))
        cap = next(c for c in caps if c.name == "access_validate_telnet")
        assert cap.service == "telnet"

    def test_capability_confidence_derived_from_node(self) -> None:
        node = _service("80", service="http", confidence=0.75)
        caps = capabilities_from_subgraph(_subgraph(node))
        web_cap = next(c for c in caps if c.name == "web_probe")
        assert web_cap.confidence == 0.75

    def test_capability_target_extracted_from_anchor(self) -> None:
        node = _service("22", service="ssh")
        caps = capabilities_from_subgraph(_subgraph(node))
        cap = next(c for c in caps if c.name == "access_validate_ssh")
        assert cap.target == _TARGET

    def test_anchor_without_host_prefix_used_as_is(self) -> None:
        sg = SubgraphView(anchor=_TARGET, nodes=[_service("22", service="ssh")], edges=[], depth=2)
        caps = capabilities_from_subgraph(sg)
        cap = next(c for c in caps if c.name == "access_validate_ssh")
        assert cap.target == _TARGET


# ---------------------------------------------------------------------------
# Multiple nodes in one subgraph
# ---------------------------------------------------------------------------

class TestMultipleNodes:
    def test_multiple_services_produce_independent_capabilities(self) -> None:
        sg = _subgraph(
            _service("22", service="ssh"),
            _service("23", service="telnet"),
            _service("80", service="http"),
        )
        names = _cap_names(capabilities_from_subgraph(sg))
        assert "access_validate_ssh" in names
        assert "access_validate_telnet" in names
        assert "web_probe" in names
        assert "browser_observe" in names
