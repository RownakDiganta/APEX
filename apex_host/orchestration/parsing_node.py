# parsing_node.py
# Parser registry and make_parsing_node factory for the APEX orchestration layer.
"""Parsing node factory and parser-routing helpers.

``make_parsing_node`` returns the ``parse_observation`` async LangGraph node.
``parse_single_result`` is the core parser-routing function, extracted from
``graph.py`` so it can be shared with ``repair_node`` and tested in isolation.
``findings_from_parsed`` converts node deltas to the finding records stored
in ``state["findings"]``.

Phase 12C: an exception from ``parse_single_result`` or
``MemoryAPI.apply_deltas`` is caught in ``parse_observation`` and converted
into an ``EngagementOutcome.parser_failure``/``memory_failure``
upstream-preset outcome — see ``apex_host.orchestration.outcome`` module
docstring, precedence level 2 — rather than propagating and crashing
``graph.ainvoke()``.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from memfabric.types import ParsedObservation, RawObservation

from apex_host.parsers.access_parser import AccessParser
from apex_host.parsers.banner_parser import BannerParser
from apex_host.parsers.browser_parser import BrowserParser
from apex_host.parsers.command_parser import CommandParser
from apex_host.parsers.ffuf_parser import FfufParser
from apex_host.parsers.gobuster_parser import GobusterParser
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.outcome import EngagementOutcome
from apex_host.parsers.nmap_parser import NmapParser
from apex_host.parsers.priv_esc_parser import PrivEscParser
from apex_host.types import BrowserObservation

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps

logger = logging.getLogger(__name__)

# Module-level singleton parser instances (cheap; no model weights)
_NMAP = NmapParser()
_FFUF = FfufParser()
_GOBUSTER = GobusterParser()
_COMMAND = CommandParser()
_BANNER = BannerParser()
_BROWSER_PARSER = BrowserParser()
_ACCESS = AccessParser()
_PRIV_ESC = PrivEscParser()


def _port_from_nc_args(args: list[str]) -> str:
    """Extract the port number from nc/netcat argv (last non-flag token)."""
    positional = [a for a in args if not a.startswith("-")]
    return positional[-1] if len(positional) >= 2 else ""


def parse_single_result(
    tool_result: dict[str, Any], state: "ApexGraphState"
) -> tuple[ParsedObservation, str]:
    """Route one tool_result dict to the correct parser and return (observation, source).

    Extracted from ``graph.py`` so it can be reused by ``repair_node`` and tested in
    isolation without the full LangGraph compile step.
    """
    if tool_result.get("kind") == "browser":
        obs_dict = tool_result.get("obs") or {}
        fallback_url = str(tool_result.get("url", ""))
        fallback_title = "(dry-run)" if tool_result.get("dry_run") else ""
        obs = BrowserObservation(
            url=str(obs_dict.get("url", fallback_url)),
            html_snippet=str(obs_dict.get("html_snippet", "")),
            title=str(obs_dict.get("title", fallback_title)),
            forms=list(obs_dict.get("forms", [])),
            tokens=list(obs_dict.get("tokens", [])),
            auth_hints=list(obs_dict.get("auth_hints", [])),
            links=list(obs_dict.get("links", [])),
            status=str(obs_dict.get("status", "")),
            headers=dict(obs_dict.get("headers", {})),
            cookies=list(obs_dict.get("cookies", [])),
            final_url=str(obs_dict.get("final_url", "")),
            favicon_present=bool(obs_dict.get("favicon_present", False)),
        )
        obs_target = str(obs_dict.get("url", fallback_url))
        parsed = _BROWSER_PARSER.parse_observation(obs, target=obs_target, source="browser")
        return parsed, "browser"

    target = tool_result.get("target", state["target"])
    stdout = tool_result.get("stdout", "")
    parser_name = tool_result.get("parser", "command")
    tool_name = tool_result.get("tool", "")
    if parser_name == "nmap" or tool_name == "nmap":
        return _NMAP.parse_text(stdout, target=target), tool_name
    if parser_name == "ffuf":
        return _FFUF.parse_text(stdout, target=target), tool_name
    if parser_name == "gobuster":
        return _GOBUSTER.parse_text(stdout, target=target), tool_name
    if tool_name in ("nc", "netcat") or parser_name == "banner":
        port = _port_from_nc_args(tool_result.get("args", []))
        return _BANNER.parse_text(stdout, target=target, source=tool_name, port=port), tool_name
    if parser_name == "access":
        username = str(tool_result.get("username", ""))
        if tool_name in ("ssh_access", "ftp_access"):
            # Phase 12B — SSH/FTP results are already classified by the
            # executor (success/authenticated determined via a typed
            # exception or protocol response code, never a text heuristic).
            default_protocol = "ssh" if tool_name == "ssh_access" else "ftp"
            protocol = str(tool_result.get("protocol", default_protocol)) or default_protocol
            operation = str(tool_result.get("operation", ""))
            parsed = _ACCESS.parse_structured(
                protocol=protocol, target=target, username=username,
                success=bool(tool_result.get("success", False)),
                authenticated=bool(tool_result.get("authenticated", False)),
                port=str(tool_result.get("port", "")),
                proto=str(tool_result.get("proto", "tcp")),
                evidence_text=str(tool_result.get("response_summary", "")),
                proof_type=f"{protocol}_{operation}".strip("_") if operation else protocol,
            )
            return parsed, tool_name
        parsed = _ACCESS.parse_text(
            stdout, target=target, username=username,
            source=str(tool_result.get("tool", "telnet_access")),
            port=str(tool_result.get("port", "")),
            proto=str(tool_result.get("proto", "tcp")),
        )
        return parsed, tool_name
    if parser_name == "curl_body":
        raw = RawObservation(raw=stdout, metadata={"source": "curl_body", "target": target})
        return _COMMAND.parse_curl_body(raw), tool_name
    if parser_name == "priv_esc":
        # Phase 13 — two producers share this parser field: searchsploit's
        # real tool output and priv_esc_analyze's precomputed analytical
        # signal (zero network, zero subprocess — see
        # apex_host/agents/priv_esc_analysis_executor.py). Neither ever
        # contains exploit code or payload content.
        if tool_name == "priv_esc_analyze":
            parsed = _PRIV_ESC.parse_analytical(
                target=target,
                category=str(tool_result.get("category", "")),
                confidence=str(tool_result.get("confidence", "")),
                description=str(tool_result.get("description", "")),
                recommended_next_action=str(tool_result.get("recommended_next_action", "")),
                discriminator=str(tool_result.get("discriminator", "")),
                evidence_source=str(tool_result.get("evidence_source", "")),
                evidence_excerpt=str(tool_result.get("evidence_excerpt", "")),
                source_node_id=str(tool_result.get("source_node_id", "")),
            )
            return parsed, tool_name
        args_list = tool_result.get("args", [])
        service = str(args_list[0]) if args_list else ""
        version = str(args_list[1]) if len(args_list) > 1 else ""
        parsed = _PRIV_ESC.parse_searchsploit(stdout, target=target, service=service, version=version)
        return parsed, tool_name
    if parser_name == "priv_esc_enum":
        # Phase 13B — live, read-only enumeration command output ->
        # evidence + derived opportunity/recommendation deltas. Fact
        # extraction is entirely deterministic (see PrivEscParser.parse_enumeration);
        # never LLM parsing. A real connection/auth/protocol failure (the
        # executor's own "error" field) never produced usable output, so it
        # is never turned into an (empty, misleading) evidence node here —
        # it is tracked instead via the existing error_episodes mechanism
        # (see docs/privilege-enumeration.md "Enumeration state").
        if tool_result.get("error"):
            return ParsedObservation(), tool_name
        parsed = _PRIV_ESC.parse_enumeration(
            stdout,
            target=target,
            category=str(tool_result.get("category", "")),
            command_key=str(tool_result.get("command_key", "")),
            source_command=str(tool_result.get("source_command", "")),
            port=str(tool_result.get("port", "")),
        )
        return parsed, tool_name
    raw = RawObservation(raw=stdout, metadata={"source": tool_name, "target": target})
    return _COMMAND.parse(raw), tool_name


def findings_from_parsed(
    parsed: ParsedObservation, *, phase: str, source: str, timestamp: str
) -> list[dict[str, Any]]:
    """Convert ParsedObservation node deltas to findings records."""
    return [
        {
            "id": node.id, "phase": phase,
            "title": f"{node.type} discovered", "detail": str(node.props)[:300],
            "confidence": node.confidence, "source": source, "timestamp": timestamp,
        }
        for node in parsed.node_deltas
    ]


def make_parsing_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``parse_observation`` async node bound to *deps*."""

    async def parse_observation(state: "ApexGraphState") -> dict[str, Any]:
        raw_results = state.get("tool_results")
        results_to_parse: list[dict[str, Any]] = (
            raw_results if raw_results
            else ([state["last_tool_result"]] if state["last_tool_result"] else [])
        )
        if not results_to_parse:
            return {}

        all_findings: list[dict[str, Any]] = []
        for tool_result in results_to_parse:
            try:
                parsed, source = parse_single_result(tool_result, state)
            except Exception as exc:
                logger.error(
                    "parser failed for tool=%r in phase %s: %s",
                    tool_result.get("tool"), state["phase"], exc,
                )
                return {
                    "findings": all_findings,
                    "outcome": EngagementOutcome.parser_failure.value,
                    "termination_reason": f"{type(exc).__name__}: {exc}",
                    "termination_phase": state["phase"],
                }

            try:
                await deps.api.apply_deltas(
                    nodes=parsed.node_deltas,
                    edges=parsed.edge_deltas,
                    knowledge=parsed.proposed_knowledge,
                )
            except Exception as exc:
                logger.error("apply_deltas failed in parse_observation: %s", exc)
                return {
                    "findings": all_findings,
                    "outcome": EngagementOutcome.memory_failure.value,
                    "termination_reason": f"{type(exc).__name__}: {exc}",
                    "termination_phase": state["phase"],
                }

            all_findings.extend(
                findings_from_parsed(
                    parsed, phase=state["phase"],
                    source=source, timestamp=tool_result.get("timestamp", ""),
                )
            )
        return {"findings": all_findings}

    return parse_observation
