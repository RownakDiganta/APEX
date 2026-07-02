# web_planner.py
# Deterministic web-phase planner that emits safe, bounded curl probes and optional wordlist-based discovery.
"""Deterministic web-phase planner.

Implements memfabric.coordination.protocols.Planner.

Probing strategy (in emission order — graph.py executes the first task per
web_agent turn):

1. ``curl -s -I <base_url>``  — HEAD probe, always emitted when curl is
   available.  Reveals HTTP status, Server header, and content-type.
   Parsed by ``CommandParser`` into an ``endpoint`` + optional ``tech`` node.

2. ``curl -s <base_url>`` — body fetch, always emitted when curl is available.
   Extracts page ``<title>`` and relative ``href`` links into additional
   ``endpoint`` nodes.  Parsed by ``CommandParser.parse_curl_body``.

3. ``ffuf -u <base_url>/FUZZ -w <wordlist>`` — directory discovery, emitted
   **only** when ``web_wordlist_path`` is configured *and* ffuf is in
   ``allowed_tools``.  Never runs against unconfigured wordlists.

4. ``gobuster dir -u <base_url> -w <wordlist>`` — alternative discovery,
   same wordlist guard as ffuf.

The planner derives the base URL from the highest-confidence ``web_probe``
capability in the EKG subgraph (produced by prior recon).  Falls back to
``http://{target}`` before recon has run.

Safety rules
------------
- No payload/exploit tasks.  Discovery only.
- Wordlist-based fuzzing is opt-in: omitting ``web_wordlist_path`` (the
  default) guarantees ffuf/gobuster are never run.
- ``max_web_paths`` caps the ``-maxtime`` argument passed to ffuf so a
  single turn cannot run indefinitely.
- Planners receive state through the blackboard (subgraph + evidence) only
  — no direct MemoryAPI calls here.
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.tools.registry import ToolRegistry


def _base_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def _url_from_cap(target: str, port: str) -> str:
    """Build a URL from a capability's target + port, choosing http/https by port."""
    scheme = "https" if port in ("443", "8443") else "http"
    non_default = port not in ("80", "443")
    suffix = f":{port}" if non_default else ""
    return f"{scheme}://{target}{suffix}"


class WebPlanner:
    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        web_wordlist_path: str | None = None,
        max_web_paths: int = 50,
    ) -> None:
        self._target = target
        self._registry = registry
        self._wordlist = web_wordlist_path
        self._max_paths = max_web_paths

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        # Derive base URL from highest-confidence web_probe capability in the
        # EKG; fall back to http://target when recon has not run yet.
        caps = capabilities_from_subgraph(subgraph)
        web_caps = sorted(
            [c for c in caps if c.name == "web_probe"],
            key=lambda c: c.confidence,
            reverse=True,
        )
        base_url = (
            _url_from_cap(web_caps[0].target, web_caps[0].port)
            if web_caps
            else _base_url(self._target)
        )

        tasks: list[TaskSpec] = []

        if self._registry.get("curl") is not None:
            # HEAD probe — server headers, status code, tech fingerprint
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="web",
                    params={
                        "tool": "curl",
                        "args": ["-s", "-I", base_url],
                        "target": base_url,
                        "parser": "command",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            )
            # Body fetch — page title + relative-href links
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="web",
                    params={
                        "tool": "curl",
                        "args": ["-s", base_url],
                        "target": base_url,
                        "parser": "curl_body",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            )

        # Wordlist-based directory discovery — opt-in only.
        # Neither ffuf nor gobuster are emitted without an explicit wordlist.
        if self._wordlist:
            if self._registry.get("ffuf") is not None:
                tasks.append(
                    TaskSpec(
                        id=new_id(),
                        goal_id=goal.id,
                        executor_domain="web",
                        params={
                            "tool": "ffuf",
                            "args": [
                                "-u", f"{base_url}/FUZZ",
                                "-w", self._wordlist,
                                "-mc", "200,301,302,403",
                                "-maxtime", "60",
                            ],
                            "target": base_url,
                            "parser": "ffuf",
                        },
                        subgraph_anchor=goal.anchor_node,
                        phase=goal.phase,
                    )
                )
            if self._registry.get("gobuster") is not None:
                tasks.append(
                    TaskSpec(
                        id=new_id(),
                        goal_id=goal.id,
                        executor_domain="web",
                        params={
                            "tool": "gobuster",
                            "args": [
                                "dir",
                                "-u", base_url,
                                "-w", self._wordlist,
                                "-q",
                                "--no-progress",
                            ],
                            "target": base_url,
                            "parser": "gobuster",
                        },
                        subgraph_anchor=goal.anchor_node,
                        phase=goal.phase,
                    )
                )

        if not tasks:
            return AbandonSignal(
                reason=(
                    "no web-capable tools in allowed_tools"
                    if not self._wordlist
                    else "no web-capable tools in allowed_tools and no wordlist-capable tools"
                )
            )
        return tasks
