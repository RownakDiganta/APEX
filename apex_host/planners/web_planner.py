# web_planner.py
# Deterministic web-phase planner with an optional PlanningEngine LLM seam.
"""Deterministic web-phase planner with optional LLM backend.

``_WebDeterministic`` contains the original rule-based logic — safe, bounded
curl probes with optional wordlist-based discovery.

``WebPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_WebDeterministic``.

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

from typing import TYPE_CHECKING

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    ClaimDependency,
    EvidenceBundle,
    Goal,
    Node,
    SubgraphView,
    TaskSpec,
)

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.planning.engine import PlanningEngine
    from apex_host.policy.llm_guard import LLMPolicyGuard


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


class _WebDeterministic:
    """Pure rule-based web planner — the fallback for PlanningEngine."""

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
        ip_base_url = (
            _url_from_cap(web_caps[0].target, web_caps[0].port)
            if web_caps
            else _base_url(self._target)
        )
        web_port = web_caps[0].port if web_caps else "80"

        # When a name-based virtual host has been DISCOVERED for this target
        # (e.g. from a 301 Location header — recorded by CommandParser as a
        # `vhost` node), fetch the real app under that host. `curl --resolve
        # <vhost>:<port>:<ip>` connects to the AUTHORIZED IP but sends the vhost
        # Host header and requests the vhost URL, so the redirect chain and
        # relative links resolve against the real app instead of the empty IP
        # 301. The vhost is always runtime-discovered, never hardcoded (§28.8).
        vhost_node = self._select_vhost(subgraph)
        resolve_args: list[str] = []
        follow_args: list[str] = []
        if vhost_node is not None:
            vhost = str(vhost_node.props.get("hostname", "")).strip()
            vip = str(vhost_node.props.get("ip") or self._target).strip()
            scheme = "https" if web_port in ("443", "8443") else "http"
            suffix = f":{web_port}" if web_port not in ("80", "443") else ""
            base_url = f"{scheme}://{vhost}{suffix}"
            # curl --resolve pins the vhost's DNS to the authorized IP — the
            # policy scope gate authorizes this via the pin (never a raw
            # off-scope host). Value is host:port:ip, no shell metacharacters.
            resolve_args = ["--resolve", f"{vhost}:{web_port}:{vip}"]
            # -L follows the redirect chain so the REAL homepage loads (the
            # vhost may itself redirect, e.g. / → /home). Only on the vhost path
            # — a bare-IP fetch must NOT follow its redirect to the unresolvable
            # vhost DNS.
            follow_args = ["-L"]
        else:
            base_url = ip_base_url

        # Record which capability (and therefore which node) drives the URL choice
        # so the conflict guard can block precisely when that node is contested.
        web_claim_deps: tuple[ClaimDependency, ...] = (
            (
                ClaimDependency(
                    node_id=web_caps[0].source_node_id, field_name="port"
                ),
            )
            if web_caps
            else ()
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
                        "args": ["-s", "-I", *follow_args, *resolve_args, base_url],
                        "target": base_url,
                        "parser": "command",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                    claim_dependencies=web_claim_deps,
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
                        "args": ["-s", *follow_args, *resolve_args, base_url],
                        "target": base_url,
                        "parser": "curl_body",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                    claim_dependencies=web_claim_deps,
                )
            )

        # Wordlist-based directory discovery — opt-in only.
        # Neither ffuf nor gobuster are emitted without an explicit wordlist.
        # ffuf/gobuster fuzz the AUTHORIZED IP URL (which resolves in the
        # container) and, when a vhost is known, carry a `-H Host: <vhost>`
        # header so nginx serves the real app under that vhost.
        if self._wordlist:
            host_header_args = (
                ["-H", f"Host: {vhost_node.props.get('hostname', '')}"]
                if vhost_node is not None
                else []
            )
            if self._registry.get("ffuf") is not None:
                tasks.append(
                    TaskSpec(
                        id=new_id(),
                        goal_id=goal.id,
                        executor_domain="web",
                        params={
                            "tool": "ffuf",
                            "args": [
                                "-u", f"{ip_base_url}/FUZZ",
                                "-w", self._wordlist,
                                *host_header_args,
                                "-mc", "200,301,302,403",
                                "-maxtime", "60",
                            ],
                            "target": ip_base_url,
                            "parser": "ffuf",
                        },
                        subgraph_anchor=goal.anchor_node,
                        phase=goal.phase,
                        claim_dependencies=web_claim_deps,
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
                                "-u", ip_base_url,
                                "-w", self._wordlist,
                                *host_header_args,
                                "-q",
                                "--no-progress",
                            ],
                            "target": ip_base_url,
                            "parser": "gobuster",
                        },
                        subgraph_anchor=goal.anchor_node,
                        phase=goal.phase,
                        claim_dependencies=web_claim_deps,
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

    @staticmethod
    def _select_vhost(subgraph: SubgraphView) -> Node | None:
        """Return the highest-confidence ``vhost`` node with a non-empty
        hostname, or ``None``. Deterministic tie-break by hostname so the same
        subgraph always yields the same vhost (blackboard model — reads the
        subgraph only)."""
        vhosts = [
            n for n in subgraph.nodes
            if n.type == "vhost" and str(n.props.get("hostname", "")).strip()
        ]
        if not vhosts:
            return None
        return sorted(
            vhosts, key=lambda n: (-float(n.confidence), str(n.props.get("hostname", "")))
        )[0]


class WebPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _WebDeterministic otherwise."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        web_wordlist_path: str | None = None,
        max_web_paths: int = 50,
        model_router: "ModelRouter | None" = None,
        allowed_tools: list[str] | None = None,
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
        budget_tracker: "LLMBudgetTracker | None" = None,
        guard: "LLMPolicyGuard | None" = None,
        gateway: "LLMGateway | None" = None,
    ) -> None:
        self._core = _WebDeterministic(
            target, registry,
            web_wordlist_path=web_wordlist_path,
            max_web_paths=max_web_paths,
        )
        self._engine: PlanningEngine | None = None
        self._last_decision: PlanDecision | None = None
        if model_router is not None:
            from apex_host.planning.engine import PlanningEngine as _PE
            tools = allowed_tools if allowed_tools is not None else registry.available()
            self._engine = _PE(
                model_router=model_router,
                fallback_planner=self._core,
                allowed_tools=tools,
                target=target,
                confidence_threshold=confidence_threshold,
                max_retries=max_retries,
                budget=budget_tracker,
                guard=guard,
                gateway=gateway,
            )

    @property
    def last_decision(self) -> PlanDecision | None:
        """Most recent ``PlanDecision`` from the last ``plan()`` call."""
        if self._engine is not None:
            return self._engine.last_decision
        return self._last_decision

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        # Deterministic vhost override (§28.8): when a name-based virtual host
        # has been DISCOVERED for the target, the required next web action is a
        # fixed, safe, Host-aware `--resolve` fetch of that vhost — a decision
        # the LLM neither knows (it re-emits a bare-IP curl that only returns the
        # known redirect stub) nor should override. So bypass the engine/LLM
        # entirely and use the deterministic planner, which fetches the real app
        # under the vhost. No extra LLM call is made for this decision.
        if _WebDeterministic._select_vhost(subgraph) is not None:
            self._last_decision = PlanDecision(
                planner_model="deterministic",
                confidence=1.0,
                selected_task_count=0,
                rejected_task_count=0,
                reasoning_summary="vhost discovered — Host-aware --resolve fetch (deterministic override)",
                fallback_used=True,
                timestamp=now(),
                phase=ApexPhase.web.value,
            )
            return await self._core.plan(goal, subgraph, evidence)

        if self._engine is not None:
            return await self._engine.plan(goal, ApexPhase.web, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.web.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
