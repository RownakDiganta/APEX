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
from urllib.parse import urlsplit

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
from apex_host.planners.web_opportunities import pending_enumerated_endpoints
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

#: Max discovered endpoints fetched per web turn (§28.13) — bounds the
#: loop-closing fetch step; each endpoint is fetched once (distinct URL →
#: distinct fingerprint), so the total is bounded by the enumeration result.
_MAX_ENDPOINT_FETCHES = 3

#: Fixed, GENERIC API-root path conventions probed for API-surface DISCOVERY
#: (§28.22) — like browser_planner's /robots.txt, these are generic REST
#: conventions, NOT machine-specific and NOT attack payloads. Probed with a
#: bounded curl HEAD + GET (read-only), once per phase; responsive roots become
#: endpoint nodes and JSON bodies are parsed into API structure.
_API_ROOT_PATHS: tuple[str, ...] = ("/api", "/api/v1", "/api/v2")

#: Fixed, generic GraphQL endpoint conventions. Probed like the API roots; if a
#: live GraphQL endpoint is discovered, ONE read-only introspection query
#: (schema READ, not an attack) is issued against it.
_GRAPHQL_PATHS: tuple[str, ...] = ("/graphql", "/api/graphql")

#: The one and only request body WebPlanner ever emits: a compact, FIXED,
#: read-only GraphQL introspection query (type + field names only — enough to
#: MAP the schema, never a mutation). A module constant, never task/LLM-derived,
#: and free of shell metacharacters so tools/safety.py passes it. This is the
#: sole permitted POST body (§28.22) — discovery only, no request forging.
_GRAPHQL_INTROSPECTION_BODY: str = (
    '{"query":"query{__schema{queryType{name} mutationType{name} '
    'types{name kind fields{name}}}}"}'
)

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
        web_enum_threads: int = 20,
        web_enum_max_seconds: int = 60,
        web_api_wordlist_path: str | None = None,
    ) -> None:
        self._target = target
        self._registry = registry
        self._wordlist = web_wordlist_path
        self._max_paths = max_web_paths
        self._enum_threads = web_enum_threads
        self._enum_max_seconds = web_enum_max_seconds
        self._api_wordlist = web_api_wordlist_path

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

        # Bounded content-enumeration (§28.12) — opt-in and once per phase.
        # Emitted only when a wordlist is configured AND no prior enumeration hit
        # already exists in the EKG (so a single bounded scan runs per phase, not
        # every turn). ONE tool is emitted — prefer ffuf (it has a hard --maxtime
        # ceiling), else gobuster. Both fuzz the AUTHORIZED IP URL (which resolves
        # in the container, so the target stays policy-approved) and, when a vhost
        # is known, carry `-H Host: <vhost>` so nginx serves the real app under
        # that vhost. Every scan is capped: concurrency (-t) and, for ffuf, a hard
        # wall-clock --maxtime; gobuster is additionally bounded by the runner's
        # subprocess timeout. DISCOVERY ONLY — hits are recorded as endpoint nodes.
        if self._wordlist and not self._enumeration_done(subgraph):
            host_header_args = (
                ["-H", f"Host: {vhost_node.props.get('hostname', '')}"]
                if vhost_node is not None
                else []
            )
            threads = str(max(1, self._enum_threads))
            maxtime = str(max(1, self._enum_max_seconds))
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
                                "-t", threads,
                                "-maxtime", maxtime,
                            ],
                            "target": ip_base_url,
                            "parser": "ffuf",
                        },
                        subgraph_anchor=goal.anchor_node,
                        phase=goal.phase,
                        claim_dependencies=web_claim_deps,
                    )
                )
            elif self._registry.get("gobuster") is not None:
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
                                "-t", threads,
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

        # ---- Bounded API-surface DISCOVERY (§28.22, §28.23) --------------
        # The web phase loads the linked app but cannot see an API surface it is
        # not linked to. Probe a FIXED, GENERIC set of API/GraphQL root
        # conventions (like browser_planner probes /robots.txt) — curl HEAD
        # (status) + GET (JSON structure), through the SAME Host-aware
        # --resolve -L path as the homepage fetch. Responsive roots become
        # endpoint nodes; JSON bodies are parsed into API structure.
        #
        # §28.23: DEFER until the base is settled — fire only when a vhost node
        # exists (→ probe the vhost via --resolve -L, so /api/v1 returns its real
        # JSON, not the bare-IP 301 stub) OR the homepage has been fetched
        # (confirming no vhost — the IP is the real app). The gate is host-aware
        # so a pre-vhost IP probe never blocks the vhost probe. DISCOVERY ONLY.
        base_host = self._url_host(base_url)
        if (
            self._registry.get("curl") is not None
            and (vhost_node is not None or self._homepage_fetched(subgraph))
            and not self._api_probe_done(subgraph, base_host)
        ):
            for path in (*_API_ROOT_PATHS, *_GRAPHQL_PATHS):
                probe_url = f"{base_url.rstrip('/')}{path}"
                tasks.append(self._curl_task(
                    goal, probe_url, "command",
                    ["-s", "-I", *follow_args, *resolve_args, probe_url], web_claim_deps))
                tasks.append(self._curl_task(
                    goal, probe_url, "curl_body",
                    ["-s", *follow_args, *resolve_args, probe_url], web_claim_deps))

        # Bounded API-path wordlist enumeration (§28.22) — extends the §28.12
        # ffuf/gobuster pattern with a SEPARATE operator-configured API wordlist
        # (web_api_wordlist_path). ONE bounded scan per phase, distinct provenance
        # (parser ffuf_api/gobuster_api) so it neither collides with nor
        # re-triggers the content-enum scan. Wordlist fuzzing still requires the
        # §19 allow_password_lists policy approval (enforced at the policy gate,
        # not here). Discovered API paths become endpoint nodes and are fetched.
        if self._api_wordlist and not self._api_enumeration_done(subgraph):
            api_host_header = (
                ["-H", f"Host: {vhost_node.props.get('hostname', '')}"]
                if vhost_node is not None else []
            )
            api_threads = str(max(1, self._enum_threads))
            api_maxtime = str(max(1, self._enum_max_seconds))
            if self._registry.get("ffuf") is not None:
                tasks.append(TaskSpec(
                    id=new_id(), goal_id=goal.id, executor_domain="web",
                    params={
                        "tool": "ffuf",
                        "args": ["-u", f"{ip_base_url}/FUZZ", "-w", self._api_wordlist,
                                 *api_host_header, "-mc", "200,301,302,403",
                                 "-t", api_threads, "-maxtime", api_maxtime],
                        "target": ip_base_url, "parser": "ffuf_api",
                    },
                    subgraph_anchor=goal.anchor_node, phase=goal.phase,
                    claim_dependencies=web_claim_deps,
                ))
            elif self._registry.get("gobuster") is not None:
                tasks.append(TaskSpec(
                    id=new_id(), goal_id=goal.id, executor_domain="web",
                    params={
                        "tool": "gobuster",
                        "args": ["dir", "-u", ip_base_url, "-w", self._api_wordlist,
                                 *api_host_header, "-t", api_threads, "-q", "--no-progress"],
                        "target": ip_base_url, "parser": "gobuster_api",
                    },
                    subgraph_anchor=goal.anchor_node, phase=goal.phase,
                    claim_dependencies=web_claim_deps,
                ))

        # GraphQL introspection (§28.22) — IF a live GraphQL endpoint was
        # discovered, issue the ONE fixed, read-only introspection query (a schema
        # READ, never a mutation; the sole POST body WebPlanner ever emits — a
        # module constant, never task/LLM-derived) and parse the returned
        # type/field names into schema nodes. Once per discovered endpoint.
        gql_ep = self._graphql_endpoint(subgraph)
        if (
            self._registry.get("curl") is not None
            and gql_ep is not None
            and not self._graphql_introspected(subgraph)
        ):
            gql_path = urlsplit(str(gql_ep.props.get("url", ""))).path or "/graphql"
            gql_url = f"{base_url.rstrip('/')}{gql_path}"
            tasks.append(self._curl_task(
                goal, gql_url, "graphql",
                ["-s", "-X", "POST", "-H", "Content-Type: application/json",
                 "-d", _GRAPHQL_INTROSPECTION_BODY, *follow_args, *resolve_args, gql_url],
                web_claim_deps))

        # Fetch discovered-but-unfetched enumeration endpoints (§28.13) — close
        # the loop: homepage → enumerate → FETCH what enumeration found. Each is
        # fetched via the same Host-aware --resolve -L path as the homepage
        # (highest-signal first), HEAD + body, once per endpoint (distinct URL →
        # distinct fingerprint), bounded to _MAX_ENDPOINT_FETCHES per turn.
        # DISCOVERY ONLY — fetch and record; no form submission or request forging.
        if self._registry.get("curl") is not None:
            for ep in pending_enumerated_endpoints(subgraph)[:_MAX_ENDPOINT_FETCHES]:
                path = urlsplit(str(ep.props.get("url", ""))).path or "/"
                fetch_url = f"{base_url.rstrip('/')}{path}"
                tasks.append(
                    TaskSpec(
                        id=new_id(), goal_id=goal.id, executor_domain="web",
                        params={
                            "tool": "curl",
                            "args": ["-s", "-I", *follow_args, *resolve_args, fetch_url],
                            "target": fetch_url, "parser": "command",
                        },
                        subgraph_anchor=goal.anchor_node, phase=goal.phase,
                        claim_dependencies=web_claim_deps,
                    )
                )
                tasks.append(
                    TaskSpec(
                        id=new_id(), goal_id=goal.id, executor_domain="web",
                        params={
                            "tool": "curl",
                            "args": ["-s", *follow_args, *resolve_args, fetch_url],
                            "target": fetch_url, "parser": "curl_body",
                        },
                        subgraph_anchor=goal.anchor_node, phase=goal.phase,
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
        # §28.23 — a fixed API-root probe and the §28.13 fetch loop can emit an
        # IDENTICAL fetch for an overlapping path (e.g. a discovered /api and the
        # fixed /api probe both → the same vhost URL). Drop exact-duplicate curl
        # actions (same tool+args+target+parser) within this turn, keeping the
        # first — the dispatcher would dedup them by fingerprint anyway, but the
        # planner should not emit the same action twice.
        deduped: list[TaskSpec] = []
        seen: set[tuple[str, tuple[str, ...], str, str]] = set()
        for t in tasks:
            key = (
                str(t.params.get("tool", "")),
                tuple(str(a) for a in t.params.get("args", [])),
                str(t.params.get("target", "")),
                str(t.params.get("parser", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(t)
        return deduped

    @staticmethod
    def _enumeration_done(subgraph: SubgraphView) -> bool:
        """True once a content-enumeration scan has already produced endpoints
        (an ``endpoint`` node whose provenance is ffuf/gobuster). Gates the scan
        to ONCE per phase — a stateless, blackboard-only check (reads the
        subgraph), never a stored flag."""
        return any(
            n.type == "endpoint" and n.source in ("ffuf", "gobuster")
            for n in subgraph.nodes
        )

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

    # ------------------------------------------------------------------
    # API-surface DISCOVERY helpers (§28.22) — pure, blackboard-only
    # ------------------------------------------------------------------

    def _curl_task(
        self, goal: Goal, url: str, parser: str, args: list[str],
        web_claim_deps: "tuple[ClaimDependency, ...]",
    ) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="web",
            params={"tool": "curl", "args": args, "target": url, "parser": parser},
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
            claim_dependencies=web_claim_deps,
        )

    @staticmethod
    def _endpoint_path(url: str) -> str:
        try:
            return (urlsplit(url).path or "/").rstrip("/") or "/"
        except ValueError:
            return "/"

    @staticmethod
    def _url_host(url: str) -> str:
        try:
            return (urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""

    @classmethod
    def _api_probe_done(cls, subgraph: SubgraphView, base_host: str) -> bool:
        """True once the fixed API/GraphQL root set has been probed AGAINST
        *base_host* — an ``endpoint`` node at an API/GraphQL-convention path whose
        URL host equals *base_host* (§28.23).

        Host-aware on purpose: a pre-vhost bare-IP probe (turn 1, before the vhost
        is discovered) creates IP-scoped 301 stubs at ``/api`` etc. Those must NOT
        satisfy the gate for the vhost base — otherwise the API roots are never
        re-probed through the vhost ``--resolve -L`` GET path once the vhost is
        known, and the real JSON is never fetched. Stateless/blackboard-only."""
        conventions = set(_API_ROOT_PATHS) | set(_GRAPHQL_PATHS)
        return any(
            n.type == "endpoint"
            and cls._endpoint_path(str(n.props.get("url", ""))) in conventions
            and cls._url_host(str(n.props.get("url", ""))) == base_host
            for n in subgraph.nodes
        )

    @staticmethod
    def _homepage_fetched(subgraph: SubgraphView) -> bool:
        """True once the homepage (root-path ``endpoint``) has been fetched — the
        signal that the base is SETTLED (a vhost has been discovered if one
        exists, or the redirect-free IP is confirmed to be the real app). Used to
        DEFER the API-root probes past turn 1 so they never fire prematurely
        against the bare IP (§28.23)."""
        return any(
            n.type == "endpoint"
            and n.props.get("fetched") is True
            and (urlsplit(str(n.props.get("url", ""))).path or "/").rstrip("/") in ("", "/")
            for n in subgraph.nodes
        )

    @staticmethod
    def _api_enumeration_done(subgraph: SubgraphView) -> bool:
        """True once the API-wordlist scan has produced endpoints (provenance
        ffuf_api/gobuster_api) — gates that scan to once per phase, independent
        of the content-enum scan (source ffuf/gobuster)."""
        return any(
            n.type == "endpoint" and n.source in ("ffuf_api", "gobuster_api")
            for n in subgraph.nodes
        )

    @classmethod
    def _graphql_endpoint(cls, subgraph: SubgraphView) -> Node | None:
        """The highest-confidence LIVE (non-404) ``endpoint`` whose URL path is a
        GraphQL convention, or None. Deterministic tie-break by URL."""
        gql = [
            n for n in subgraph.nodes
            if n.type == "endpoint"
            and cls._endpoint_path(str(n.props.get("url", ""))) in set(_GRAPHQL_PATHS)
            and str(n.props.get("status", "")).strip() != "404"
        ]
        if not gql:
            return None
        return sorted(gql, key=lambda n: (-float(n.confidence), str(n.props.get("url", ""))))[0]

    @staticmethod
    def _graphql_introspected(subgraph: SubgraphView) -> bool:
        """True once a GraphQL schema has been recorded (an ``api_schema`` node) —
        gates introspection to once per discovered endpoint."""
        return any(n.type == "api_schema" for n in subgraph.nodes)


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
        web_enum_threads: int = 20,
        web_enum_max_seconds: int = 60,
        web_api_wordlist_path: str | None = None,
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
            web_enum_threads=web_enum_threads,
            web_enum_max_seconds=web_enum_max_seconds,
            web_api_wordlist_path=web_api_wordlist_path,
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
