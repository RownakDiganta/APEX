# Web Exploitation Planning & Browser Reasoning (Phase 14)

**Status:** implemented. Transforms the browser subsystem from a
single-page, hardcoded-URL executor into an intelligent planning
component: structured page/form/technology observations, a session model
that never revisits an identical page, deterministic technology detection,
and structured web opportunities for a human operator to review.

## 1. What this is — and is not

This is a **reasoning framework, not a web exploitation tool.** The browser
subsystem now organizes what it has observed (pages, forms, technologies,
links), tracks what it has already inspected so it never repeats itself,
and surfaces structured, non-executable "you might want to look at this"
opportunities. It never submits a form, never injects a payload, never
performs SQL injection, XSS, or CSRF, never uploads a file, and never
attempts to log in or bypass authentication.

Before this phase, `browser_agent` hardcoded `state["target"]` as the URL
to visit on **every single turn** — a second browser turn could only ever
re-request an already-completed fingerprint and be silently
duplicate-skipped by the generic `TaskDispatcher` gate. There was no
technology detection, no structured opportunity model, and discovered
links were captured in the episode but never turned into EKG data a future
turn could act on. Phase 14 fixes all of this by introducing a real
`BrowserPlanner`.

## 2. Design decision — reuse existing node types, don't fragment the graph

The task's suggested graph shape (`host → web_page → form → technology →
web_opportunity`) is implemented using the **existing, already-pervasive**
node types rather than introducing competing ones:

| Suggested label | Actual EKG node type used | Why |
|---|---|---|
| `web_page` | `endpoint` | `endpoint` is already produced by `NmapParser`, `CommandParser`, `FfufParser`, `GobusterParser`, and the pre-Phase-14 `BrowserParser` — for the same real-world concept (an HTTP URL). `GlobalPlanner.decide_phase` and `capabilities.py` already gate phase transitions on `endpoint` node presence. Introducing a second, parallel `web_page` type would fragment every consumer that already reasons about endpoints. |
| `technology` | `tech` | Same reasoning — `tech` nodes already exist (nmap version strings, `curl -I` Server headers). Phase 14's technology detector writes to the same node type, just via new detection channels. |
| `web_opportunity` | `web_opportunity` (new) | No existing node type captured "a non-executable, human-actionable web finding" — this is the one genuinely new node type, mirroring `priv_esc_opportunity` from Phase 13 exactly. |

`form` was already a distinct node type (Phase 12's `BrowserParser`) and is
unchanged in kind, only enriched with new props (see §4).

## 3. Browser reasoning — structured observations

`BrowserObservation` (`apex_host/types.py`) gained five fields, all
additive — no existing caller (real or test) that only sets the original
seven fields is affected:

| Field | Purpose |
|---|---|
| `status` | HTTP response status code |
| `headers` | Full response headers (raw; only a safe allowlist is ever persisted to the EKG — see §6) |
| `cookies` | `[{"name", "http_only", "secure"}]` — **never a cookie value** |
| `final_url` | Set only when a live fetch followed a redirect chain that landed somewhere different from the requested `url` |
| `favicon_present` | Whether a `<link rel="icon">` was found |

`BrowserExecutor` (`apex_host/agents/browser_executor.py`) collects all of
this in live mode via Playwright (`response.status`, `response.headers`,
`page.context.cookies()`, `page.url` vs. the requested URL, a
`document.querySelector('link[rel~="icon"]')` check) and returns a
deliberately unremarkable synthetic equivalent in dry-run mode — the
synthetic observation never fabricates an "interesting" technology header,
backup file, or directory listing, so a dry-run engagement demonstrates the
full parsing/opportunity pipeline without manufacturing a finding that
didn't come from a real page (same discipline Phase 13B's
`PrivEscEnumExecutor` dry-run output follows).

`html_snippet` (already existed) now actually flows all the way through
`episode.data["obs"]["html_snippet"]` to `parse_observation` — previously
it was hardcoded to `""` in `apex_host/orchestration/parsing_node.py`,
which silently meant no HTML-based technology/opportunity detection could
ever fire through the real pipeline. This is fixed.

Forms (`_JS_FORMS` in `browser_executor.py`) now also capture each field's
`type` attribute (`field_types: {name: type}`) alongside the existing
`fields` name list — additive, so any code that only reads `fields` is
unaffected; `field_types` absent or empty degrades gracefully to the
pre-existing name-based heuristics.

## 4. Session model — never revisit an identical page

There is no separate, in-memory "browser session" object (that would
violate memfabric Invariant 6 — executors are stateless). Instead, the
session model is a **view reconstructed from the EKG** each turn:

- **Visited pages**: an `endpoint` node's `browsed` prop is `True` only
  when a browser navigation (real or synthetic) actually produced that
  page — set exclusively by `BrowserParser.parse_observation()`. Endpoint
  nodes discovered only as links (not yet visited) have `browsed=False`.
  `apex_host.planners.web_opportunities.visited_urls_from_subgraph()`
  reconstructs the visited set.
- **Discovered-but-unvisited pages**: `BrowserParser` now also creates
  `endpoint` nodes (bounded at 20, mirroring `CommandParser.parse_curl_body`'s
  own 20-link cap) from `obs.links` — **same-origin only** (a different
  host is never turned into a candidate; the browser must never be planned
  to navigate off-target based on a discovered external link).
  `select_unvisited_endpoints()` returns these, ranked deterministically:
  interesting-keyword priority (`admin`/`login`/`api`/... first), then path
  depth, then URL alphabetically — never random, never insertion-order.
- **Redirects**: recorded as `final_url` on the endpoint node when
  different from the requested `url` — the requested URL remains the
  node's identity, so redirect tracking never disturbs visited-URL dedup.
- **Cookies**: recorded as `cookie_names` (names only) on the endpoint node.
- **Login state**: `WebSessionState.login_state` is `"authenticated"` when
  an `access_state` node exists for the target — the exact same success
  signal every other phase already uses, never a second, independent
  notion of "logged in".
- **Forms already inspected**: implied by page-level dedup — a form is
  inspected exactly when its containing page is browsed, and pages are
  visited at most once (their form IDs are content-addressed on
  `url:index`, so re-observing the same page upserts the same form node
  rather than duplicating it).

### `BrowserPlanner` — visit priority

`apex_host/planners/browser_planner.py` follows the same
`_<Name>Deterministic` + thin-wrapper convention as every other domain
planner (CLAUDE.md §15.2). Priority order per turn (exactly one page
visited per turn, bounded):

1. The base URL (derived from the highest-confidence `web_probe`
   capability — the SAME logic `WebPlanner` already uses, so the browser
   inspects the same site WebPlanner found, not a hardcoded port).
2. `{base}/robots.txt` — parsed for `Disallow:` entries (see §5).
3. `{base}/sitemap.xml`.
4. The highest-priority same-origin discovered-but-unvisited endpoint.

Once every known candidate has been visited, the planner returns an
explicit `AbandonSignal` instead of silently re-requesting an
already-visited page (which the generic `TaskDispatcher` duplicate gate
would only catch after the fact, wasting a turn).

`apex_host/orchestration/dispatch_node.py::make_browser_node` was
rewritten from a hand-rolled, single-hardcoded-URL dispatch into a thin
node that calls `_dispatch_tasks(deps, state, deps.phase_planners["browser"],
single_task=True)` — the same shared dispatch helper every other phase
agent uses. `"browser"` is registered in `build_planners()`'s returned
dict alongside the four `ApexPhase`-keyed planners (it is not itself an
`ApexPhase` — `browser_agent` and `web_agent` are two different graph
nodes that both execute during the `web` phase; see
`apex_host/orchestration/routing.py`).

## 5. Technology detection — deterministic, no fingerprinting tool

`apex_host/parsers/tech_detector.py` is pure (no I/O, no network, no
WhatWeb/Wappalyzer/nmap `-sV` script) and detects from three channels,
merged with the highest-confidence match per technology name winning:

| Channel | Confidence | Covers |
|---|---|---|
| HTTP headers | 0.85 | Apache/nginx/IIS/Werkzeug(Flask) via `Server`; PHP/ASP.NET/Express via `X-Powered-By`; ASP.NET via `X-AspNet-Version`; PHP/ASP.NET/Django/Express via `Set-Cookie` name **patterns only** (never the cookie value — see §6); Drupal via `X-Generator` |
| HTML markers | 0.6 | WordPress (`wp-content`/`wp-includes`/generator meta), Joomla (`/components/com_`/generator meta), Drupal (`sites/default/files`/generator meta), Django (`csrfmiddlewaretoken`) |
| URL patterns | 0.4 | PHP (`.php`), ASP.NET (`.aspx`), WordPress (`/wp-admin`, `/wp-login.php`), Joomla (`/administrator`) |

`BrowserParser` calls `detect_technologies()` on every page visit and
writes one host-scoped `tech` node per finding (`apex_host/graph_ids.py::tech_id`
— unchanged builder, shared with nmap/curl-header detection), linked via a
`runs` edge from the endpoint.

## 6. Secret handling — no leakage into the EKG

Two deliberate redaction points, both caught and fixed during this phase's
own test-writing (a `Set-Cookie` value initially leaked into a `tech`
node's evidence excerpt before the fix below):

1. **Endpoint `headers` prop is an allowlist, not the raw dict.** Only
   `server`, `x-powered-by`, `content-type`, `x-aspnet-version`, and
   `x-generator` are ever copied onto the persisted `endpoint` node —
   `Set-Cookie` (and any other header) is excluded outright, since a
   session/CSRF cookie value is credential-shaped material.
2. **`tech_detector`'s Set-Cookie-derived findings never store the raw
   header.** The `TechFinding.excerpt` for a cookie-name-pattern match
   (e.g. `PHPSESSID`, `csrftoken`) is a fixed, redacted description like
   `"Set-Cookie name pattern: PHPSESSID"` — never `set_cookie[:200]`,
   which would have embedded the actual session value.
3. **Cookies on the endpoint node are name-only** (`cookie_names: list[str]`)
   — `BrowserExecutor` itself never even collects the `value` field from
   Playwright's `page.context.cookies()` into the observation.

## 7. Opportunity generation

`WebOpportunityCategory` (`apex_host/types.py`): `authentication_portal`,
`admin_panel`, `upload_functionality`, `search_functionality`,
`directory_listing`, `api_endpoint`, `robots_entry`, `backup_file`,
`default_page`, plus `none` (reserved).

Derived inline inside `BrowserParser.parse_observation()` from the facts it
already has for that one page visit (mirrors
`apex_host/parsers/priv_esc_parser.py`'s `_opportunities_from_facts` style
— colocated with the parsing logic that already extracted the raw facts,
not a second subgraph-wide pass):

| Trigger | Category | Confidence |
|---|---|---|
| Form with a password-type field | `authentication_portal` | high |
| URL path matches admin/administrator/manage/dashboard/cpanel | `admin_panel` | medium |
| Form with a file-type field | `upload_functionality` | medium |
| Form with a search-type field or `/search` action | `search_functionality` | low |
| Title/body matches `"Index of /"` | `directory_listing` | high |
| URL matches `/api/`, `/v1/`, `/graphql`, `.json` | `api_endpoint` | low |
| Discovered link matches a backup-file extension (`.bak`/`.old`/`.zip`/`.sql`/`~`/...) | `backup_file` | medium |
| `robots.txt` `Disallow:` entry (one opportunity per path, bounded at 10) | `robots_entry` | low |
| Title/body matches a known default-install-page marker (Apache/nginx/IIS default page) | `default_page` | low |

Every opportunity is content-addressed
(`apex_host/graph_ids.py::web_opportunity_id(target, category,
discriminator)`) so re-observing the same page/link/marker upserts the
same node rather than creating a duplicate — no separate "already
recorded" check is needed the way Phase 13's `PrivEscPlanner` needs one,
because the opportunity ID itself is stable and idempotent.

`recommended_next_action` is always **advisory text for a human
operator** — e.g. *"Manually review the authentication mechanism at this
URL; APEX does not attempt to log in or bypass authentication
automatically"* — never an executable command or payload.

## 8. Graph shape

```
host --exposes--> endpoint --contains--> form
                  endpoint --contains--> endpoint (discovered link, browsed=False)
                  endpoint --contains--> token
                  endpoint --requires--> auth_flow
                  endpoint --runs-----> tech
                  endpoint --indicates--> web_opportunity
```

The `host → endpoint` `exposes` edge (new in this phase) is load-bearing,
not cosmetic — without it, browser-visited endpoint nodes would be
orphans, invisible to `MemoryAPI.get_subgraph()`'s bounded host-anchored
traversal, which would silently break both `BrowserPlanner`'s own
visited-page dedup check and the report's page/opportunity counts. This
was caught and fixed during this phase's own test-writing (mirrors the
identical class of bug Phase 13 hit and fixed for `priv_esc_opportunity`
nodes — see `docs/privilege-escalation-planning.md` §9).

## 9. Reporting

`RunReport` gains a "Web Summary" section, shown only when at least one
page was visited:

```
Web Summary
  Pages visited        : 4
  Forms discovered     : 2
  Technologies detected: nginx, PHP
  Authentication portals: 1
  Potential opportunities: 3 (admin_panel=1, authentication_portal=1, backup_file=1)
  Duplicate pages avoided: 0
  Recommendations:
    Manually review the authentication mechanism at this URL...
```

| Field | Derivation |
|---|---|
| `web_pages_visited` | `len(visited_urls_from_subgraph(final_subgraph))` |
| `web_forms_discovered` | Count of `form` nodes in the final subgraph |
| `web_technologies_detected` / `web_technology_names` | `technologies_from_subgraph(final_subgraph)` |
| `web_authentication_portals` | Opportunity count for category `authentication_portal` |
| `web_opportunity_count` / `web_opportunity_categories` | `rank_opportunities(opportunities_from_subgraph(final_subgraph))` |
| `web_duplicate_pages_avoided` | Count of `state["duplicate_actions"]` entries with `tool == "browser"` — a real, observed count of browse tasks the dispatcher's fingerprint gate prevented from executing a second time |

Like the Phase 13/13B privilege-escalation fields, every field except
`web_duplicate_pages_avoided` (no EKG representation — a duplicate-skipped
browse task produces no node) is derived directly from the **final**
subgraph at report-build time, never from the possibly-one-turn-stale
`ApexGraphState["web_session_state"]` snapshot. `to_json_dict()` gains a
`"web_planning"` block with the same fields.

## 10. Tests

`tests/apex_host/test_phase14_web_planning.py` (95 tests) covers:
technology detection (headers/HTML/URL channels, merge/dedup,
deterministic ordering), form parsing (login/upload/search/CSRF detection
via both typed fields and the name-heuristic fallback), the session model
(browsed flag, same-origin link filtering, bounded link count, safe
header/cookie handling), opportunity generation (all nine categories,
robots.txt parsing and bounding, deterministic IDs), `BrowserPlanner`
(visit priority, never-revisit dedup, capability-derived base URL,
exhaustion), full `MemoryAPI` integration (graph link reachability,
upsert-not-duplicate, transaction rollback on a dangling edge, no secret
leakage), report generation (all Web Summary fields, text/JSON output),
and static no-exploitation scans (no Metasploit/sqlmap/XSS-payload/reverse-
shell references, no network-write calls in the parser, no shell
metacharacters in any recommendation text).

Two pre-existing tests were updated to reflect this phase's own,
deliberate behavior changes (not weakened — both now assert the new,
intentional design): `test_browser_executor.py`'s dry-run→endpoint-node
test now expects the visited page plus its discovered-but-unvisited link
endpoints (previously asserted exactly one endpoint, before link-endpoint
creation existed); `test_phase10_orchestration.py`'s `build_planners()`
key-set test now includes the new `"browser"` entry.

## 11. Current limitations

- **No live enumeration beyond passive browsing.** The browser never
  submits a form, never follows a login flow, never attempts SQL
  injection/XSS/CSRF testing, never fuzzes parameters. This is a
  deliberate, documented scope boundary, not an oversight — mirrors Phase
  13's "no new live enumeration" precedent exactly, just for the web
  surface instead of the shell surface.
- **Technology detection is a fixed, non-configurable list.** Apache,
  nginx, IIS, PHP, ASP.NET, Django, Flask, Express, WordPress, Joomla,
  Drupal only — no plugin/version-fingerprint database, no CVE
  correlation (that remains `apex_host/knowledge/`'s compiled intel corpus,
  a separate system).
- **`robots.txt`/`sitemap.xml` are visited like any other page** (no
  dedicated XML sitemap parser) — `sitemap.xml`'s content is not parsed
  for `<loc>` entries in this phase; only `robots.txt`'s `Disallow:` lines
  are.
- **One page per turn.** Mirrors the pre-Phase-14 "one browse action per
  turn" behavior deliberately — bounded, deterministic pacing, not a
  missed optimization.
- **`web_duplicate_pages_avoided` has no EKG representation** (a
  duplicate-skipped task produces no node at all), so it is derived from
  `state["duplicate_actions"]` rather than graph data, unlike every other
  field in the reporting section.
- **No new live command execution, no form submission, no payload of any
  kind was added or performed.** `access_state` remains the engagement's
  only success signal — this phase adds structured, read-only web
  reconnaissance and reasoning around it, nothing more.
