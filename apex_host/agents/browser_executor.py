# browser_executor.py
# Browser-phase executor that drives Playwright in live mode and returns a synthetic observation in dry-run mode.
"""Browser-phase executor. Implements memfabric.coordination.protocols.Executor.

Playwright is only ever invoked when ``config.dry_run`` is False; in
dry-run mode (the default) a synthetic BrowserObservation is returned and no
browser process is launched. Stateless across tasks: a fresh Playwright
instance/browser/page is created and torn down inside ``run()`` — nothing is
held on ``self`` between calls (memfabric Invariant 6).

In live mode the executor uses JavaScript evaluation to collect:
- page title
- form metadata (action, method, named input fields)
- hidden-input / meta token names matching csrf/token/nonce patterns
- up to 50 same-origin anchor links
- an auth_hint if a password-type input exists

All collected data is stored in ``episode.data["obs"]`` as a plain
JSON-serialisable dict. Parsing into EKG node/edge deltas is intentionally
deferred to ``parse_observation`` in ``apex_host/graph.py`` — consistent
with every other executor/parser pair in this codebase (memfabric Invariant 1).
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from memfabric.types import EvidenceBundle, Episode, ExecutorResult, Outcome, TaskSpec

from apex_host.types import BrowserObservation

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

# ---------------------------------------------------------------------------
# JavaScript snippets evaluated inside the live Playwright page
# ---------------------------------------------------------------------------

_JS_FORMS = """
Array.from(document.forms).map(f => {
    const els = Array.from(f.elements).filter(el => el.name);
    return {
        action: f.action || '',
        method: (f.method || 'GET').toUpperCase(),
        fields: els.map(el => el.name),
        field_types: Object.fromEntries(
            els.map(el => [el.name, (el.type || 'text').toLowerCase()])
        ),
    };
})
""".strip()

_JS_TOKENS = """
(() => {
    const re = /csrf|token|nonce|_token/i;
    const names = new Set();
    document.querySelectorAll('input[type="hidden"]').forEach(el => {
        if (el.name && re.test(el.name)) names.add(el.name);
    });
    document.querySelectorAll('meta[name]').forEach(el => {
        if (re.test(el.name)) names.add(el.name);
    });
    return Array.from(names);
})()
""".strip()

_JS_LINKS = """
Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter(h => h.startsWith('http'))
    .slice(0, 50)
""".strip()

_JS_HAS_PASSWORD = (
    "document.querySelector('input[type=\"password\"]') !== null"
)

_JS_HAS_FAVICON = (
    "document.querySelector('link[rel~=\"icon\"]') !== null"
)


class BrowserExecutor:
    domain: str = "browser"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        url = str(task.params.get("url", task.params.get("target", self._config.target)))
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        try:
            if self._config.dry_run:
                obs = self._synthetic_observation(url)
            else:
                obs = await self._real_observation(url)
        except Exception as exc:  # noqa: BLE001 — Playwright failures are fundamental
            episode = Episode(
                agent=self.domain,
                action=f"browse {url}",
                outcome=Outcome.fundamental,
                data={"url": url, "error": str(exc)},
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)

        obs_dict: dict[str, Any] = {
            "url": obs.url,
            "title": obs.title,
            "forms": obs.forms,
            "tokens": obs.tokens,
            "auth_hints": obs.auth_hints,
            "links": obs.links,
            # Phase 14 additions — see apex_host/types.py::BrowserObservation
            # for the "no secret leakage" rationale on cookies/headers.
            "html_snippet": obs.html_snippet,
            "status": obs.status,
            "headers": obs.headers,
            "cookies": obs.cookies,
            "final_url": obs.final_url,
            "favicon_present": obs.favicon_present,
        }
        episode = Episode(
            agent=self.domain,
            action=f"browse {url}",
            outcome=Outcome.success,
            data={
                "url": url,
                "dry_run": self._config.dry_run,
                "title": obs.title,
                "obs": obs_dict,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    def _synthetic_observation(self, url: str) -> BrowserObservation:
        """Plausible login-page snapshot — no network, safe in dry-run mode.

        Deliberately unremarkable beyond the pre-existing login-form/CSRF
        signal this fixture has always carried: no fabricated technology
        header, no fabricated backup file, no fabricated directory listing —
        a dry-run engagement demonstrates the full parsing/opportunity
        pipeline without manufacturing findings that didn't come from a
        real page (mirrors the same discipline Phase 13B's
        ``PrivEscEnumExecutor`` dry-run output follows).
        """
        return BrowserObservation(
            url=url,
            html_snippet="<html><body><!-- dry-run: no real page fetched --></body></html>",
            title="(dry-run) Login",
            forms=[{
                "action": "/login", "method": "POST",
                "fields": ["username", "password"],
                "field_types": {"username": "text", "password": "password"},
            }],
            tokens=["csrf_token"],
            auth_hints=["password-field"],
            links=[f"{url}/login", f"{url}/admin"],
            status="200",
            headers={"Server": "(dry-run)"},
            cookies=[{"name": "session_id", "http_only": True, "secure": False}],
            final_url="",
            favicon_present=False,
        )

    async def _real_observation(self, url: str) -> BrowserObservation:
        from playwright.async_api import async_playwright  # lazy import: optional dep

        timeout_ms = self._config.max_command_seconds * 1000
        # P7-I05 / A09: browser.launch() needs an explicit timeout; without one
        # a hung browser process stalls the event loop indefinitely.
        launch_timeout = float(
            getattr(self._config, "browser_launch_timeout_seconds", 30.0)
        )
        async with async_playwright() as playwright:
            browser = await asyncio.wait_for(
                playwright.chromium.launch(),
                timeout=launch_timeout,
            )
            try:
                page = await browser.new_page()
                response = await page.goto(url, timeout=timeout_ms)
                title = await page.title()
                html = await page.content()
                forms: list[dict[str, Any]] = await page.evaluate(_JS_FORMS)
                tokens: list[str] = await page.evaluate(_JS_TOKENS)
                links: list[str] = await page.evaluate(_JS_LINKS)
                has_password: bool = await page.evaluate(_JS_HAS_PASSWORD)
                has_favicon: bool = await page.evaluate(_JS_HAS_FAVICON)
                raw_cookies = await page.context.cookies()
                final_url = page.url
                status = str(response.status) if response is not None else ""
                headers: dict[str, str] = dict(response.headers) if response is not None else {}
            finally:
                await browser.close()

        auth_hints: list[str] = ["password-field"] if has_password else []
        # Cookie NAME/flags only — never the value (P8-S06-style secret
        # discipline: a session cookie value is credential-shaped material).
        cookies: list[dict[str, Any]] = [
            {
                "name": str(c.get("name", "")),
                "http_only": bool(c.get("httpOnly", False)),
                "secure": bool(c.get("secure", False)),
            }
            for c in raw_cookies
        ]
        return BrowserObservation(
            url=url,
            html_snippet=html[:2000],
            title=title,
            forms=forms,
            tokens=tokens,
            auth_hints=auth_hints,
            links=links,
            status=status,
            headers=headers,
            cookies=cookies,
            final_url=final_url if final_url and final_url != url else "",
            favicon_present=bool(has_favicon),
        )
