"""Browser-phase executor. Implements memfabric.coordination.protocols.Executor.

Playwright is only ever invoked when ``config.dry_run`` is False; in
dry-run mode (the default) a synthetic BrowserObservation is returned and no
browser process is launched. Stateless across tasks: a fresh Playwright
instance/browser/page is created and torn down inside run() — nothing is
held on self between calls (memfabric Invariant 6).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.types import EvidenceBundle, Episode, ExecutorResult, Outcome, TaskSpec

from apex_host.parsers.browser_parser import BrowserParser
from apex_host.types import BrowserObservation

if TYPE_CHECKING:
    from apex_host.config import ApexConfig


class BrowserExecutor:
    domain: str = "browser"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config
        self._parser = BrowserParser()

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        url = str(task.params.get("url", task.params.get("target", self._config.target)))

        try:
            if self._config.dry_run:
                obs = self._synthetic_observation(url)
            else:
                obs = await self._real_observation(url)
        except Exception as exc:  # noqa: BLE001 - any Playwright failure is a fundamental outcome
            episode = Episode(
                agent=self.domain,
                action=f"browse {url}",
                outcome=Outcome.fundamental,
                data={"url": url, "error": str(exc)},
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)

        parsed = self._parser.parse_observation(obs, target=url, source=self.domain)
        episode = Episode(
            agent=self.domain,
            action=f"browse {url}",
            outcome=Outcome.success,
            data={"url": url, "dry_run": self._config.dry_run, "title": obs.title},
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(
            task_id=task.id,
            episode=episode,
            node_deltas=parsed.node_deltas,
            edge_deltas=parsed.edge_deltas,
        )

    def _synthetic_observation(self, url: str) -> BrowserObservation:
        return BrowserObservation(
            url=url,
            html_snippet="<html><!-- dry-run: no real page was fetched --></html>",
            title="(dry-run)",
        )

    async def _real_observation(self, url: str) -> BrowserObservation:
        from playwright.async_api import async_playwright  # lazy import: optional dep

        timeout_ms = self._config.max_command_seconds * 1000
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page()
                await page.goto(url, timeout=timeout_ms)
                title = await page.title()
                html = await page.content()
            finally:
                await browser.close()
        return BrowserObservation(url=url, html_snippet=html[:2000], title=title)
