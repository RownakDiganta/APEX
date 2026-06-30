"""Concurrency-capped task dispatcher.

Rules:
- At most ``cap`` tasks run concurrently; excess queue.
- Tasks with disjoint ``subgraph_anchor``s may run in parallel.
- Results are gathered as tasks complete and returned in completion order.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Callable, Coroutine, Any

from memfabric.types import ExecutorResult, TaskSpec

logger = logging.getLogger(__name__)


class Scheduler:
    """Concurrency-capped coroutine dispatcher.

    Parameters
    ----------
    cap:
        Maximum number of concurrently running tasks.  Defaults to
        ``min(max(1, os.cpu_count() - 2), config.max_concurrency)``.
    """

    def __init__(self, cap: int) -> None:
        self._cap = max(1, cap)
        self._semaphore = asyncio.Semaphore(self._cap)

    @property
    def cap(self) -> int:
        return self._cap

    async def dispatch(
        self,
        tasks: list[TaskSpec],
        run: Callable[[TaskSpec], Coroutine[Any, Any, ExecutorResult]],
    ) -> list[ExecutorResult]:
        """Run *tasks* through *run* with the configured concurrency cap.

        Returns results in completion order (not submission order).
        """
        if not tasks:
            return []

        results: list[ExecutorResult] = []
        lock = asyncio.Lock()

        async def _run_one(task: TaskSpec) -> None:
            async with self._semaphore:
                logger.debug("scheduler: start task=%s", task.id)
                result = await run(task)
                logger.debug("scheduler: done  task=%s", task.id)
                async with lock:
                    results.append(result)

        await asyncio.gather(*[_run_one(t) for t in tasks])
        return results

    @classmethod
    def from_config(cls, max_concurrency: int) -> "Scheduler":
        cpu = os.cpu_count() or 2
        cap = min(max(1, cpu - 2), max_concurrency)
        return cls(cap=cap)
