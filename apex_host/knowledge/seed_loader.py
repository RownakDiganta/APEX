# seed_loader.py
# Bootstrap helper that loads the payload repository into staged knowledge and immediately runs one Reflector promotion pass before engagement starts.
"""Bootstrap helper: load the payload repo, then run one Reflector pass so the
staged entries clear the promotion gate before the engagement starts.

This does not bypass the staging gate (memfabric Invariant 4) — it simply
drives the same ``ReflectorWorker.run_once()`` promotion path that runs on
the worker's normal schedule, once, synchronously, at startup.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from apex_host.knowledge.payload_repo_loader import PayloadRepoLoader
from memfabric.reflector.worker import ReflectorWorker

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.config import Config


async def seed_payload_repo(
    payload_repo_path: str, api: "MemoryAPI", config: "Config"
) -> int:
    """Load *payload_repo_path* into staged knowledge and run one promotion pass.

    Returns the number of chunks proposed (promotion count may differ if some
    entries don't clear the gate).
    """
    loader = PayloadRepoLoader(payload_repo_path, api)
    count = await loader.load()
    if count:
        worker = ReflectorWorker(api, config)
        await worker.run_once()
    return count
