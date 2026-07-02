# test_preflight.py
# Tests for apex_host/tools/preflight.py covering PATH resolution and missing-tool detection.
from __future__ import annotations

import shutil

import pytest

from apex_host.config import ApexConfig
from apex_host.tools.preflight import check_local_tools


def test_returns_dict_keyed_by_allowed_tools() -> None:
    config = ApexConfig(target="127.0.0.1", allowed_tools=["nmap", "curl", "nc"])
    result = check_local_tools(config)
    assert set(result.keys()) == {"nmap", "curl", "nc"}


def test_python3_is_present() -> None:
    """python3 must always resolve on the test machine (it runs pytest)."""
    config = ApexConfig(target="127.0.0.1", allowed_tools=["python3"])
    result = check_local_tools(config)
    assert result["python3"] is True


def test_nonexistent_tool_is_false() -> None:
    config = ApexConfig(target="127.0.0.1", allowed_tools=["_apex_nonexistent_tool_xyz"])
    result = check_local_tools(config)
    assert result["_apex_nonexistent_tool_xyz"] is False


def test_all_values_are_bool() -> None:
    config = ApexConfig(target="127.0.0.1", allowed_tools=["python3", "_apex_missing_xyz"])
    result = check_local_tools(config)
    assert all(isinstance(v, bool) for v in result.values())


def test_empty_allowed_tools_returns_empty_dict() -> None:
    config = ApexConfig(target="127.0.0.1", allowed_tools=[])
    result = check_local_tools(config)
    assert result == {}


def test_result_agrees_with_shutil_which() -> None:
    """check_local_tools must agree with shutil.which for each tool."""
    tools = ["python3", "curl", "_apex_never_exists_xyz"]
    config = ApexConfig(target="127.0.0.1", allowed_tools=tools)
    result = check_local_tools(config)
    for tool in tools:
        expected = shutil.which(tool) is not None
        assert result[tool] == expected, f"Mismatch for {tool!r}"
