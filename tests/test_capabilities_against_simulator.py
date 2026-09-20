"""Cross-check config/capabilities.yaml against the starter kit's own tool
definitions, when the starter kit is present on disk next to this repo.
Guards against drift if a tool's consequential/prerequisite behaviour ever
changes after we transcribed this registry by hand. Skipped entirely (not
failed) when the starter kit isn't importable -- this is an integration
sanity check for our own development machine, not a hard dependency of the
defense itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from defense.capabilities import CapabilityRegistry

STARTER_KIT_SRC = Path.home() / "Sentinel_Starter_Kit" / "src"

if not STARTER_KIT_SRC.is_dir():
    pytest.skip("starter kit not found on disk; skipping drift check", allow_module_level=True)

if str(STARTER_KIT_SRC) not in sys.path:
    sys.path.insert(0, str(STARTER_KIT_SRC))

try:
    from sentinel.defenses.baselines.common import STATUS_CONSEQUENTIAL
    from sentinel.domains import DOMAIN_TOOLS
except Exception as exc:  # pragma: no cover - environment-dependent
    pytest.skip(f"starter kit present but not importable ({exc}); skipping drift check", allow_module_level=True)

ALL_SIMULATOR_TOOLS = {tool.name: tool for factory in DOMAIN_TOOLS.values() for tool in factory()}


def test_every_simulator_tool_is_registered() -> None:
    registry = CapabilityRegistry.load()
    missing = set(ALL_SIMULATOR_TOOLS) - set(registry.tools)
    assert not missing, f"capabilities.yaml is missing tools the simulator defines: {missing}"


def test_no_extra_tools_registered() -> None:
    registry = CapabilityRegistry.load()
    extra = set(registry.tools) - set(ALL_SIMULATOR_TOOLS)
    assert not extra, f"capabilities.yaml has tools the simulator does not define: {extra}"


def test_consequential_flag_matches_simulator_default() -> None:
    """For tools whose is_consequential does not depend on arguments, our
    static consequential: true|false must match the simulator's default."""
    registry = CapabilityRegistry.load()
    for name, tool in ALL_SIMULATOR_TOOLS.items():
        cap = registry.get(name)
        if cap.consequential_when:
            continue  # argument-dependent; checked separately below
        assert cap.is_consequential({}) == tool.is_consequential({}), name


def test_conditional_status_tools_match_simulator() -> None:
    registry = CapabilityRegistry.load()
    for tool_name, trigger_values in STATUS_CONSEQUENTIAL.items():
        cap = registry.get(tool_name)
        assert set(cap.consequential_when.get("status", [])) == set(trigger_values), tool_name
