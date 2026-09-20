"""Capability registry (F1): per-tool metadata loaded from config/capabilities.yaml.

Stage 2 and stage 3 read irreversibility, sinks, prerequisites, and approval
requirements from here -- never infer them ad hoc from a tool name string or
argument shape at decision time. See config/capabilities.yaml for the field
definitions and where each value was read off the starter kit's own tool
source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CAPABILITIES_PATH = Path(__file__).resolve().parents[2] / "config" / "capabilities.yaml"

Consequential = bool | str  # True | False | "conditional"


@dataclass(frozen=True)
class ToolCapability:
    name: str
    consequential: Consequential
    consequential_when: dict[str, list[str]] = field(default_factory=dict)
    reversible: bool = True
    sink: bool = False
    destination_tags: tuple[str, ...] = ()
    requires_predecessor: tuple[str, ...] = ()
    requires_approval: Consequential = False

    def is_consequential(self, arguments: dict[str, Any]) -> bool:
        """Mirrors sentinel.tools.base.Tool.is_consequential(arguments)."""
        if self.consequential in (True, False):
            return bool(self.consequential)
        for arg_name, trigger_values in self.consequential_when.items():
            if arguments.get(arg_name) in trigger_values:
                return True
        return False

    def needs_approval(self, arguments: dict[str, Any]) -> bool:
        if self.requires_approval in (True, False):
            return bool(self.requires_approval)
        return self.is_consequential(arguments)


class UnknownTool(KeyError):
    """A candidate action names a tool this registry has never heard of.

    Stage 2 should default-deny on this, not silently allow it -- an unknown
    tool is either a scenario outside the published three domains (unlikely,
    but the safe read is "we cannot vouch for it") or a bug in this registry.
    """


@dataclass
class CapabilityRegistry:
    tools: dict[str, ToolCapability]

    @classmethod
    def load(cls, path: Path = DEFAULT_CAPABILITIES_PATH) -> CapabilityRegistry:
        raw = yaml.safe_load(path.read_text())
        tools: dict[str, ToolCapability] = {}
        for name, spec in raw.get("tools", {}).items():
            tools[name] = ToolCapability(
                name=name,
                consequential=spec.get("consequential", False),
                consequential_when=spec.get("consequential_when", {}),
                reversible=spec.get("reversible", True),
                sink=spec.get("sink", False),
                destination_tags=tuple(spec.get("destination_tags", [])),
                requires_predecessor=tuple(spec.get("requires_predecessor", [])),
                requires_approval=spec.get("requires_approval", False),
            )
        return cls(tools=tools)

    def get(self, tool_name: str) -> ToolCapability:
        try:
            return self.tools[tool_name]
        except KeyError as exc:
            raise UnknownTool(tool_name) from exc

    def __contains__(self, tool_name: str) -> bool:
        return tool_name in self.tools


_REGISTRY: CapabilityRegistry | None = None


def default_registry() -> CapabilityRegistry:
    """Process-wide singleton, loaded once. Deterministic: the YAML on disk
    does not change between calls within a run."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = CapabilityRegistry.load()
    return _REGISTRY
