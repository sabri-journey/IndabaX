"""Launcher for a SECOND, separate SENTINEL defense server instance (port
8081) that knows AgentDojo's tools -- without ever touching
IndabaX/config/capabilities.yaml. Monkeypatches the capability registry's
default path at process start, before any request loads the (cached)
singleton. The original server on 8080, and config/capabilities.yaml
itself, are completely untouched -- this is a second, independent process
reusing the same src/defense code.
"""

import sys
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/ahmed/IndabaX/src")

import defense.capabilities as capabilities

# NOTE: reassigning DEFAULT_CAPABILITIES_PATH alone does NOT work --
# CapabilityRegistry.load()'s `path` default parameter was already bound to
# the original value at module-import time (Python's classic late-binding-
# default gotcha). Pre-populate the cached singleton directly instead, with
# an explicit path, before any request can trigger the lazy default.
_agentdojo_capabilities_path = Path(__file__).resolve().parent / "agentdojo_capabilities.yaml"
capabilities._REGISTRY = capabilities.CapabilityRegistry.load(path=_agentdojo_capabilities_path)

import uvicorn

if __name__ == "__main__":
    uvicorn.run("defense.adapter:app", host="127.0.0.1", port=8081, log_level="info")
