"""Shared test fixtures.

The session store (session_store.py) is a process-wide singleton, keyed by
session_key -- necessary in production (an HTTP defense is stateless per
call, so cross-step state has to live somewhere), but it would otherwise let
state leak between test functions that happen to reuse the same run_id
string. Reset it before and after every test.
"""

from __future__ import annotations

import pytest

from defense.session_store import default_store


@pytest.fixture(autouse=True)
def _clean_session_store():
    default_store().clear()
    yield
    default_store().clear()
