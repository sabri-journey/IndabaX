"""F1 -- capability registry: shape and consequential/approval logic."""

from __future__ import annotations

import pytest

from defense.capabilities import CapabilityRegistry, UnknownTool

ALL_TOOLS = {
    # enterprise
    "email_search",
    "email_read",
    "email_draft",
    "email_send",
    "document_search",
    "document_read",
    "wiki_search",
    "ticket_read",
    "ticket_update",
    # finance
    "customer_lookup",
    "account_summary",
    "case_document_read",
    "case_note_create",
    "policy_search",
    "payment_prepare",
    "payment_confirm",
    "payment_execute",
    # soc
    "alert_search",
    "alert_read",
    "asset_lookup",
    "intel_search",
    "incident_create",
    "incident_update",
    "remediation_prepare",
    "remediation_execute",
}


@pytest.fixture(scope="module")
def registry() -> CapabilityRegistry:
    return CapabilityRegistry.load()


def test_all_25_tools_present(registry: CapabilityRegistry) -> None:
    assert len(ALL_TOOLS) == 25
    assert set(registry.tools) == ALL_TOOLS


def test_unconditional_consequential_tools(registry: CapabilityRegistry) -> None:
    for tool in ["email_send", "payment_confirm", "payment_execute", "remediation_execute"]:
        cap = registry.get(tool)
        assert cap.is_consequential({}) is True
        assert cap.needs_approval({}) is True


def test_conditional_consequential_ticket_update(registry: CapabilityRegistry) -> None:
    cap = registry.get("ticket_update")
    assert cap.is_consequential({"status": "closed"}) is True
    assert cap.is_consequential({"status": "resolved"}) is True
    assert cap.is_consequential({"status": "open"}) is False
    assert cap.is_consequential({}) is False


def test_conditional_consequential_incident_update(registry: CapabilityRegistry) -> None:
    cap = registry.get("incident_update")
    assert cap.is_consequential({"status": "closed"}) is True
    assert cap.is_consequential({"status": "contained"}) is False
    assert cap.is_consequential({}) is False


def test_read_only_tools_are_not_consequential(registry: CapabilityRegistry) -> None:
    for tool in ["email_search", "document_read", "customer_lookup", "alert_search", "policy_search"]:
        assert registry.get(tool).is_consequential({}) is False


def test_payment_and_remediation_prerequisites(registry: CapabilityRegistry) -> None:
    assert registry.get("payment_confirm").requires_predecessor == ("payment_prepare",)
    assert registry.get("payment_execute").requires_predecessor == ("payment_confirm",)
    assert registry.get("remediation_execute").requires_predecessor == ("remediation_prepare",)


def test_unknown_tool_raises(registry: CapabilityRegistry) -> None:
    with pytest.raises(UnknownTool):
        registry.get("delete_everything")


def test_irreversible_consequential_tools(registry: CapabilityRegistry) -> None:
    for tool in ["payment_confirm", "payment_execute", "remediation_execute"]:
        assert registry.get(tool).reversible is False
