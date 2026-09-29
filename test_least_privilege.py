import pytest
from agentguard.guard import AgentGuard, LeastPrivilegeViolation
from agentguard.policy import ToolPolicy


def make_guard():
    return AgentGuard([
        ToolPolicy(tool_name="lookup_account", allowed_roles=["support_agent", "loan_agent"]),
        ToolPolicy(tool_name="calculate_loan", allowed_roles=["loan_agent"]),
        ToolPolicy(tool_name="transfer_funds", allowed_roles=["loan_agent"]),
        ToolPolicy(tool_name="send_email"),  # allowed_roles=None: any role, not a declared need
    ])


def test_no_violation_when_granted_tools_match_role_need():
    guard = make_guard()
    violations = guard.least_privilege_violations("support_agent", ["lookup_account"])
    assert violations == []


def test_violation_when_granted_extra_tool():
    guard = make_guard()
    violations = guard.least_privilege_violations("support_agent", ["lookup_account", "transfer_funds"])
    assert violations == ["transfer_funds"]


def test_tool_with_no_policy_is_not_counted_as_needed():
    guard = make_guard()
    violations = guard.least_privilege_violations("support_agent", ["some_undeclared_tool"])
    assert violations == ["some_undeclared_tool"]


def test_tool_with_allowed_roles_none_is_not_counted_as_needed():
    guard = make_guard()
    violations = guard.least_privilege_violations("support_agent", ["send_email"])
    assert violations == ["send_email"]


def test_enforce_raises_on_violation():
    guard = make_guard()
    with pytest.raises(LeastPrivilegeViolation):
        guard.enforce_least_privilege("support_agent", ["lookup_account", "transfer_funds"])


def test_enforce_passes_when_no_violation():
    guard = make_guard()
    guard.enforce_least_privilege("loan_agent", ["lookup_account", "calculate_loan", "transfer_funds"])