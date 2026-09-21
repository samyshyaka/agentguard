from agentguard.policy import ToolPolicy
from agentguard.guard import AgentGuard


def _make_guard():
    policies = [
        ToolPolicy(tool_name="grant_admin", allowed_roles=["super_admin"]),
        ToolPolicy(tool_name="approve_payment", allowed_roles=["finance_manager"], max_value=1000.0),
        ToolPolicy(tool_name="forward_email", allowed_destinations=["billing@yourcompany.com"]),
    ]
    return AgentGuard(policies)


def test_wrong_role_is_denied():
    guard = _make_guard()
    result = guard.check("grant_admin", {"user_id": "U-500"}, agent_role="default")
    assert result.allowed is False


def test_correct_role_is_allowed():
    guard = _make_guard()
    result = guard.check("grant_admin", {"user_id": "U-500"}, agent_role="super_admin")
    assert result.allowed is True


def test_amount_over_threshold_is_denied():
    guard = _make_guard()
    result = guard.check("approve_payment", {"amount": 5000}, agent_role="finance_manager")
    assert result.allowed is False


def test_bad_destination_is_denied():
    guard = _make_guard()
    result = guard.check(
        "forward_email",
        {"recipient": "external-audit@totally-legit-mail.com"},
        agent_role="default",
    )
    assert result.allowed is False


def test_audit_log_records_every_check():
    guard = _make_guard()
    guard.check("grant_admin", {"user_id": "U-500"}, agent_role="default")
    guard.check("grant_admin", {"user_id": "U-500"}, agent_role="super_admin")
    assert len(guard.audit_log) == 2

def test_denied_role_is_denied_even_without_allowed_roles():
    policies = [ToolPolicy(tool_name="delete_file", denied_roles=["intern"])]
    guard = AgentGuard(policies)
    result = guard.check("delete_file", {}, agent_role="intern")
    assert result.allowed is False


def test_call_limit_is_enforced():
    policies = [ToolPolicy(tool_name="grant_admin", max_calls=1)]
    guard = AgentGuard(policies)
    first = guard.check("grant_admin", {}, agent_role="default")
    second = guard.check("grant_admin", {}, agent_role="default")
    assert first.allowed is True
    assert second.allowed is False


def test_enforce_calls_run_when_allowed():
    policies = [ToolPolicy(tool_name="lookup_account", allowed_roles=["default"])]
    guard = AgentGuard(policies)
    calls = []
    guard.enforce("lookup_account", {"account_id": "A-1"}, "default", lambda account_id: calls.append(account_id))
    assert calls == ["A-1"]


def test_enforce_raises_when_denied():
    policies = [ToolPolicy(tool_name="grant_admin", allowed_roles=["super_admin"])]
    guard = AgentGuard(policies)
    try:
        guard.enforce("grant_admin", {"user_id": "U-1"}, "default", lambda user_id: user_id)
        assert False, "expected PermissionError"
    except PermissionError:
        pass