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