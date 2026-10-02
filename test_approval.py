import pytest
from agentguard.guard import AgentGuard
from agentguard.policy import ToolPolicy
from agentguard.approval import ApprovalQueue


def make_guard():
    return AgentGuard([
        ToolPolicy(tool_name="transfer_funds", risk_tier="high", policy_id="BANK-AG-004"),
        ToolPolicy(tool_name="lookup_account", risk_tier="low"),
    ])


def test_high_risk_tier_requires_confirmation_without_manual_flag():
    guard = make_guard()
    result = guard.check("transfer_funds", {}, agent_role="loan_agent")
    assert result.requires_confirmation is True
    assert result.decision == "PENDING_CONFIRMATION"


def test_low_risk_tier_does_not_require_confirmation():
    guard = make_guard()
    result = guard.check("lookup_account", {}, agent_role="loan_agent")
    assert result.requires_confirmation is False
    assert result.decision == "ALLOW"


def test_enforce_with_approval_runs_when_approved():
    guard = make_guard()
    ran = {}

    def run(**kwargs):
        ran["called"] = True
        return "ok"

    def approve(tool_name, args, agent_id, reason):
        return True

    out = guard.enforce_with_approval("transfer_funds", {"amount": 100}, "loan_agent", run, approve)
    assert out == "ok"
    assert ran["called"] is True


def test_enforce_with_approval_raises_when_denied():
    guard = make_guard()

    def run(**kwargs):
        return "should not run"

    def approve(tool_name, args, agent_id, reason):
        return False

    with pytest.raises(PermissionError):
        guard.enforce_with_approval("transfer_funds", {"amount": 100}, "loan_agent", run, approve)


def test_approval_queue_cli_prompt_logs_approval(monkeypatch):
    queue = ApprovalQueue()
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    approved = queue.cli_prompt("transfer_funds", {"amount": 100}, "loan_agent_01", "high risk tier")
    assert approved is True
    assert len(queue.log) == 1
    assert queue.log[0].approved is True
    assert queue.log[0].tool_name == "transfer_funds"


def test_approval_queue_cli_prompt_logs_denial(monkeypatch):
    queue = ApprovalQueue()
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    approved = queue.cli_prompt("transfer_funds", {"amount": 100}, "loan_agent_01", "high risk tier")
    assert approved is False
    assert queue.log[0].approved is False