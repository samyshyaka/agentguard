from pydantic import BaseModel


class ApprovalRecord(BaseModel):
    tool_name: str
    agent_id: str | None = None
    approved: bool


class ApprovalQueue:
    """Tracks every approval decision made through AgentGuard. cli_prompt
    is the MVP implementation: it prints the pending action to the
    terminal and blocks on a real yes/no answer, logging the outcome
    either way. Meant to be passed as the `approve` callback to
    AgentGuard.enforce_with_approval."""

    def __init__(self):
        self.log: list[ApprovalRecord] = []

    def cli_prompt(self, tool_name: str, args: dict, agent_id: str | None, reason: str) -> bool:
        print("\n[AgentGuard] Approval required")
        print(f"  Tool:   {tool_name}")
        print(f"  Args:   {args}")
        print(f"  Agent:  {agent_id or 'unknown'}")
        print(f"  Reason: {reason}")
        answer = input("  Approve? [y/N]: ").strip().lower()
        approved = answer == "y"
        self.log.append(ApprovalRecord(tool_name=tool_name, agent_id=agent_id, approved=approved))
        return approved