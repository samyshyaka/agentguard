from pydantic import BaseModel


class ToolPolicy(BaseModel):
    """A single rule governing when a tool call is allowed."""
    tool_name: str
    policy_id: str | None = None  # human-readable id for audit events, e.g. "BANK-AG-004"
    allowed_roles: list[str] | None = None  # None = any role allowed
    denied_roles: list[str] | None = None  # explicit blocklist, checked before allowed_roles
    max_value: float | None = None  # for args like 'amount'
    allowed_destinations: list[str] | None = None  # None = not checked
    max_calls: int | None = None  # max times this tool may be called per AgentGuard session
    requires_confirmation: bool = False  # if True, a call that passes every other check is still
    # held for human sign-off instead of auto-running (see AgentGuard.enforce's `confirmed` arg)


class DecisionResult(BaseModel):
    allowed: bool
    reason: str
    tool_name: str
    requires_confirmation: bool = False
    agent_id: str | None = None
    policy_id: str | None = None

    @property
    def decision(self) -> str:
        if self.requires_confirmation and not self.allowed:
            return "PENDING_CONFIRMATION"
        return "ALLOW" if self.allowed else "DENY"