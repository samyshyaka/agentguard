from pydantic import BaseModel


class ToolPolicy(BaseModel):
    """A single rule governing when a tool call is allowed."""
    tool_name: str
    allowed_roles: list[str] | None = None  # None = any role allowed
    denied_roles: list[str] | None = None  # explicit blocklist, checked before allowed_roles
    max_value: float | None = None  # for args like 'amount'
    allowed_destinations: list[str] | None = None  # None = not checked
    max_calls: int | None = None  # max times this tool may be called per AgentGuard session


class DecisionResult(BaseModel):
    allowed: bool
    reason: str
    tool_name: str