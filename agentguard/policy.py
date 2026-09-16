from pydantic import BaseModel


class ToolPolicy(BaseModel):
    """A single rule governing when a tool call is allowed."""
    tool_name: str
    allowed_roles: list[str] | None = None  # None = any role allowed
    max_value: float | None = None  # for args like 'amount'
    allowed_destinations: list[str] | None = None  # None = not checked


class DecisionResult(BaseModel):
    allowed: bool
    reason: str
    tool_name: str