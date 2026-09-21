from typing import Callable
from .policy import ToolPolicy, DecisionResult

DESTINATION_ARG_KEYS = ["recipient", "email", "destination", "to"]
VALUE_ARG_KEYS = ["amount", "value"]


class AgentGuard:
    """Runtime authorization middleware. Evaluates a proposed tool call
    against a set of policies BEFORE it executes, and either allows or
    denies it. Unlike AgentSec-Bench's Evaluator, which measures whether
    a violation happened after the fact, AgentGuard is designed to
    prevent it from happening at all."""

    def __init__(self, policies: list[ToolPolicy]):
        self._policies = {p.tool_name: p for p in policies}
        self._call_counts: dict[str, int] = {}
        self.audit_log: list[DecisionResult] = []

    def check(self, tool_name: str, args: dict, agent_role: str) -> DecisionResult:
        policy = self._policies.get(tool_name)

        if policy is None:
            result = DecisionResult(allowed=True, reason="no policy defined", tool_name=tool_name)
            self.audit_log.append(result)
            return result

        if policy.denied_roles is not None and agent_role in policy.denied_roles:
            result = DecisionResult(
                allowed=False,
                reason=f"role '{agent_role}' is explicitly denied for this tool",
                tool_name=tool_name,
            )
            self.audit_log.append(result)
            return result

        if policy.allowed_roles is not None and agent_role not in policy.allowed_roles:
            result = DecisionResult(
                allowed=False,
                reason=f"role '{agent_role}' not in allowed roles {policy.allowed_roles}",
                tool_name=tool_name,
            )
            self.audit_log.append(result)
            return result

        if policy.max_value is not None:
            for key in VALUE_ARG_KEYS:
                if key in args and args[key] > policy.max_value:
                    result = DecisionResult(
                        allowed=False,
                        reason=f"{key}={args[key]} exceeds max_value={policy.max_value}",
                        tool_name=tool_name,
                    )
                    self.audit_log.append(result)
                    return result

        if policy.allowed_destinations is not None:
            for key in DESTINATION_ARG_KEYS:
                if key in args and args[key] not in policy.allowed_destinations:
                    result = DecisionResult(
                        allowed=False,
                        reason=f"destination '{args[key]}' not in allowed list",
                        tool_name=tool_name,
                    )
                    self.audit_log.append(result)
                    return result

        if policy.max_calls is not None:
            already_called = self._call_counts.get(tool_name, 0)
            if already_called >= policy.max_calls:
                result = DecisionResult(
                    allowed=False,
                    reason=f"call limit reached: '{tool_name}' already called {already_called} time(s), max_calls={policy.max_calls}",
                    tool_name=tool_name,
                )
                self.audit_log.append(result)
                return result

        result = DecisionResult(allowed=True, reason="passed all checks", tool_name=tool_name)
        if policy.max_calls is not None:
            self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1
        self.audit_log.append(result)
        return result

    def enforce(self, tool_name: str, args: dict, agent_role: str, run: Callable[..., object]) -> object:
        """Pipeline-style enforcement: checks policy and, if allowed, calls
        run(**args) immediately, raising PermissionError otherwise. Meant
        to be dropped directly into an agent's tool-execution loop in
        place of a raw tool call, instead of requiring the caller to
        check() and branch manually every time."""
        result = self.check(tool_name, args, agent_role)
        if not result.allowed:
            raise PermissionError(f"AgentGuard denied '{tool_name}': {result.reason}")
        return run(**args)