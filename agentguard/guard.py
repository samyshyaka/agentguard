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
        self.audit_log: list[DecisionResult] = []

    def check(self, tool_name: str, args: dict, agent_role: str) -> DecisionResult:
        policy = self._policies.get(tool_name)

        if policy is None:
            # No policy defined for this tool = allowed by default.
            result = DecisionResult(allowed=True, reason="no policy defined", tool_name=tool_name)
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

        result = DecisionResult(allowed=True, reason="passed all checks", tool_name=tool_name)
        self.audit_log.append(result)
        return result