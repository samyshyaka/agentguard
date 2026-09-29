from typing import Callable
from .policy import ToolPolicy, DecisionResult
from .identity import AgentIdentity

DESTINATION_ARG_KEYS = ["recipient", "email", "destination", "to"]
VALUE_ARG_KEYS = ["amount", "value"]


class ConfirmationRequiredError(PermissionError):
    """Raised by enforce() when a tool call passed every policy check but
    is marked requires_confirmation=True, and no confirmation was given.
    Subclasses PermissionError so existing callers that only catch
    PermissionError still work, but callers that care about the
    difference can catch this specifically."""
    pass


class LeastPrivilegeViolation(ValueError):
    """Raised when an agent is about to be granted a tool its role has no
    declared need for, based on the policies AgentGuard already knows
    about. A tool counts as needed by a role only if some policy for that
    tool explicitly lists the role in allowed_roles."""
    pass


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

    def check(self, tool_name: str, args: dict, agent_role: str, agent: AgentIdentity | None = None) -> DecisionResult:
        agent_id = agent.id if agent is not None else None
        policy = self._policies.get(tool_name)

        if policy is None:
            result = DecisionResult(allowed=True, reason="no policy defined", tool_name=tool_name, agent_id=agent_id)
            self.audit_log.append(result)
            return result

        if policy.denied_roles is not None and agent_role in policy.denied_roles:
            result = DecisionResult(
                allowed=False,
                reason=f"role '{agent_role}' is explicitly denied for this tool",
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=policy.policy_id,
            )
            self.audit_log.append(result)
            return result

        if policy.allowed_roles is not None and agent_role not in policy.allowed_roles:
            result = DecisionResult(
                allowed=False,
                reason=f"role '{agent_role}' not in allowed roles {policy.allowed_roles}",
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=policy.policy_id,
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
                        agent_id=agent_id,
                        policy_id=policy.policy_id,
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
                        agent_id=agent_id,
                        policy_id=policy.policy_id,
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
                    agent_id=agent_id,
                    policy_id=policy.policy_id,
                )
                self.audit_log.append(result)
                return result

        if policy.requires_confirmation:
            result = DecisionResult(
                allowed=False,
                requires_confirmation=True,
                reason=f"'{tool_name}' passed all automatic checks but requires human confirmation before it can proceed",
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=policy.policy_id,
            )
            self.audit_log.append(result)
            return result

        result = DecisionResult(allowed=True, reason="passed all checks", tool_name=tool_name, agent_id=agent_id, policy_id=policy.policy_id)
        if policy.max_calls is not None:
            self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1
        self.audit_log.append(result)
        return result

    def enforce(self, tool_name: str, args: dict, agent_role: str, run: Callable[..., object], confirmed: bool = False, agent: AgentIdentity | None = None) -> object:
        """Pipeline-style enforcement: checks policy and, if allowed, calls
        run(**args) immediately. Meant to be dropped directly into an
        agent's tool-execution loop in place of a raw tool call, instead
        of requiring the caller to check() and branch manually every time.

        If the policy requires confirmation and confirmed=False, raises
        ConfirmationRequiredError instead of running - the caller (e.g. a
        human-in-the-loop UI) should get sign-off and re-call with
        confirmed=True. Any other denial raises plain PermissionError."""
        result = self.check(tool_name, args, agent_role, agent=agent)
        if result.requires_confirmation and not confirmed:
            raise ConfirmationRequiredError(f"AgentGuard requires confirmation for '{tool_name}': {result.reason}")
        if not result.allowed and not (result.requires_confirmation and confirmed):
            raise PermissionError(f"AgentGuard denied '{tool_name}': {result.reason}")
        return run(**args)

    def least_privilege_violations(self, agent_role: str, granted_tools: list[str]) -> list[str]:
        """Given the tools about to be handed to an agent with the given
        role, return the subset that role has no declared need for. A tool
        counts as needed by a role only if a policy for that tool exists
        and explicitly lists the role in allowed_roles - a tool with no
        policy at all, or a policy with allowed_roles=None (any role
        allowed), is not counted as a declared need for any specific role.
        An empty list means the agent is minimally provisioned."""
        needed = {
            tool_name for tool_name, policy in self._policies.items()
            if policy.allowed_roles is not None and agent_role in policy.allowed_roles
        }
        return [t for t in granted_tools if t not in needed]

    def enforce_least_privilege(self, agent_role: str, granted_tools: list[str]) -> None:
        """Raises LeastPrivilegeViolation if granted_tools includes
        anything agent_role has no declared need for. Meant to be called
        once, when an agent is being constructed and handed its tool
        list - before any individual tool call happens."""
        violations = self.least_privilege_violations(agent_role, granted_tools)
        if violations:
            raise LeastPrivilegeViolation(
                f"role '{agent_role}' was granted tools with no declared need: {violations}"
            )