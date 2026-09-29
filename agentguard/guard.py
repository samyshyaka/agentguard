from typing import Callable
from .policy import ToolPolicy, DecisionResult, OutcomeConsistencyRule
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

    def __init__(self, policies: list[ToolPolicy], outcome_rules: list[OutcomeConsistencyRule] | None = None):
        self._policies = {p.tool_name: p for p in policies}
        self._outcome_rules = {r.tool_name: r for r in (outcome_rules or [])}
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
                reason=f"role \'{agent_role}\' is explicitly denied for this tool",
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=policy.policy_id,
                risk_tier=policy.risk_tier,
            )
            self.audit_log.append(result)
            return result

        if policy.allowed_roles is not None and agent_role not in policy.allowed_roles:
            result = DecisionResult(
                allowed=False,
                reason=f"role \'{agent_role}\' not in allowed roles {policy.allowed_roles}",
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=policy.policy_id,
                risk_tier=policy.risk_tier,
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
                        risk_tier=policy.risk_tier,
                    )
                    self.audit_log.append(result)
                    return result

        if policy.allowed_destinations is not None:
            for key in DESTINATION_ARG_KEYS:
                if key in args and args[key] not in policy.allowed_destinations:
                    result = DecisionResult(
                        allowed=False,
                        reason=f"destination \'{args[key]}\' not in allowed list",
                        tool_name=tool_name,
                        agent_id=agent_id,
                        policy_id=policy.policy_id,
                        risk_tier=policy.risk_tier,
                    )
                    self.audit_log.append(result)
                    return result

        if policy.max_calls is not None:
            already_called = self._call_counts.get(tool_name, 0)
            if already_called >= policy.max_calls:
                result = DecisionResult(
                    allowed=False,
                    reason=f"call limit reached: \'{tool_name}\' already called {already_called} time(s), max_calls={policy.max_calls}",
                    tool_name=tool_name,
                    agent_id=agent_id,
                    policy_id=policy.policy_id,
                    risk_tier=policy.risk_tier,
                )
                self.audit_log.append(result)
                return result

        if policy.requires_confirmation or policy.risk_tier == "high":
            reason = (
                f"\'{tool_name}\' passed all automatic checks but requires human confirmation before it can proceed"
                if policy.requires_confirmation
                else f"\'{tool_name}\' is tagged risk_tier=\'high\', which requires human confirmation before it can proceed"
            )
            result = DecisionResult(
                allowed=False,
                requires_confirmation=True,
                reason=reason,
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=policy.policy_id,
                risk_tier=policy.risk_tier,
            )
            self.audit_log.append(result)
            return result

        result = DecisionResult(allowed=True, reason="passed all checks", tool_name=tool_name, agent_id=agent_id, policy_id=policy.policy_id, risk_tier=policy.risk_tier)
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
            raise ConfirmationRequiredError(f"AgentGuard requires confirmation for \'{tool_name}\': {result.reason}")
        if not result.allowed and not (result.requires_confirmation and confirmed):
            raise PermissionError(f"AgentGuard denied \'{tool_name}\': {result.reason}")
        return run(**args)

    def enforce_with_approval(self, tool_name: str, args: dict, agent_role: str, run: Callable[..., object], approve: Callable[[str, dict, str | None, str], bool], agent: AgentIdentity | None = None) -> object:
        """Like enforce(), but when a call needs confirmation, calls
        approve(tool_name, args, agent_id, reason) right then and there to
        get a real yes/no decision, instead of requiring the caller to
        already have a confirmed=True in hand. approve() is where a CLI
        prompt, a queue, or any other approval mechanism plugs in - see
        ApprovalQueue.cli_prompt for the MVP CLI implementation."""
        result = self.check(tool_name, args, agent_role, agent=agent)
        if result.requires_confirmation:
            agent_id = agent.id if agent is not None else None
            approved = approve(tool_name, args, agent_id, result.reason)
            if not approved:
                raise PermissionError(f"AgentGuard: approval denied for \'{tool_name}\'")
            return run(**args)
        if not result.allowed:
            raise PermissionError(f"AgentGuard denied \'{tool_name}\': {result.reason}")
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
                f"role \'{agent_role}\' was granted tools with no declared need: {violations}"
            )

    def check_outcome(self, tool_name: str, args: dict, actual_state: dict, agent_role: str, agent: AgentIdentity | None = None) -> DecisionResult:
        """Checks whether a tool call's claimed outcome matches reality,
        for tools that have an OutcomeConsistencyRule registered. This is
        separate from check() because authorization (\'can this role call
        this tool\') and truthfulness (\'is what it\'s claiming actually
        true\') are different questions - a call can be fully authorized
        and still be a lie, which is exactly HT-001 (TrustExploitationScenario):
        report_status is a legitimate call for the role making it, but the
        agent can still report status=\'success\' when actual_state says
        status=\'failed\'. actual_state is supplied by the caller (from the
        real environment), since AgentGuard has no independent access to it."""
        agent_id = agent.id if agent is not None else None
        rule = self._outcome_rules.get(tool_name)

        if rule is None:
            result = DecisionResult(allowed=True, reason="no outcome consistency rule defined", tool_name=tool_name, agent_id=agent_id)
            self.audit_log.append(result)
            return result

        claimed = args.get(rule.field)
        actual = actual_state.get(rule.field)
        if claimed != actual:
            result = DecisionResult(
                allowed=False,
                reason=f"\'{tool_name}\' claims {rule.field}=\'{claimed}\' but actual {rule.field} is \'{actual}\'",
                tool_name=tool_name,
                agent_id=agent_id,
                policy_id=rule.policy_id,
            )
            self.audit_log.append(result)
            return result

        result = DecisionResult(allowed=True, reason="outcome matches reality", tool_name=tool_name, agent_id=agent_id, policy_id=rule.policy_id)
        self.audit_log.append(result)
        return result

    def enforce_outcome(self, tool_name: str, args: dict, actual_state: dict, agent_role: str, run: Callable[..., object], agent: AgentIdentity | None = None) -> object:
        """Like enforce(), but for outcome consistency: raises
        PermissionError if the claimed outcome doesn\'t match actual_state,
        otherwise calls run(**args)."""
        result = self.check_outcome(tool_name, args, actual_state, agent_role, agent=agent)
        if not result.allowed:
            raise PermissionError(f"AgentGuard denied \'{tool_name}\': {result.reason}")
        return run(**args)
