import yaml
from .policy import ToolPolicy


def load_policies_from_yaml(path: str) -> list[ToolPolicy]:
    """Load one agent's policy file, in the shape:

        agent:
          id: loan_assistant_01
          role: loan_assistant
          environment: community_bank

        permissions:
          read_customer_profile:
            allow: true
          transfer_funds:
            allow: false
            requires_confirmation: true

    Returns one ToolPolicy per tool listed under permissions, scoped to
    the role declared in the agent block: allow: true adds the role to
    allowed_roles, allow: false adds it to denied_roles. Optional keys
    (policy_id, max_value, allowed_destinations, max_calls, risk_tier)
    are passed through if present."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    role = data["agent"]["role"]
    policies = []
    for tool_name, spec in data.get("permissions", {}).items():
        allow = spec.get("allow", True)
        policies.append(ToolPolicy(
            tool_name=tool_name,
            allowed_roles=[role] if allow else None,
            denied_roles=[role] if not allow else None,
            requires_confirmation=spec.get("requires_confirmation", False),
            risk_tier=spec.get("risk_tier", "low"),
            policy_id=spec.get("policy_id"),
            max_value=spec.get("max_value"),
            allowed_destinations=spec.get("allowed_destinations"),
            max_calls=spec.get("max_calls"),
        ))
    return policies


def merge_policy_files(paths: list[str]) -> list[ToolPolicy]:
    """Load several agent policy files and merge them into one policy set
    keyed by tool_name, since AgentGuard indexes policies by tool and
    multiple roles often share a tool. allowed_roles and denied_roles are
    unioned across files. Scalar fields (max_value, max_calls,
    allowed_destinations, risk_tier, requires_confirmation, policy_id)
    must agree across every file that sets them - a real conflict (e.g.
    two files disagreeing on max_value for the same tool) raises rather
    than silently picking one, since silently resolving a security policy
    conflict is worse than failing loudly."""
    merged: dict[str, ToolPolicy] = {}

    for path in paths:
        for policy in load_policies_from_yaml(path):
            if policy.tool_name not in merged:
                merged[policy.tool_name] = policy
                continue

            existing = merged[policy.tool_name]
            new_allowed = sorted(set(existing.allowed_roles or []) | set(policy.allowed_roles or [])) or None
            new_denied = sorted(set(existing.denied_roles or []) | set(policy.denied_roles or [])) or None

            for field in ["max_value", "allowed_destinations", "max_calls", "risk_tier", "requires_confirmation", "policy_id"]:
                existing_val = getattr(existing, field)
                new_val = getattr(policy, field)
                default = ToolPolicy.model_fields[field].default
                if existing_val != default and new_val != default and existing_val != new_val:
                    raise ValueError(
                        f"conflicting '{field}' for tool '{policy.tool_name}': "
                        f"{existing_val!r} vs {new_val!r} across policy files"
                    )

            merged[policy.tool_name] = existing.model_copy(update={
                "allowed_roles": new_allowed,
                "denied_roles": new_denied,
            })

    return list(merged.values())