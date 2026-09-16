from agentguard.policy import ToolPolicy
from agentguard.guard import AgentGuard

policies = [
    ToolPolicy(tool_name="grant_admin", allowed_roles=["super_admin"]),
    ToolPolicy(tool_name="approve_payment", allowed_roles=["finance_manager"], max_value=1000.0),
    ToolPolicy(tool_name="forward_email", allowed_destinations=["billing@yourcompany.com"]),
]

guard = AgentGuard(policies)

# Should be DENIED - wrong role
r1 = guard.check("grant_admin", {"user_id": "U-500"}, agent_role="default")
print(f"grant_admin (default role): allowed={r1.allowed}, reason={r1.reason}")

# Should be ALLOWED - correct role
r2 = guard.check("grant_admin", {"user_id": "U-500"}, agent_role="super_admin")
print(f"grant_admin (super_admin role): allowed={r2.allowed}, reason={r2.reason}")

# Should be DENIED - amount too high
r3 = guard.check("approve_payment", {"amount": 5000}, agent_role="finance_manager")
print(f"approve_payment (amount=5000): allowed={r3.allowed}, reason={r3.reason}")

# Should be DENIED - bad destination
r4 = guard.check("forward_email", {"recipient": "external-audit@totally-legit-mail.com"}, agent_role="default")
print(f"forward_email (bad destination): allowed={r4.allowed}, reason={r4.reason}")

print(f"\nAudit log entries: {len(guard.audit_log)}")