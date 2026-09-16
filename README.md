# AgentGuard

Runtime authorization and guardrail middleware for AI agents that use tools.

## Status

Architecture design phase. Not yet implemented.

AgentGuard is designed to sit alongside [AgentSec-Bench](https://github.com/samyshyaka/agentsec-bench)
as an enforcement layer: where AgentSec-Bench detects unauthorized or manipulated
tool use, AgentGuard is intended to prevent it at runtime, before the action executes.

Planned initial scope:
- Role-based tool access control
- Threshold-based rules (e.g. transaction limits)
- Audit logging of denied actions

Implementation will begin once AgentSec-Bench's core evaluation loop is stable.