# AgentGuard

Runtime authorization and guardrail middleware for AI agents that use tools.

## Status

Working prototype.

AgentGuard sits alongside [AgentSec-Bench](https://github.com/samyshyaka/agentsec-bench)
as an enforcement layer: where AgentSec-Bench detects unauthorized or manipulated
tool use after the fact, AgentGuard prevents it at runtime, before the action executes.

Currently implemented:
- A policy model (`ToolPolicy`) defining allowed roles, value thresholds, and
  allowed destinations per tool
- Runtime enforcement (`AgentGuard.check()`) that evaluates a proposed tool call
  against policy before execution
- Audit logging of every decision, allowed or denied

Demonstrated integration with AgentSec-Bench: the same scripted "misbehaving" agent
that AgentSec-Bench detects committing an unauthorized payment approval after the
fact is blocked by AgentGuard before the call executes at all. See
`guard_integration_demo.py` in the AgentSec-Bench repository.

## Project layout

- `agentguard/policy.py` — the `ToolPolicy` model (allowed roles, value thresholds, allowed destinations per tool).
- `agentguard/guard.py` — `AgentGuard.check()`, the runtime enforcement logic plus audit logging.
- `test_guard.py` — test suite for the policy and enforcement logic.

## Not yet done

- Integration as a proper pipeline element (currently checked explicitly, not
  automatically inserted into an agent's execution loop)
- Broader policy types beyond role/value/destination
- Testing against live LLM agents rather than scripted stand-ins