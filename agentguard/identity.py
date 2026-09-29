from pydantic import BaseModel


class AgentIdentity(BaseModel):
    """A stable identity for an agent: who it is, what role it plays,
    and which deployment environment it's running in. Matches the
    identity block AgentGuard policies and audit events key off of:

        agent:
          id: loan_assistant_01
          role: loan_assistant
          environment: community_bank
    """
    id: str
    role: str
    environment: str = "default"