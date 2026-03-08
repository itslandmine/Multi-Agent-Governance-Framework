"""
Multi-Agent Orchestrator with Governance

Coordinates multiple governed agents, enforcing:
- Context isolation between agent sessions
- Centralized audit trail
- Consistent guardrail policies
"""

from dataclasses import dataclass, field

from .agent import GovernedAgent, AgentResponse
from .guardrails import PIIFilter, PromptInjectionDetector, OutputScanner, RBACEnforcer
from .audit import AuditLogger


@dataclass
class OrchestratorResult:
    agent_id: str
    response: AgentResponse
    routed_to: str


class MultiAgentOrchestrator:
    """Routes requests to governed agents with centralized governance.

    Key governance features:
    - Shared audit logger (single source of truth)
    - Per-agent RBAC roles
    - Context isolation (agents don't share memory)
    - Consistent PII and injection filtering
    """

    def __init__(self, audit_dir: str = "audit_logs"):
        # Shared governance components
        self.pii_filter = PIIFilter()
        self.injection_detector = PromptInjectionDetector()
        self.output_scanner = OutputScanner(self.pii_filter)
        self.rbac = RBACEnforcer()
        self.audit_logger = AuditLogger(log_dir=audit_dir)

        self.agents: dict[str, GovernedAgent] = {}

    def register_agent(
        self, agent_id: str, role: str, system_prompt: str = "",
        agent_class: type[GovernedAgent] | None = None,
    ) -> GovernedAgent:
        """Register a new agent with shared governance infrastructure."""
        cls = agent_class or GovernedAgent
        agent = cls(
            agent_id=agent_id,
            role=role,
            system_prompt=system_prompt,
            pii_filter=self.pii_filter,
            injection_detector=self.injection_detector,
            output_scanner=self.output_scanner,
            rbac=self.rbac,
            audit_logger=self.audit_logger,
        )
        self.agents[agent_id] = agent
        return agent

    def route(self, user_input: str, agent_id: str, tool: str | None = None) -> OrchestratorResult:
        """Route a request to a specific agent."""
        agent = self.agents.get(agent_id)
        if not agent:
            raise ValueError(f"Unknown agent: {agent_id}")

        response = agent.process(user_input, tool=tool)
        return OrchestratorResult(
            agent_id=agent_id,
            response=response,
            routed_to=agent.role,
        )

    def get_audit_trail(self) -> list[dict]:
        return self.audit_logger.compliance_export()

    def verify_audit_integrity(self) -> tuple[bool, str]:
        return self.audit_logger.verify_chain()
