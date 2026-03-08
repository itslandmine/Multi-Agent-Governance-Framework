"""
Governed Agent - Base agent with guardrails baked in.

Every agent action passes through the governance pipeline:
Input -> PII Filter -> Injection Check -> RBAC -> [Agent Logic] -> Output Scan -> Audit Log
"""

import time
import uuid
from dataclasses import dataclass, field

from .guardrails import PIIFilter, PromptInjectionDetector, OutputScanner, RBACEnforcer
from .audit import AuditLogger, AuditEvent


@dataclass
class AgentResponse:
    output: str
    was_filtered: bool = False
    guardrails_triggered: list[str] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""


class GovernedAgent:
    """An agent wrapped with governance guardrails.

    Implements the full governance pipeline:
    1. Input PII redaction (Classify -> Redact)
    2. Prompt injection detection
    3. RBAC enforcement
    4. Agent processing (delegates to subclass)
    5. Output scanning
    6. Audit logging
    """

    def __init__(
        self,
        agent_id: str,
        role: str,
        system_prompt: str = "",
        pii_filter: PIIFilter | None = None,
        injection_detector: PromptInjectionDetector | None = None,
        output_scanner: OutputScanner | None = None,
        rbac: RBACEnforcer | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.system_prompt = system_prompt
        self.session_id = str(uuid.uuid4())[:8]

        self.pii_filter = pii_filter or PIIFilter()
        self.injection_detector = injection_detector or PromptInjectionDetector()
        self.output_scanner = output_scanner or OutputScanner(self.pii_filter)
        self.rbac = rbac or RBACEnforcer()
        self.audit_logger = audit_logger or AuditLogger()

    def process(self, user_input: str, tool: str | None = None) -> AgentResponse:
        """Run the full governance pipeline on an input."""
        guardrails_triggered = []

        # Step 1: Check for prompt injection
        injection_result = self.injection_detector.analyze(user_input)
        if injection_result.is_injection:
            guardrails_triggered.append(f"prompt_injection: {injection_result.explanation}")
            self._log(user_input, "[BLOCKED]", guardrails_triggered)
            return AgentResponse(
                output="",
                blocked=True,
                block_reason=f"Prompt injection detected: {injection_result.explanation}",
                guardrails_triggered=guardrails_triggered,
            )

        # Step 2: RBAC check
        if tool:
            access_denied = self.rbac.authorize(self.role, "execute_tool", tool)
            if access_denied:
                guardrails_triggered.append(f"rbac: {access_denied.reason}")
                self._log(user_input, "[ACCESS DENIED]", guardrails_triggered)
                return AgentResponse(
                    output="",
                    blocked=True,
                    block_reason=access_denied.reason,
                    guardrails_triggered=guardrails_triggered,
                )

        # Step 3: PII redaction on input
        sanitized_input, pii_matches = self.pii_filter.redact(user_input)
        was_filtered = len(pii_matches) > 0
        if was_filtered:
            guardrails_triggered.append(
                f"pii_redacted: {', '.join(m.entity_type for m in pii_matches)}"
            )

        # Step 4: Agent logic (simulate LLM response)
        raw_output = self._generate(sanitized_input)

        # Step 5: Output scanning
        scan_result = self.output_scanner.scan(raw_output)
        if not scan_result.is_safe:
            guardrails_triggered.extend(f"output_scan: {issue}" for issue in scan_result.issues)
            raw_output = scan_result.redacted_output or raw_output

        # Step 6: Audit logging
        self._log(
            user_input, raw_output, guardrails_triggered,
            pii_detected=was_filtered, tools=[tool] if tool else [],
        )

        return AgentResponse(
            output=raw_output,
            was_filtered=was_filtered,
            guardrails_triggered=guardrails_triggered,
        )

    def _generate(self, sanitized_input: str) -> str:
        """Simulate agent response. Override this for real LLM integration."""
        return f"[Agent {self.agent_id}] Processed: {sanitized_input}"

    def _log(
        self, input_text: str, output_text: str, guardrails: list[str],
        pii_detected: bool = False, tools: list[str] | None = None,
    ):
        event = AuditEvent(
            timestamp=time.time(),
            agent_id=self.agent_id,
            agent_role=self.role,
            action="process",
            input_text=input_text,
            output_text=output_text,
            tools_called=tools or [],
            pii_detected=pii_detected,
            pii_redacted=pii_detected,
            guardrail_triggered=guardrails,
            session_id=self.session_id,
        )
        self.audit_logger.log(event)
