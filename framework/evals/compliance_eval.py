"""
Compliance Evaluator

Maps to presentation slides:
- "Compliance, Privacy & Governance Principles"
- "GDPR, HIPAA, EU AI Act"
- "Key question per workflow: What data does this agent touch, and who authorized it?"
"""

from dataclasses import dataclass, field


@dataclass
class ComplianceCheck:
    regulation: str
    requirement: str
    status: str  # "pass", "fail", "warning"
    details: str


@dataclass
class AgentWorkflowConfig:
    agent_name: str
    data_types_accessed: list[str] = field(default_factory=list)
    has_pii_redaction: bool = False
    has_audit_logging: bool = False
    has_consent_mechanism: bool = False
    has_data_retention_policy: bool = False
    has_encryption_at_rest: bool = False
    has_encryption_in_transit: bool = False
    has_rbac: bool = False
    has_human_in_the_loop: bool = False
    has_right_to_delete: bool = False
    has_purpose_limitation: bool = False
    retention_days: int | None = None


class ComplianceEvaluator:
    """Evaluates an agent workflow against regulatory requirements.

    Checks alignment with GDPR, HIPAA, EU AI Act, and SOC 2.
    """

    def evaluate(self, config: AgentWorkflowConfig) -> list[ComplianceCheck]:
        checks = []
        checks.extend(self._check_gdpr(config))
        checks.extend(self._check_hipaa(config))
        checks.extend(self._check_eu_ai_act(config))
        checks.extend(self._check_soc2(config))
        return checks

    def _check_gdpr(self, config: AgentWorkflowConfig) -> list[ComplianceCheck]:
        checks = []
        has_personal_data = any(
            dt in config.data_types_accessed
            for dt in ["PII", "email", "name", "address", "phone", "SSN"]
        )

        if has_personal_data:
            checks.append(ComplianceCheck(
                "GDPR", "Data minimization (Art. 5)",
                "pass" if config.has_pii_redaction else "fail",
                "PII redaction is required when processing personal data",
            ))
            checks.append(ComplianceCheck(
                "GDPR", "Right to erasure (Art. 17)",
                "pass" if config.has_right_to_delete else "fail",
                "Must support deletion of personal data on request",
            ))
            checks.append(ComplianceCheck(
                "GDPR", "Purpose limitation (Art. 5)",
                "pass" if config.has_purpose_limitation else "warning",
                "Data should only be used for its stated purpose",
            ))
            checks.append(ComplianceCheck(
                "GDPR", "Lawful basis & consent (Art. 6)",
                "pass" if config.has_consent_mechanism else "fail",
                "Processing requires lawful basis or explicit consent",
            ))

        checks.append(ComplianceCheck(
            "GDPR", "Accountability (Art. 5)",
            "pass" if config.has_audit_logging else "fail",
            "Must maintain records of processing activities",
        ))

        return checks

    def _check_hipaa(self, config: AgentWorkflowConfig) -> list[ComplianceCheck]:
        checks = []
        has_phi = any(
            dt in config.data_types_accessed
            for dt in ["PHI", "medical_records", "health_data", "diagnosis"]
        )

        if has_phi:
            checks.append(ComplianceCheck(
                "HIPAA", "Encryption safeguard",
                "pass" if (config.has_encryption_at_rest and config.has_encryption_in_transit) else "fail",
                "PHI must be encrypted at rest and in transit",
            ))
            checks.append(ComplianceCheck(
                "HIPAA", "Access control",
                "pass" if config.has_rbac else "fail",
                "Role-based access control required for PHI",
            ))
            checks.append(ComplianceCheck(
                "HIPAA", "Audit trail",
                "pass" if config.has_audit_logging else "fail",
                "All PHI access must be logged",
            ))

        return checks

    def _check_eu_ai_act(self, config: AgentWorkflowConfig) -> list[ComplianceCheck]:
        checks = []
        checks.append(ComplianceCheck(
            "EU AI Act", "Human oversight (Art. 14)",
            "pass" if config.has_human_in_the_loop else "warning",
            "High-risk AI systems require human oversight mechanisms",
        ))
        checks.append(ComplianceCheck(
            "EU AI Act", "Transparency (Art. 13)",
            "pass" if config.has_audit_logging else "fail",
            "AI systems must be transparent and explainable",
        ))
        return checks

    def _check_soc2(self, config: AgentWorkflowConfig) -> list[ComplianceCheck]:
        checks = []
        checks.append(ComplianceCheck(
            "SOC 2", "Access controls",
            "pass" if config.has_rbac else "fail",
            "Logical access controls must be in place",
        ))
        checks.append(ComplianceCheck(
            "SOC 2", "Data retention",
            "pass" if config.has_data_retention_policy else "fail",
            "Data retention and disposal policies required",
        ))
        checks.append(ComplianceCheck(
            "SOC 2", "Monitoring & logging",
            "pass" if config.has_audit_logging else "fail",
            "Continuous monitoring and audit logging required",
        ))
        return checks

    def summary(self, checks: list[ComplianceCheck]) -> dict:
        total = len(checks)
        passed = sum(1 for c in checks if c.status == "pass")
        failed = sum(1 for c in checks if c.status == "fail")
        warnings = sum(1 for c in checks if c.status == "warning")
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "compliance_score": passed / total if total > 0 else 0,
            "by_regulation": {
                reg: {
                    "passed": sum(1 for c in checks if c.regulation == reg and c.status == "pass"),
                    "failed": sum(1 for c in checks if c.regulation == reg and c.status == "fail"),
                    "warnings": sum(1 for c in checks if c.regulation == reg and c.status == "warning"),
                }
                for reg in sorted({c.regulation for c in checks})
            },
        }
