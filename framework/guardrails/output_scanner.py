"""
Output Guardrails

- "Output Guardrails: Scan responses for inadvertent leakage,
   hallucinated credentials, and adversarial patterns"
"""

import re
from dataclasses import dataclass

from .pii_filter import PIIFilter


@dataclass
class ScanResult:
    is_safe: bool
    issues: list[str]
    redacted_output: str | None


class OutputScanner:
    """Scans agent outputs before they reach the user.

    Catches:
    - PII leakage in responses
    - Hallucinated credentials/secrets
    - Toxic or non-compliant content patterns
    - Refusal bypass indicators
    """

    HALLUCINATED_SECRETS = re.compile(
        r"(?:password|secret|token|api.?key)\s*[:=]\s*\S+",
        re.IGNORECASE,
    )

    UNSAFE_CONTENT = re.compile(
        r"(?:how\s+to\s+(?:hack|exploit|attack|break\s+into)|"
        r"step[s]?\s+to\s+(?:bypass|circumvent|disable)\s+security)",
        re.IGNORECASE,
    )

    def __init__(self, pii_filter: PIIFilter | None = None):
        self.pii_filter = pii_filter or PIIFilter()

    def scan(self, output: str) -> ScanResult:
        """Scan an agent's output for safety issues."""
        issues = []

        # Check for PII leakage
        pii_matches = self.pii_filter.detect(output)
        if pii_matches:
            entities = {m.entity_type for m in pii_matches}
            issues.append(f"PII leakage detected: {', '.join(sorted(entities))}")

        # Check for hallucinated credentials
        if self.HALLUCINATED_SECRETS.search(output):
            issues.append("Potential hallucinated credentials in output")

        # Check for unsafe content
        if self.UNSAFE_CONTENT.search(output):
            issues.append("Unsafe content pattern detected")

        redacted = None
        if issues:
            redacted, _ = self.pii_filter.redact(output)

        return ScanResult(
            is_safe=len(issues) == 0,
            issues=issues,
            redacted_output=redacted,
        )
