"""
PII Detection & Redaction Guardrail

Maps to presentation slides:
- "Managing Sensitive Data in Agentic Systems" (Classify -> Redact lifecycle)
- "PII Detection & Redaction: Deploy NER-based filters"
"""

import re
from dataclasses import dataclass, field


@dataclass
class PIIMatch:
    entity_type: str
    text: str
    start: int
    end: int
    score: float


class PIIFilter:
    """Detects and redacts PII before data reaches the LLM.

    Implements the "Classify -> Redact" stages of the sensitive data lifecycle.
    Uses regex patterns as a lightweight, dependency-free baseline.
    Can be extended with Presidio or custom NER models for production use.
    """

    PATTERNS: dict[str, re.Pattern] = {
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "PHONE": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "IP_ADDRESS": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "DATE_OF_BIRTH": re.compile(
            r"\b(?:DOB|date of birth|born)[:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
            re.IGNORECASE,
        ),
        "API_KEY": re.compile(r"\b(?:sk|pk|api[_-]?key)[_-][A-Za-z0-9]{20,}\b", re.IGNORECASE),
    }

    def __init__(self, custom_patterns: dict[str, re.Pattern] | None = None):
        self.patterns = {**self.PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)

    def detect(self, text: str) -> list[PIIMatch]:
        """Scan text and return all PII matches."""
        matches = []
        for entity_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                matches.append(
                    PIIMatch(
                        entity_type=entity_type,
                        text=match.group(),
                        start=match.start(),
                        end=match.end(),
                        score=1.0,
                    )
                )
        return sorted(matches, key=lambda m: m.start)

    def redact(self, text: str, replacement_format: str = "[{entity_type}]") -> tuple[str, list[PIIMatch]]:
        """Detect and replace PII with placeholder tokens.

        Returns the redacted text and the list of matches found.
        """
        matches = self.detect(text)
        redacted = text
        offset = 0
        for match in matches:
            placeholder = replacement_format.format(entity_type=match.entity_type)
            start = match.start + offset
            end = match.end + offset
            redacted = redacted[:start] + placeholder + redacted[end:]
            offset += len(placeholder) - (match.end - match.start)
        return redacted, matches

    def is_safe(self, text: str) -> bool:
        """Quick check: does this text contain any PII?"""
        return len(self.detect(text)) == 0
