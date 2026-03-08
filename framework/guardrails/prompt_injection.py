"""
Prompt Injection Defense Guardrail

- "Prompt Injection Defense: Validate and sanitize all user inputs;
   use structured schemas to prevent prompt manipulation"
"""

import re
from dataclasses import dataclass


@dataclass
class InjectionResult:
    is_injection: bool
    risk_score: float  # 0.0 to 1.0
    matched_patterns: list[str]
    explanation: str


class PromptInjectionDetector:
    """Detects prompt injection attempts in user inputs.

    Uses a layered approach:
    1. Known attack pattern matching
    2. Structural analysis (role boundary violations)
    3. Heuristic scoring
    """

    INJECTION_PATTERNS: list[tuple[str, re.Pattern, float]] = [
        # (description, pattern, weight)
        ("Role override attempt", re.compile(
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)",
            re.IGNORECASE,
        ), 0.9),
        ("System prompt extraction", re.compile(
            r"(?:reveal|show|print|output|repeat|display)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)",
            re.IGNORECASE,
        ), 0.8),
        ("Role impersonation", re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|new\s+role|switch\s+to)\s+",
            re.IGNORECASE,
        ), 0.7),
        ("Delimiter injection", re.compile(
            r"(?:```|<\|im_end\|>|<\|im_start\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
            re.IGNORECASE,
        ), 0.85),
        ("Encoded payload", re.compile(
            r"(?:base64|eval|exec|import\s+os|subprocess|__import__)",
            re.IGNORECASE,
        ), 0.9),
        ("Data exfiltration attempt", re.compile(
            r"(?:send\s+(?:to|all|data)|http[s]?://|fetch\s+url|curl\s+|wget\s+)",
            re.IGNORECASE,
        ), 0.6),
        ("Jailbreak keyword", re.compile(
            r"(?:DAN|do\s+anything\s+now|jailbreak|bypass\s+(?:filter|safety|restriction))",
            re.IGNORECASE,
        ), 0.95),
    ]

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def analyze(self, user_input: str) -> InjectionResult:
        """Analyze input for prompt injection attempts."""
        matched = []
        total_weight = 0.0

        for description, pattern, weight in self.INJECTION_PATTERNS:
            if pattern.search(user_input):
                matched.append(description)
                total_weight = max(total_weight, weight)

        risk_score = total_weight
        is_injection = risk_score >= self.threshold

        if matched:
            explanation = f"Detected: {', '.join(matched)}"
        else:
            explanation = "No injection patterns detected"

        return InjectionResult(
            is_injection=is_injection,
            risk_score=risk_score,
            matched_patterns=matched,
            explanation=explanation,
        )

    def sanitize(self, user_input: str) -> str:
        """Strip known dangerous patterns from input while preserving intent."""
        sanitized = user_input
        for _, pattern, weight in self.INJECTION_PATTERNS:
            if weight >= 0.8:
                sanitized = pattern.sub("[BLOCKED]", sanitized)
        return sanitized
