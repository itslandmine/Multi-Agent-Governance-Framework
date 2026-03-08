"""
Immutable Audit Logger

Maps to presentation slides:
- "Ethical AI Practices & Audit Trails"
- "Immutable logs for every interaction"
- "Captured: timestamp, user, input, output, tools, model"
- "Lineage tracking: input -> source data -> reasoning"
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class AuditEvent:
    timestamp: float
    agent_id: str
    agent_role: str
    action: str
    input_text: str
    output_text: str
    tools_called: list[str] = field(default_factory=list)
    model_version: str = ""
    pii_detected: bool = False
    pii_redacted: bool = False
    guardrail_triggered: list[str] = field(default_factory=list)
    session_id: str = ""
    # Integrity: hash of previous event for tamper-proof chain
    previous_hash: str = ""
    event_hash: str = ""

    def compute_hash(self) -> str:
        content = json.dumps(
            {k: v for k, v in asdict(self).items() if k != "event_hash"},
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()


class AuditLogger:
    """Append-only audit logger with tamper-proof hash chain.

    Provides the immutable audit trail required for compliance.
    Each event is chained to the previous via hash, making
    tampering detectable.
    """

    def __init__(self, log_dir: str = "audit_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[AuditEvent] = []
        self._last_hash = "genesis"

    def log(self, event: AuditEvent) -> AuditEvent:
        """Log an event to the immutable audit trail."""
        event.previous_hash = self._last_hash
        event.event_hash = event.compute_hash()
        self._last_hash = event.event_hash
        self.events.append(event)

        # Persist to file
        log_file = self.log_dir / f"audit_{event.session_id or 'default'}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(asdict(event)) + "\n")

        return event

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the integrity of the audit chain."""
        if not self.events:
            return True, "Empty chain"

        prev_hash = "genesis"
        for i, event in enumerate(self.events):
            if event.previous_hash != prev_hash:
                return False, f"Chain broken at event {i}: previous_hash mismatch"
            recomputed = event.compute_hash()
            if event.event_hash != recomputed:
                return False, f"Event {i} tampered: hash mismatch"
            prev_hash = event.event_hash

        return True, f"Chain verified: {len(self.events)} events intact"

    def get_lineage(self, session_id: str) -> list[AuditEvent]:
        """Get the full lineage for a session (input -> reasoning -> output)."""
        return [e for e in self.events if e.session_id == session_id]

    def compliance_export(self) -> list[dict]:
        """Export audit trail in a format suitable for compliance review."""
        return [asdict(e) for e in self.events]
