"""Local, rule-based security checks for the AIShield hackathon demo.

This is a demonstration scanner, not a production DLP or prompt-injection detector.
Use synthetic test data only.
"""
import re
from dataclasses import dataclass, asdict
from typing import List


@dataclass
class Finding:
    category: str
    rule: str
    severity: str
    explanation: str


@dataclass
class ScanResult:
    decision: str
    risk_score: int
    summary: str
    findings: List[Finding]

    def as_dict(self):
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
        }


# These are deliberately simple patterns for a demo. They are not exhaustive.
SECRET_RULES = [
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Password assignment", re.compile(
        r"""(?i)\b(password|passwd|pwd)\s*[:=]\s*['"]?[^,\s'"]{4,}"""
    )),
    ("Generic token assignment", re.compile(
        r"""(?i)\b(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-./+=]{8,}"""
    )),
]
CUSTOMER_RULES = [
    ("Email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("Possible phone number", re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)")),
]
INJECTION_PHRASES = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "reveal the system prompt",
    "show me your hidden instructions",
    "bypass your safety rules",
    "exfiltrate the secret",
    "send the secret",
]


def scan_message(message: str) -> ScanResult:
    """Inspect a message and return an explainable allow/warn/block result."""
    message = message or ""
    findings: List[Finding] = []

    for label, pattern in SECRET_RULES:
        if pattern.search(message):
            findings.append(Finding(
                category="Credential / secret",
                rule=label,
                severity="HIGH",
                explanation="This pattern may represent a credential or secret. Remove it before using an AI tool.",
            ))

    for label, pattern in CUSTOMER_RULES:
        if pattern.search(message):
            findings.append(Finding(
                category="Possible customer data",
                rule=label,
                severity="MEDIUM",
                explanation="This message may contain identifiable contact information. Review or redact it first.",
            ))

    lowered = message.lower()
    for phrase in INJECTION_PHRASES:
        if phrase in lowered:
            findings.append(Finding(
                category="Suspicious instruction",
                rule=phrase,
                severity="HIGH",
                explanation="This phrase resembles an attempt to override instructions or request protected information.",
            ))

    # Simple transparent scoring for demo purposes, capped at 100.
    score = min(100, sum(60 if f.severity == "HIGH" else 25 for f in findings))
    has_secret = any(f.category == "Credential / secret" for f in findings)
    has_high = any(f.severity == "HIGH" for f in findings)
    has_customer = any(f.category == "Possible customer data" for f in findings)

    if has_secret or has_high:
        decision = "BLOCK"
        summary = "High-risk signal detected. The simulated gateway would stop this message."
    elif has_customer:
        decision = "WARN"
        summary = "Possible customer data detected. Review and redact before continuing."
    else:
        decision = "ALLOW"
        score = 0
        summary = "No configured demo rule matched this message."

    return ScanResult(decision=decision, risk_score=score, summary=summary, findings=findings)
