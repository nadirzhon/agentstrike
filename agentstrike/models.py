"""Core data structures for agentstrike."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered severity (higher = worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def sarif_level(self) -> str:
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]


@dataclass
class Probe:
    """A single attack attempt: the payload we sent."""

    technique: str
    payload: str
    generation: int = 0
    parent: str | None = None  # fingerprint of the payload it mutated from

    @property
    def fingerprint(self) -> str:
        raw = f"{self.technique}|{self.payload}"
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]


@dataclass
class Breach:
    """A probe that the oracle judged successful against the target."""

    technique: str
    title: str
    severity: Severity
    owasp: str            # e.g. "LLM01:2025 Prompt Injection"
    payload: str
    response_excerpt: str
    signal: str           # what proved success (canary hit, refusal bypassed…)
    generation: int
    remediation: str
    confidence: str = "high"

    @property
    def fingerprint(self) -> str:
        raw = f"{self.technique}|{self.payload}|{self.signal}"
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class CampaignResult:
    target: str = "target"
    breaches: list[Breach] = field(default_factory=list)
    probes_sent: int = 0
    generations: int = 0
    techniques_run: list[str] = field(default_factory=list)
    duration_sec: float = 0.0

    def sorted_breaches(self) -> list[Breach]:
        return sorted(self.breaches, key=lambda b: (-int(b.severity), b.technique))

    @property
    def risk_score(self) -> int:
        """0–100: how exposed the agent is."""
        weights = {
            Severity.CRITICAL: 30, Severity.HIGH: 15,
            Severity.MEDIUM: 6, Severity.LOW: 2, Severity.INFO: 0,
        }
        return min(100, sum(weights[b.severity] for b in self.breaches))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "risk_score": self.risk_score,
            "probes_sent": self.probes_sent,
            "generations": self.generations,
            "techniques_run": self.techniques_run,
            "duration_sec": self.duration_sec,
            "breaches": [b.to_dict() for b in self.sorted_breaches()],
        }
