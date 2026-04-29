"""
Base probe interface and security finding data model.

Every security probe inherits from BaseProbe and returns a list of
SecurityFinding objects. This uniform interface lets the scanner
aggregate, filter, and report findings from all probes consistently.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    TOKEN_EXPIRY = "token_expiry"
    ALGORITHM_CONFUSION = "algorithm_confusion"
    SCOPE_OVERFLOW = "scope_overflow"
    REPLAY_ATTACK = "replay_attack"
    WEAK_SECRET = "weak_secret"
    MISSING_CLAIM = "missing_claim"
    INSECURE_TRANSPORT = "insecure_transport"
    EXCESSIVE_LIFETIME = "excessive_lifetime"
    NONE_ALGORITHM = "none_algorithm"
    KID_INJECTION = "kid_injection"


@dataclass
class SecurityFinding:
    probe: str
    category: FindingCategory
    severity: Severity
    title: str
    detail: str
    evidence: Optional[dict] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None          # e.g. "CWE-347"
    cvss_score: Optional[float] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "probe": self.probe,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.probe}: {self.title}"


class BaseProbe(ABC):
    """
    Abstract base for all security probes.

    Each probe is responsible for one attack category and returns a
    (possibly empty) list of SecurityFinding objects.
    """

    name: str = "base"
    description: str = ""

    @abstractmethod
    def run(self, *args, **kwargs) -> list[SecurityFinding]:
        """Execute the probe and return findings."""
        ...
