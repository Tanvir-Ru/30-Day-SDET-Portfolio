"""
Base probe interface and OWASPFinding data model.

Every OWASP probe inherits from OWASPBaseProbe and returns a list of
OWASPFinding objects. The finding model maps directly to the OWASP Top 10
2021 risk categories with CWE IDs and CVSS v3.1 scores.

OWASP Top 10 2021 categories covered:
  A01 - Broken Access Control
  A02 - Cryptographic Failures
  A03 - Injection
  A04 - Insecure Design          (checked via headers/configuration probes)
  A05 - Security Misconfiguration
  A06 - Vulnerable Components    (checked via response header analysis)
  A07 - Identification & Auth Failures
  A08 - Software & Data Integrity Failures
  A09 - Security Logging Failures (checked via audit trail probes)
  A10 - SSRF
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import time


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL      = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES     = "A02:2021 - Cryptographic Failures"
    A03_INJECTION                  = "A03:2021 - Injection"
    A04_INSECURE_DESIGN            = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIG         = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS      = "A06:2021 - Vulnerable & Outdated Components"
    A07_AUTH_FAILURES              = "A07:2021 - Identification & Authentication Failures"
    A08_DATA_INTEGRITY             = "A08:2021 - Software & Data Integrity Failures"
    A09_LOGGING_FAILURES           = "A09:2021 - Security Logging & Monitoring Failures"
    A10_SSRF                       = "A10:2021 - Server-Side Request Forgery"


@dataclass
class OWASPFinding:
    probe:          str
    owasp_category: OWASPCategory
    severity:       Severity
    title:          str
    detail:         str
    evidence:       Optional[str] = None
    request_url:    Optional[str] = None
    request_method: Optional[str] = None
    status_code:    Optional[int] = None
    remediation:    Optional[str] = None
    cwe_id:         Optional[str] = None
    cvss_score:     Optional[float] = None
    timestamp:      float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "probe":          self.probe,
            "owasp_category": self.owasp_category.value,
            "severity":       self.severity.value,
            "title":          self.title,
            "detail":         self.detail,
            "evidence":       self.evidence,
            "request_url":    self.request_url,
            "request_method": self.request_method,
            "status_code":    self.status_code,
            "remediation":    self.remediation,
            "cwe_id":         self.cwe_id,
            "cvss_score":     self.cvss_score,
            "timestamp":      self.timestamp,
        }

    def __str__(self) -> str:
        cat = self.owasp_category.value.split(" - ")[0]
        return f"[{self.severity.value:8s}] [{cat}] {self.title}"


class OWASPBaseProbe(ABC):
    """Abstract base for all OWASP probes."""

    name:        str = "base"
    category:    OWASPCategory = OWASPCategory.A05_SECURITY_MISCONFIG
    description: str = ""

    @abstractmethod
    def run(self, base_url: str, session: Any, **kwargs) -> list[OWASPFinding]:
        """Execute probe and return findings. Empty list = no issues found."""
        ...
