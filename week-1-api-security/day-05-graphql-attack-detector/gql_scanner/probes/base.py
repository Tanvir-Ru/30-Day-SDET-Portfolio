"""
Base probe interface and GraphQLFinding data model.

GraphQL attack surface differs from REST because:
  - A single endpoint handles all operations
  - Schema is self-describing via introspection
  - Query complexity is client-controlled (batching, nesting, aliases)
  - Errors are returned with HTTP 200 (not 4xx/5xx)
  - Type system creates unique injection vectors

Finding categories mirror the GraphQL-specific OWASP checklist:
  INTROSPECTION      — schema exposed in production
  DEPTH_ATTACK       — deeply nested queries amplify server cost
  BATCHING_ABUSE     — query batching bypasses per-request rate limits
  FIELD_SUGGESTION   — error oracle leaks schema without introspection
  ALIAS_OVERLOAD     — field aliasing multiplies resolver execution
  DIRECTIVE_ABUSE    — deprecated/experimental directives exploitable
  INJECTION          — SQL/NoSQL/SSTI through argument fields
  INFORMATION_LEAK   — stack traces, internal paths in GQL errors
  RATE_LIMIT_BYPASS  — multiple attack vectors to bypass limits
  CSRF               — GQL via GET or no CSRF token check
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


class AttackCategory(str, Enum):
    INTROSPECTION      = "introspection"
    DEPTH_ATTACK       = "depth_attack"
    BATCHING_ABUSE     = "batching_abuse"
    FIELD_SUGGESTION   = "field_suggestion"
    ALIAS_OVERLOAD     = "alias_overload"
    DIRECTIVE_ABUSE    = "directive_abuse"
    INJECTION          = "injection"
    INFORMATION_LEAK   = "information_leak"
    RATE_LIMIT_BYPASS  = "rate_limit_bypass"
    CSRF               = "csrf"
    DOS                = "dos"


@dataclass
class GraphQLFinding:
    probe:         str
    category:      AttackCategory
    severity:      Severity
    title:         str
    detail:        str
    evidence:      Optional[str] = None
    query_used:    Optional[str] = None
    endpoint:      Optional[str] = None
    status_code:   Optional[int] = None
    response_ms:   Optional[float] = None
    remediation:   Optional[str] = None
    cwe_id:        Optional[str] = None
    cvss_score:    Optional[float] = None
    timestamp:     float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "probe":       self.probe,
            "category":    self.category.value,
            "severity":    self.severity.value,
            "title":       self.title,
            "detail":      self.detail,
            "evidence":    self.evidence,
            "query_used":  self.query_used,
            "endpoint":    self.endpoint,
            "status_code": self.status_code,
            "response_ms": round(self.response_ms, 2) if self.response_ms else None,
            "remediation": self.remediation,
            "cwe_id":      self.cwe_id,
            "cvss_score":  self.cvss_score,
            "timestamp":   self.timestamp,
        }

    def __str__(self) -> str:
        return f"[{self.severity.value:8s}] [{self.category.value}] {self.title}"


class GraphQLBaseProbe(ABC):
    """Abstract base for all GraphQL attack probes."""

    name:        str = "base"
    category:    AttackCategory = AttackCategory.INTROSPECTION
    description: str = ""

    @abstractmethod
    def run(self, endpoint: str, session: Any, **kwargs) -> list[GraphQLFinding]:
        """Execute probe and return findings. Empty list = no issues found."""
        ...
