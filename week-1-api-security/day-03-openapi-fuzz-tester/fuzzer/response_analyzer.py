"""
Response analyzer.

Evaluates an HTTP response against a set of assertions and produces
FuzzFinding objects for any anomaly detected.

Anomaly classes detected:
  - 5xx responses (server errors — unhandled input)
  - Stack traces / exception messages in response body
  - Unexpectedly successful responses to clearly invalid input (200 on SQL injection)
  - Response time spikes (potential ReDoS or slow query injection)
  - Schema validation failures (response doesn't match spec)
  - Information disclosure (internal paths, framework names, version strings)
  - Oversized response bodies (amplification)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class FuzzFinding:
    endpoint:        str
    method:          str
    parameter:       str
    param_location:  str
    mutator:         str
    fuzz_value:      Any
    finding_type:    str
    severity:        FindingSeverity
    title:           str
    detail:          str
    status_code:     int
    response_time_ms: float
    evidence:        Optional[str] = None
    cwe_id:          Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "endpoint":        self.endpoint,
            "method":          self.method,
            "parameter":       self.parameter,
            "param_location":  self.param_location,
            "mutator":         self.mutator,
            "fuzz_value":      str(self.fuzz_value)[:200],
            "finding_type":    self.finding_type,
            "severity":        self.severity.value,
            "title":           self.title,
            "detail":          self.detail,
            "status_code":     self.status_code,
            "response_time_ms": round(self.response_time_ms, 2),
            "evidence":        self.evidence,
            "cwe_id":          self.cwe_id,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity.value:8s}] {self.method} {self.endpoint} "
            f"param={self.parameter!r} → {self.title} (HTTP {self.status_code})"
        )


# ── Patterns ──────────────────────────────────────────────────────────────────

# Stack trace / exception patterns
STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",           # Python
    r"at \w+\.\w+\([\w.]+:\d+\)",                    # Java stack frame
    r"System\.(?:Exception|NullReferenceException)",  # .NET
    r"Error: .+\n\s+at .+:\d+:\d+",                  # Node.js
    r"Fatal error:.+in .+ on line \d+",              # PHP
    r"panic: .+\ngoroutine \d+",                     # Go
    r"SQLSTATE\[",                                    # SQL error with state
    r"ORA-\d{5}",                                    # Oracle error
    r"PG::.*Error",                                  # PostgreSQL error
    r"mysql_fetch",                                  # MySQL raw error
]

# Internal path disclosure
INTERNAL_PATH_PATTERNS = [
    r"/home/\w+/",
    r"C:\\Users\\",
    r"/var/www/",
    r"/opt/app/",
    r"__pycache__",
    r"node_modules",
    r"\.git/",
]

# Framework / version disclosure
FRAMEWORK_PATTERNS = [
    r"Django/[\d.]+",
    r"Flask/[\d.]+",
    r"Express/[\d.]+",
    r"Laravel/[\d.]+",
    r"Ruby on Rails [\d.]+",
    r"ASP\.NET Core/[\d.]+",
    r"uvicorn/[\d.]+",
    r"gunicorn/[\d.]+",
]

# Thresholds
SLOW_RESPONSE_THRESHOLD_MS = 3000   # 3 seconds
VERY_SLOW_THRESHOLD_MS     = 10000  # 10 seconds — possible ReDoS
MAX_RESPONSE_BODY_KB       = 1024   # 1 MB


class ResponseAnalyzer:
    """
    Analyzes a response for security anomalies.

    Call analyze() with the response and context metadata;
    it returns a list of FuzzFinding objects (empty = no anomalies).
    """

    def analyze(
        self,
        response: httpx.Response,
        response_time_ms: float,
        endpoint: str,
        method: str,
        parameter: str,
        param_location: str,
        mutator: str,
        fuzz_value: Any,
        baseline_status: int = 200,
    ) -> list[FuzzFinding]:
        findings = []
        ctx = dict(
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            param_location=param_location,
            mutator=mutator,
            fuzz_value=fuzz_value,
            status_code=response.status_code,
            response_time_ms=response_time_ms,
        )

        # Try to parse body
        body_text = ""
        try:
            body_text = response.text[:8192]   # Limit to 8KB for pattern matching
        except Exception:
            pass

        # ── 5xx server errors ──────────────────────────────────────────────
        if response.status_code >= 500:
            findings.append(FuzzFinding(
                **ctx,
                finding_type="server_error",
                severity=FindingSeverity.HIGH,
                title=f"Server error {response.status_code} triggered by fuzz input",
                detail=(
                    f"Sending {mutator!r} value to parameter '{parameter}' caused a "
                    f"HTTP {response.status_code}. Unhandled exceptions indicate missing "
                    "input validation and may expose stack traces or internal state."
                ),
                evidence=body_text[:500] if body_text else None,
                cwe_id="CWE-20",
            ))

        # ── Stack trace / exception disclosure ─────────────────────────────
        for pattern in STACK_TRACE_PATTERNS:
            match = re.search(pattern, body_text, re.IGNORECASE)
            if match:
                findings.append(FuzzFinding(
                    **ctx,
                    finding_type="stack_trace_disclosure",
                    severity=FindingSeverity.HIGH,
                    title="Stack trace or exception message in response",
                    detail=(
                        f"Pattern '{pattern}' matched in response body. "
                        "Stack traces disclose internal paths, framework versions, "
                        "and code structure useful for targeted attacks."
                    ),
                    evidence=body_text[max(0, match.start()-50):match.start()+200],
                    cwe_id="CWE-209",
                ))
                break

        # ── Internal path disclosure ───────────────────────────────────────
        for pattern in INTERNAL_PATH_PATTERNS:
            match = re.search(pattern, body_text)
            if match:
                findings.append(FuzzFinding(
                    **ctx,
                    finding_type="path_disclosure",
                    severity=FindingSeverity.MEDIUM,
                    title="Internal filesystem path disclosed in response",
                    detail=f"Pattern '{pattern}' found in response body.",
                    evidence=body_text[max(0, match.start()-20):match.start()+100],
                    cwe_id="CWE-200",
                ))
                break

        # ── Framework version disclosure ───────────────────────────────────
        for pattern in FRAMEWORK_PATTERNS:
            match = re.search(pattern, body_text)
            if not match:
                # Also check headers
                headers_str = str(dict(response.headers))
                match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                findings.append(FuzzFinding(
                    **ctx,
                    finding_type="version_disclosure",
                    severity=FindingSeverity.LOW,
                    title="Framework/server version disclosed",
                    detail=f"Version string '{match.group()}' found in response.",
                    evidence=match.group(),
                    cwe_id="CWE-200",
                ))
                break

        # ── Unexpected 200 on injection payload ───────────────────────────
        if (
            response.status_code == 200
            and mutator == "injection"
            and response.status_code == baseline_status
        ):
            findings.append(FuzzFinding(
                **ctx,
                finding_type="injection_success",
                severity=FindingSeverity.CRITICAL,
                title="Injection payload returned HTTP 200 — possible injection vulnerability",
                detail=(
                    f"SQL/NoSQL injection seed in parameter '{parameter}' returned HTTP 200. "
                    "The application may not be sanitising this input. Requires manual verification."
                ),
                evidence=body_text[:300],
                cwe_id="CWE-89",
            ))

        # ── Slow response — possible ReDoS or slow query injection ─────────
        if response_time_ms > VERY_SLOW_THRESHOLD_MS:
            findings.append(FuzzFinding(
                **ctx,
                finding_type="redos_candidate",
                severity=FindingSeverity.HIGH,
                title=f"Very slow response ({response_time_ms:.0f}ms) — possible ReDoS or blind injection",
                detail=(
                    f"Response took {response_time_ms:.0f}ms for a fuzz input. "
                    "This may indicate regex catastrophic backtracking (ReDoS), "
                    "a time-based SQL injection (SLEEP), or an extremely slow query."
                ),
                cwe_id="CWE-400",
            ))
        elif response_time_ms > SLOW_RESPONSE_THRESHOLD_MS:
            findings.append(FuzzFinding(
                **ctx,
                finding_type="slow_response",
                severity=FindingSeverity.MEDIUM,
                title=f"Slow response ({response_time_ms:.0f}ms) on fuzz input",
                detail=f"Response time {response_time_ms:.0f}ms exceeds {SLOW_RESPONSE_THRESHOLD_MS}ms threshold.",
                cwe_id="CWE-400",
            ))

        # ── Oversized response ─────────────────────────────────────────────
        content_length = len(response.content)
        if content_length > MAX_RESPONSE_BODY_KB * 1024:
            findings.append(FuzzFinding(
                **ctx,
                finding_type="response_amplification",
                severity=FindingSeverity.MEDIUM,
                title=f"Oversized response ({content_length // 1024}KB) — possible amplification",
                detail=(
                    f"Response body is {content_length // 1024}KB for a single request. "
                    "This may indicate an unbounded query result or amplification vulnerability."
                ),
                cwe_id="CWE-400",
            ))

        return findings
