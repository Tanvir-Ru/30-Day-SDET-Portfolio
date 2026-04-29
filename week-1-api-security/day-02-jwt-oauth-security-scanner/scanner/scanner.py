"""
JWT / OAuth 2.0 Security Scanner — main orchestrator.

Runs all probes against a JWT token and produces a structured report.
Can be used as a library or run directly from the CLI.

Usage (CLI):
    python -m scanner.scanner --token "eyJ..." --type access
    python -m scanner.scanner --token-file token.txt --issuer https://auth.example.com
    python -m scanner.scanner --token "eyJ..." --output json > report.json

Usage (library):
    from scanner.scanner import JWTSecurityScanner
    scanner = JWTSecurityScanner()
    report = scanner.scan(token="eyJ...", token_type="access")
    print(report.summary())
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from scanner.jwt_decoder import decode_jwt, JWTAnalysis
from scanner.probes.base import SecurityFinding, Severity
from scanner.probes.expiry_probe import TokenExpiryProbe
from scanner.probes.algorithm_probe import AlgorithmConfusionProbe
from scanner.probes.scope_probe import ScopeOverflowProbe
from scanner.probes.replay_probe import ReplayAttackProbe


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class ScanReport:
    token_analysis: JWTAnalysis
    findings: list[SecurityFinding]
    scan_duration_ms: float
    scanner_version: str = "1.0.0"
    timestamp: float = field(default_factory=time.time)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def risk_score(self) -> float:
        """Weighted risk score 0–100."""
        weights = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1}
        return min(100.0, sum(weights.get(f.severity, 0) for f in self.findings))

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "JWT SECURITY SCAN REPORT",
            "=" * 60,
            f"Algorithm    : {self.token_analysis.algorithm}",
            f"Subject      : {self.token_analysis.subject or 'N/A'}",
            f"Issuer       : {self.token_analysis.issuer or 'N/A'}",
            f"Scopes       : {', '.join(self.token_analysis.scopes) or 'None'}",
            f"Expired      : {self.token_analysis.is_expired}",
            f"Scan time    : {self.scan_duration_ms:.1f}ms",
            "",
            f"Risk Score   : {self.risk_score:.0f}/100",
            f"Findings     : {len(self.findings)} total  "
            f"({self.critical_count} CRITICAL, {self.high_count} HIGH, "
            f"{self.medium_count} MEDIUM, {self.low_count} LOW)",
            "",
        ]

        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
        for finding in sorted_findings:
            lines.append(f"  [{finding.severity.value:8s}] {finding.title}")
            lines.append(f"             {finding.detail[:80]}...")
            if finding.cwe_id:
                lines.append(f"             {finding.cwe_id}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "scanner_version": self.scanner_version,
            "timestamp": self.timestamp,
            "scan_duration_ms": self.scan_duration_ms,
            "risk_score": self.risk_score,
            "token": {
                "algorithm": self.token_analysis.algorithm,
                "subject": self.token_analysis.subject,
                "issuer": self.token_analysis.issuer,
                "audience": self.token_analysis.audience,
                "scopes": self.token_analysis.scopes,
                "is_expired": self.token_analysis.is_expired,
                "expires_at": self.token_analysis.expires_at,
            },
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda f: SEVERITY_ORDER[f.severity]
            )],
        }


class JWTSecurityScanner:
    """
    Orchestrates all security probes against a JWT token.

    Designed to be extended: add new probes by instantiating them
    and appending to self.probes in __init__.
    """

    def __init__(
        self,
        allowed_algorithms: list[str] = None,
        expected_issuer: str = None,
        expected_audience: str = None,
        expected_scopes: list[str] = None,
    ):
        self.allowed_algorithms = allowed_algorithms
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.expected_scopes = expected_scopes

        self.probes = [
            TokenExpiryProbe(),
            AlgorithmConfusionProbe(),
            ScopeOverflowProbe(),
            ReplayAttackProbe(),
        ]

    def scan(self, token: str, token_type: str = "access") -> ScanReport:
        start = time.perf_counter()

        analysis = decode_jwt(token)
        all_findings: list[SecurityFinding] = []

        for probe in self.probes:
            try:
                kwargs = {}
                if isinstance(probe, TokenExpiryProbe):
                    kwargs["token_type"] = token_type
                elif isinstance(probe, AlgorithmConfusionProbe):
                    kwargs["allowed_algorithms"] = self.allowed_algorithms
                elif isinstance(probe, ScopeOverflowProbe):
                    kwargs["expected_scopes"] = self.expected_scopes
                elif isinstance(probe, ReplayAttackProbe):
                    kwargs["expected_issuer"] = self.expected_issuer
                    kwargs["expected_audience"] = self.expected_audience

                findings = probe.run(analysis, **kwargs)
                all_findings.extend(findings)
            except Exception as e:
                print(f"WARNING: Probe '{probe.name}' failed: {e}", file=sys.stderr)

        duration_ms = (time.perf_counter() - start) * 1000
        return ScanReport(
            token_analysis=analysis,
            findings=all_findings,
            scan_duration_ms=duration_ms,
        )


def main():
    parser = argparse.ArgumentParser(
        description="JWT / OAuth 2.0 Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--token", help="JWT token string")
    parser.add_argument("--token-file", help="File containing the JWT token")
    parser.add_argument("--type", choices=["access", "refresh"], default="access")
    parser.add_argument("--issuer", help="Expected issuer URI")
    parser.add_argument("--audience", help="Expected audience")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.token:
        token = args.token
    elif args.token_file:
        with open(args.token_file) as f:
            token = f.read().strip()
    else:
        print("ERROR: Provide --token or --token-file", file=sys.stderr)
        sys.exit(1)

    scanner = JWTSecurityScanner(
        expected_issuer=args.issuer,
        expected_audience=args.audience,
    )
    report = scanner.scan(token=token, token_type=args.type)

    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())

    sys.exit(1 if report.critical_count > 0 or report.high_count > 0 else 0)


if __name__ == "__main__":
    main()
