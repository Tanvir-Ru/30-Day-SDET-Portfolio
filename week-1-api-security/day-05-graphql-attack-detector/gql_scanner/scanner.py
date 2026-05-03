"""
GraphQL Attack Surface Scanner — main orchestrator.

Runs all probes against a GraphQL endpoint and produces a structured
JSON + text report with attack category breakdown.

Usage (CLI):
    python -m gql_scanner.scanner --endpoint http://localhost:4000/graphql
    python -m gql_scanner.scanner --endpoint https://api.example.com/graphql --token Bearer_xyz
    python -m gql_scanner.scanner --endpoint http://localhost:4000/graphql --output json

Usage (library):
    from gql_scanner.scanner import GraphQLScanner
    scanner = GraphQLScanner("http://localhost:4000/graphql")
    report  = scanner.run()
    print(report.summary())
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from gql_scanner.probes.base import GraphQLFinding, Severity, AttackCategory
from gql_scanner.probes.introspection_probe import IntrospectionProbe
from gql_scanner.probes.depth_probe import DepthComplexityProbe
from gql_scanner.probes.batching_probe import BatchingAbuseProbe
from gql_scanner.probes.field_injection_probe import FieldSuggestionProbe, InjectionProbe


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}


@dataclass
class GraphQLScanReport:
    endpoint:        str
    findings:        list[GraphQLFinding]
    probes_run:      list[str]
    scan_duration_s: float
    timestamp:       float = field(default_factory=time.time)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def risk_score(self) -> float:
        weights = {
            Severity.CRITICAL: 25, Severity.HIGH: 10,
            Severity.MEDIUM: 4,   Severity.LOW: 1, Severity.INFO: 0,
        }
        return min(100.0, sum(weights.get(f.severity, 0) for f in self.findings))

    def by_category(self) -> dict[str, list[GraphQLFinding]]:
        result: dict[str, list[GraphQLFinding]] = {}
        for f in self.findings:
            result.setdefault(f.category.value, []).append(f)
        return result

    def summary(self) -> str:
        sorted_f = sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
        med  = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low  = sum(1 for f in self.findings if f.severity == Severity.LOW)
        lines = [
            "=" * 70,
            "GRAPHQL ATTACK SURFACE SCAN REPORT",
            "=" * 70,
            f"Endpoint     : {self.endpoint}",
            f"Probes run   : {', '.join(self.probes_run)}",
            f"Duration     : {self.scan_duration_s:.1f}s",
            f"Risk Score   : {self.risk_score:.0f}/100",
            f"Findings     : {len(self.findings)} total  "
            f"({self.critical_count} CRITICAL, {self.high_count} HIGH, {med} MEDIUM, {low} LOW)",
            "",
        ]
        for f in sorted_f:
            if f.severity == Severity.INFO:
                continue
            lines.append(f"  [{f.severity.value:8s}] [{f.category.value}]")
            lines.append(f"               {f.title}")
            if f.cwe_id:
                lines.append(f"               {f.cwe_id}  CVSS {f.cvss_score}")
            if f.remediation:
                lines.append(f"               Fix: {f.remediation[:90]}")
            lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "endpoint":        self.endpoint,
            "timestamp":       self.timestamp,
            "scan_duration_s": round(self.scan_duration_s, 2),
            "risk_score":      self.risk_score,
            "probes_run":      self.probes_run,
            "summary": {
                "critical": self.critical_count,
                "high":     self.high_count,
                "medium":   sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low":      sum(1 for f in self.findings if f.severity == Severity.LOW),
                "total":    len(self.findings),
            },
            "findings": [
                f.to_dict() for f in sorted(
                    self.findings, key=lambda f: SEVERITY_ORDER[f.severity]
                )
            ],
            "by_category": {
                cat: [f.to_dict() for f in findings]
                for cat, findings in self.by_category().items()
            },
        }


class GraphQLScanner:
    """Orchestrates all GraphQL attack probes against a target endpoint."""

    def __init__(
        self,
        endpoint:    str,
        auth_token:  str = None,
        timeout:     float = 20.0,
        login_field: str = "login",
    ):
        self.endpoint    = endpoint
        self.auth_token  = auth_token
        self.timeout     = timeout
        self.login_field = login_field

        self._probes = [
            IntrospectionProbe(),
            DepthComplexityProbe(),
            BatchingAbuseProbe(),
            FieldSuggestionProbe(),
            InjectionProbe(),
        ]

    def run(self) -> GraphQLScanReport:
        start   = time.perf_counter()
        session = httpx.Client(timeout=self.timeout, follow_redirects=True)
        all_findings: list[GraphQLFinding] = []
        probes_run = []

        for probe in self._probes:
            print(f"  → {probe.name}", flush=True)
            probes_run.append(probe.name)
            try:
                findings = probe.run(
                    endpoint=self.endpoint,
                    session=session,
                    auth_token=self.auth_token,
                    login_field=self.login_field,
                )
                all_findings.extend(findings)
                visible = [f for f in findings if f.severity != Severity.INFO]
                print(f"     {len(visible)} finding(s)", flush=True)
            except Exception as e:
                print(f"     WARNING: {probe.name} failed: {e}", flush=True)

        session.close()
        return GraphQLScanReport(
            endpoint=self.endpoint,
            findings=all_findings,
            probes_run=probes_run,
            scan_duration_s=time.perf_counter() - start,
        )


def main():
    parser = argparse.ArgumentParser(description="GraphQL Attack Surface Detector")
    parser.add_argument("--endpoint", required=True, help="GraphQL endpoint URL")
    parser.add_argument("--token",    help="Bearer token for auth")
    parser.add_argument("--output",   choices=["text", "json"], default="text")
    parser.add_argument("--out-file", default="gql-report", help="Output file basename")
    args = parser.parse_args()

    print(f"GraphQL Attack Surface Scanner → {args.endpoint}\n")
    scanner = GraphQLScanner(endpoint=args.endpoint, auth_token=args.token)
    report  = scanner.run()
    print()

    if args.output == "json":
        out = f"{args.out_file}.json"
        Path(out).write_text(json.dumps(report.to_dict(), indent=2))
        print(f"JSON report: {out}")
    else:
        print(report.summary())

    sys.exit(1 if report.critical_count > 0 or report.high_count > 0 else 0)


if __name__ == "__main__":
    main()
