"""
OpenAPI Fuzz Test Engine — main orchestrator.

Ties together: spec parsing → baseline request → mutation generation →
request sending → response analysis → finding aggregation → reporting.

Usage (CLI):
    python -m fuzzer.engine --spec openapi.yaml --base-url http://localhost:8000
    python -m fuzzer.engine --spec https://api.example.com/openapi.json --token Bearer_xyz
    python -m fuzzer.engine --spec openapi.yaml --endpoint "POST /users" --mutators injection,boundary

Usage (library):
    from fuzzer.engine import FuzzEngine
    engine = FuzzEngine(spec_path="openapi.yaml", base_url="http://localhost:8000")
    report = engine.run()
    print(report.summary())
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from fuzzer.spec_parser import OpenAPIParser, EndpointSpec, APISpec
from fuzzer.mutators.payload_mutators import generate_mutations, ALL_MUTATORS
from fuzzer.request_builder import FuzzRequestBuilder
from fuzzer.response_analyzer import ResponseAnalyzer, FuzzFinding, FindingSeverity


SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH:     1,
    FindingSeverity.MEDIUM:   2,
    FindingSeverity.LOW:      3,
    FindingSeverity.INFO:     4,
}


# ── Report model ──────────────────────────────────────────────────────────────

@dataclass
class FuzzReport:
    api_title:           str
    api_version:         str
    base_url:            str
    endpoints_tested:    int
    total_requests:      int
    findings:            list[FuzzFinding]
    coverage:            dict            # endpoint → list of tested parameters
    duration_seconds:    float
    timestamp:           float = field(default_factory=time.time)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    def summary(self) -> str:
        lines = [
            "=" * 70,
            "OPENAPI FUZZ TEST REPORT",
            "=" * 70,
            f"API              : {self.api_title} v{self.api_version}",
            f"Base URL         : {self.base_url}",
            f"Endpoints tested : {self.endpoints_tested}",
            f"Total requests   : {self.total_requests}",
            f"Duration         : {self.duration_seconds:.1f}s",
            f"Requests/sec     : {self.total_requests / max(self.duration_seconds, 0.1):.0f}",
            "",
            f"Findings         : {len(self.findings)} total "
            f"({self.critical_count} CRITICAL, {self.high_count} HIGH, "
            f"{sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)} MEDIUM, "
            f"{sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)} LOW)",
            "",
        ]

        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
        for finding in sorted_findings:
            lines.append(f"  [{finding.severity.value:8s}] {finding.method} {finding.endpoint}")
            lines.append(f"               param={finding.parameter!r} ({finding.param_location})")
            lines.append(f"               {finding.title}")
            if finding.cwe_id:
                lines.append(f"               {finding.cwe_id}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "api": {"title": self.api_title, "version": self.api_version, "base_url": self.base_url},
            "stats": {
                "endpoints_tested": self.endpoints_tested,
                "total_requests": self.total_requests,
                "duration_seconds": round(self.duration_seconds, 2),
            },
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "total": len(self.findings),
            },
            "findings": [
                f.to_dict() for f in sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
            ],
            "coverage": self.coverage,
        }


# ── Fuzz engine ───────────────────────────────────────────────────────────────

class FuzzEngine:
    """
    Orchestrates the full fuzz test cycle for an OpenAPI spec.

    For each endpoint × parameter × mutator combination:
      1. Build a valid baseline request
      2. Confirm baseline returns expected status (skip if API is broken)
      3. For each mutation: send request, analyze response, collect findings
    """

    def __init__(
        self,
        spec_path: str,
        base_url: str = None,
        auth_token: str = None,
        timeout: float = 15.0,
        endpoint_filter: str = None,
        mutator_filter: list[str] = None,
        max_mutations_per_param: int = 50,
        skip_baseline: bool = False,
        verbose: bool = False,
    ):
        self.spec_path           = spec_path
        self.base_url            = base_url
        self.auth_token          = auth_token
        self.timeout             = timeout
        self.endpoint_filter     = endpoint_filter
        self.mutator_filter      = mutator_filter
        self.max_per_param       = max_mutations_per_param
        self.skip_baseline       = skip_baseline
        self.verbose             = verbose

    def run(self) -> FuzzReport:
        start = time.perf_counter()

        # Parse spec
        parser = OpenAPIParser(self.spec_path)
        api_spec = parser.parse(self.base_url)

        builder  = FuzzRequestBuilder(api_spec, self.auth_token)
        analyzer = ResponseAnalyzer()

        all_findings: list[FuzzFinding] = []
        total_requests = 0
        coverage: dict[str, list[str]] = {}

        # Filter endpoints if requested
        endpoints = api_spec.endpoints
        if self.endpoint_filter:
            method, _, path = self.endpoint_filter.partition(" ")
            endpoints = [
                e for e in endpoints
                if (not method or e.method.upper() == method.upper())
                and (not path or path in e.path)
            ]

        client = httpx.Client(timeout=self.timeout, follow_redirects=True)

        for endpoint in endpoints:
            ep_id = endpoint.endpoint_id
            coverage[ep_id] = []

            if self.verbose:
                print(f"\n→ {ep_id}", flush=True)

            # ── Baseline check ─────────────────────────────────────────────
            baseline_status = 200
            if not self.skip_baseline:
                try:
                    baseline_req  = builder.build_baseline(endpoint)
                    baseline_resp = client.send(baseline_req)
                    baseline_status = baseline_resp.status_code
                    total_requests += 1
                    if self.verbose:
                        print(f"  baseline: HTTP {baseline_status}", flush=True)
                    # Skip endpoint if baseline is already broken
                    if baseline_status >= 500:
                        print(f"  SKIP: baseline returned {baseline_status}", flush=True)
                        continue
                except Exception as e:
                    if self.verbose:
                        print(f"  SKIP: baseline request failed: {e}", flush=True)
                    continue

            # ── Parameter fuzzing ──────────────────────────────────────────
            fuzz_targets = []

            # Path + query parameters
            for param in endpoint.parameters:
                fuzz_targets.append((param.name, param.location, param.schema))

            # Request body fields
            if endpoint.request_body:
                body_schema = endpoint.request_body.schema
                if body_schema.get("type") == "object":
                    for field_name, field_schema in body_schema.get("properties", {}).items():
                        fuzz_targets.append((field_name, "body", field_schema))
                else:
                    fuzz_targets.append(("body", "body", body_schema))

            for param_name, param_location, schema in fuzz_targets:
                mutations = generate_mutations(schema)

                # Apply mutator filter
                if self.mutator_filter:
                    mutations = [(m, v) for m, v in mutations if m in self.mutator_filter]

                # Cap mutations per parameter
                mutations = mutations[: self.max_per_param]

                coverage[ep_id].append(f"{param_location}:{param_name} ({len(mutations)} mutations)")

                for mutator_name, fuzz_value in mutations:
                    try:
                        req = builder.build_fuzzed(
                            endpoint, param_name, param_location, fuzz_value
                        )
                        t0 = time.perf_counter()
                        resp = client.send(req)
                        elapsed_ms = (time.perf_counter() - t0) * 1000
                        total_requests += 1

                        findings = analyzer.analyze(
                            response=resp,
                            response_time_ms=elapsed_ms,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=param_name,
                            param_location=param_location,
                            mutator=mutator_name,
                            fuzz_value=fuzz_value,
                            baseline_status=baseline_status,
                        )
                        all_findings.extend(findings)

                        if self.verbose and findings:
                            for f in findings:
                                print(f"  [{f.severity.value}] {f.title}", flush=True)

                    except httpx.TimeoutException:
                        total_requests += 1
                        all_findings.append(FuzzFinding(
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=param_name,
                            param_location=param_location,
                            mutator=mutator_name,
                            fuzz_value=fuzz_value,
                            finding_type="timeout",
                            severity=FindingSeverity.MEDIUM,
                            title=f"Request timed out after {self.timeout}s on fuzz input",
                            detail="Possible ReDoS or blind time-based injection.",
                            status_code=0,
                            response_time_ms=self.timeout * 1000,
                            cwe_id="CWE-400",
                        ))
                    except Exception:
                        total_requests += 1

        client.close()

        duration = time.perf_counter() - start
        return FuzzReport(
            api_title=api_spec.title,
            api_version=api_spec.version,
            base_url=api_spec.base_url,
            endpoints_tested=len(endpoints),
            total_requests=total_requests,
            findings=all_findings,
            coverage=coverage,
            duration_seconds=duration,
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OpenAPI Schema-Driven Fuzz Tester")
    parser.add_argument("--spec",       required=True, help="Path or URL to OpenAPI spec")
    parser.add_argument("--base-url",   help="Override server base URL")
    parser.add_argument("--token",      help="Bearer token for auth")
    parser.add_argument("--endpoint",   help="Filter: 'POST /users'")
    parser.add_argument("--mutators",   help="Comma-separated mutator names")
    parser.add_argument("--output",     choices=["text", "json"], default="text")
    parser.add_argument("--verbose",    action="store_true")
    args = parser.parse_args()

    mutator_filter = args.mutators.split(",") if args.mutators else None

    engine = FuzzEngine(
        spec_path=args.spec,
        base_url=args.base_url,
        auth_token=args.token,
        endpoint_filter=args.endpoint,
        mutator_filter=mutator_filter,
        verbose=args.verbose,
    )

    report = engine.run()

    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())

    sys.exit(1 if report.critical_count > 0 or report.high_count > 0 else 0)


if __name__ == "__main__":
    main()
