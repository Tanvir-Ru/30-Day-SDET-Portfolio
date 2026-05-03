"""
Probe: Query Batching Abuse & Rate Limit Bypass

GraphQL supports sending multiple operations in a single HTTP request
(batching). If rate limiting is applied at the HTTP request level
(not the operation level), batching allows:
  - 100 login attempts in 1 HTTP request
  - 1000 data exfiltration queries in 1 HTTP request
  - Brute-forcing OTP codes in a single request

This is one of the most underappreciated GraphQL security issues.
A WAF or API gateway that limits to 60 req/min sees 1 request;
the server executes 100 operations.

Also tests:
  - Batching size limits (is there a max batch size?)
  - Mixed operation batching (query + mutation together)
  - Timeout enforcement on batch requests

CWE-307: Improper Restriction of Excessive Authentication Attempts
CWE-770: Allocation of Resources Without Limits
"""

from __future__ import annotations

import time
import httpx

from gql_scanner.probes.base import GraphQLBaseProbe, GraphQLFinding, AttackCategory, Severity
from gql_scanner.gql_client import GQLClient


class BatchingAbuseProbe(GraphQLBaseProbe):
    name        = "batching_abuse"
    category    = AttackCategory.BATCHING_ABUSE
    description = "Tests batch query size limits and rate-limit bypass via batching"

    def run(self, endpoint: str, session: httpx.Client, **kwargs) -> list[GraphQLFinding]:
        findings = []
        auth_token      = kwargs.get("auth_token")
        login_field     = kwargs.get("login_field", "login")
        client          = GQLClient(endpoint, session, auth_token=auth_token)

        findings.extend(self._test_batch_size_limit(client, endpoint))
        findings.extend(self._test_rate_limit_bypass(client, endpoint, login_field))
        findings.extend(self._test_batch_mutation_amplification(client, endpoint))

        return findings

    def _test_batch_size_limit(
        self, client: GQLClient, endpoint: str
    ) -> list[GraphQLFinding]:
        """Send progressively larger batches to find the limit."""
        findings = []
        BATCH_SIZES = [10, 50, 100, 500]

        baseline_resp = client.query("{ __typename }")
        if baseline_resp.status_code == 0:
            return findings   # Can't reach server

        for batch_size in BATCH_SIZES:
            batch = [
                {"query": "{ __typename }", "operationName": f"Op{i}"}
                for i in range(batch_size)
            ]

            t0   = time.perf_counter()
            resp = client.batch(batch)
            ms   = (time.perf_counter() - t0) * 1000

            if resp.status_code in (200, 201) and not resp.has_errors:
                severity = Severity.HIGH if batch_size >= 100 else Severity.MEDIUM
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=severity,
                    title=f"No batch size limit — {batch_size} operations accepted in one request",
                    detail=(
                        f"A batch of {batch_size} GraphQL operations was accepted in a single HTTP request. "
                        f"Response time: {ms:.0f}ms. "
                        "Rate limits applied at the HTTP level are bypassed entirely: "
                        f"an attacker gets {batch_size}× the operations per rate-limit window."
                    ),
                    evidence=f"batch_size={batch_size}, HTTP {resp.status_code}, {ms:.0f}ms",
                    query_used=f"[batch of {batch_size} × {{__typename}}]",
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=ms,
                    remediation=(
                        "Implement batch size limits (recommended: max 10 operations per batch). "
                        "Apply rate limiting at the operation level, not the HTTP request level. "
                        "Consider disabling batching entirely if not required."
                    ),
                    cwe_id="CWE-770",
                    cvss_score=7.5 if batch_size >= 100 else 5.3,
                ))
                break   # Found the limit (or lack of it) — stop escalating

            elif resp.status_code == 429 or (resp.has_errors and "limit" in str(resp.errors).lower()):
                # Found the limit — this is good, no finding
                break

        return findings

    def _test_rate_limit_bypass(
        self, client: GQLClient, endpoint: str, login_field: str
    ) -> list[GraphQLFinding]:
        """
        Simulate credential stuffing via batch — 100 login attempts in 1 request.
        This is a CRITICAL finding: brute-force in a single HTTP request.
        """
        findings = []

        # Build 20 login attempts (kept low to avoid actually brute-forcing)
        ATTEMPT_COUNT = 20
        batch = [
            {
                "query": f"""
                    mutation LoginAttempt_{i} {{
                        {login_field}(
                            username: "admin",
                            password: "attempt_{i}_wrong_pw"
                        ) {{
                            token
                        }}
                    }}
                """,
                "operationName": f"LoginAttempt_{i}",
            }
            for i in range(ATTEMPT_COUNT)
        ]

        resp = client.batch(batch)

        # If all operations ran (even with errors) — the batch was processed
        if resp.status_code in (200, 201):
            batch_results = resp.field_data("batch_results") or []
            executed_count = len(batch_results) if isinstance(batch_results, list) else ATTEMPT_COUNT

            if executed_count >= 5:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=AttackCategory.RATE_LIMIT_BYPASS,
                    severity=Severity.CRITICAL,
                    title=f"Credential stuffing via batch — {executed_count} login attempts in 1 HTTP request",
                    detail=(
                        f"Sent {ATTEMPT_COUNT} login mutation attempts in a single HTTP request "
                        f"and {executed_count} operations were executed. "
                        "An attacker can attempt thousands of passwords against an account "
                        "while appearing to the rate limiter as a single request. "
                        "OTP brute-forcing (10000 combinations) fits in ~100 batched requests."
                    ),
                    evidence=f"{executed_count} login mutations executed in one HTTP request",
                    query_used=f"[batch of {ATTEMPT_COUNT} login mutations]",
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=resp.elapsed_ms,
                    remediation=(
                        "Apply rate limiting per operation name, not per HTTP request. "
                        "Limit batched mutations: max 1–3 mutations per batch. "
                        "Use CAPTCHA / device fingerprinting on auth endpoints."
                    ),
                    cwe_id="CWE-307",
                    cvss_score=9.1,
                ))

        return findings

    def _test_batch_mutation_amplification(
        self, client: GQLClient, endpoint: str
    ) -> list[GraphQLFinding]:
        """Test if multiple mutations in a batch all execute (write amplification)."""
        findings = []

        # Send 5 identical mutations in one batch
        MUTATION_COUNT = 5
        batch = [
            {
                "query": "mutation { createUser(name: \"fuzz_test_user\", email: \"fuzz@test.com\") { id } }",
                "operationName": f"CreateUser{i}",
            }
            for i in range(MUTATION_COUNT)
        ]

        resp = client.batch(batch)

        if resp.status_code in (200, 201):
            batch_results = resp.field_data("batch_results") or []
            # Count successful mutations (have data, no errors)
            successful = 0
            if isinstance(batch_results, list):
                successful = sum(
                    1 for r in batch_results
                    if isinstance(r, dict) and r.get("data") and not r.get("errors")
                )

            if successful >= 2:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Write amplification — {successful}/{MUTATION_COUNT} mutations executed in one batch",
                    detail=(
                        f"{successful} of {MUTATION_COUNT} identical mutations executed in a single HTTP request. "
                        "An attacker can amplify write operations (account creation, data modification) "
                        f"{successful}× without triggering per-request rate limits."
                    ),
                    evidence=f"{successful} successful mutations in one batched request",
                    query_used=f"[batch of {MUTATION_COUNT} createUser mutations]",
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=resp.elapsed_ms,
                    remediation=(
                        "Limit the number of mutations per batch to 1. "
                        "Apply per-operation rate limits for mutations."
                    ),
                    cwe_id="CWE-770",
                    cvss_score=7.5,
                ))

        return findings
