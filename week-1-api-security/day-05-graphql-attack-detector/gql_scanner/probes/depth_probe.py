"""
Probe: Query Depth & Complexity Attacks

GraphQL allows clients to request any nesting depth they want — unless
the server enforces limits. A single deeply-nested query can exponentially
amplify database load, triggering N+1 queries at each level.

Attack surface:
  - Circular/recursive types (User → friends → User → friends → ...)
  - Deep nesting amplifies resolver execution exponentially
  - Aliases multiply resolver cost without increasing query size
  - Fragments allow payload reuse to amplify complexity cheaply
  - Directive @include/@skip can sometimes bypass static analysis

CWE-400: Uncontrolled Resource Consumption
CWE-770: Allocation of Resources Without Limits or Throttling
"""

from __future__ import annotations

import time
import httpx

from gql_scanner.probes.base import GraphQLBaseProbe, GraphQLFinding, AttackCategory, Severity
from gql_scanner.gql_client import GQLClient


def _build_deep_query(type_name: str, field: str, depth: int) -> str:
    """Build a deeply nested query to test depth limiting."""
    inner = f"{{ {field} }}"
    for _ in range(depth - 1):
        inner = f"{{ {field} {inner} }}"
    return f"{{ {type_name} {inner} }}"


def _build_alias_overload(field: str, count: int) -> str:
    """Build a query using many aliases to multiply resolver cost."""
    aliases = "\n  ".join(f"f{i}: {field}" for i in range(count))
    return f"{{ {aliases} }}"


def _build_fragment_bomb(type_name: str, field: str, fragment_count: int) -> str:
    """Use fragments to alias the same expensive field many times."""
    fragments = "\n".join(
        f"fragment F{i} on {type_name} {{ {field} }}" for i in range(fragment_count)
    )
    spreads = " ".join(f"...F{i}" for i in range(fragment_count))
    return f"{{ {type_name} {{ {spreads} }} }}\n{fragments}"


class DepthComplexityProbe(GraphQLBaseProbe):
    name        = "depth_complexity"
    category    = AttackCategory.DEPTH_ATTACK
    description = "Tests query depth limits, alias overloading, fragment bombs, and complexity thresholds"

    # These are common field names in GraphQL APIs to use for depth attacks
    CANDIDATE_QUERY_FIELDS = [
        ("users",    "id"),
        ("user",     "id"),
        ("posts",    "id"),
        ("products", "id"),
        ("orders",   "id"),
        ("me",       "id"),
        ("nodes",    "id"),
    ]

    def run(self, endpoint: str, session: httpx.Client, **kwargs) -> list[GraphQLFinding]:
        findings = []
        auth_token     = kwargs.get("auth_token")
        schema_types   = kwargs.get("schema_types", {})
        client         = GQLClient(endpoint, session, auth_token=auth_token)

        # First discover a working field from baseline
        working_field  = self._discover_field(client)

        findings.extend(self._test_depth_limit(client, endpoint, working_field))
        findings.extend(self._test_alias_overload(client, endpoint, working_field))
        findings.extend(self._test_circular_reference(client, endpoint))
        findings.extend(self._test_field_duplication(client, endpoint, working_field))

        return findings

    def _discover_field(self, client: GQLClient) -> tuple[str, str]:
        """Find a working root query field to use for depth tests."""
        for type_name, field in self.CANDIDATE_QUERY_FIELDS:
            resp = client.query(f"{{ {type_name} {{ {field} }} }}")
            if not resp.has_errors or (resp.errors and "depth" not in str(resp.errors).lower()):
                return type_name, field
        return "users", "id"   # fallback

    def _test_depth_limit(
        self, client: GQLClient, endpoint: str, working_field: tuple
    ) -> list[GraphQLFinding]:
        findings = []
        type_name, field = working_field

        DEPTH_LEVELS = [5, 10, 15, 25, 50, 100]
        baseline_ms = None

        for depth in DEPTH_LEVELS:
            query = _build_deep_query(type_name, field, depth)
            t0    = time.perf_counter()
            resp  = client.query(query)
            ms    = (time.perf_counter() - t0) * 1000

            if baseline_ms is None and resp.status_code != 0:
                baseline_ms = ms

            # Server accepted a very deep query
            if depth >= 15 and not resp.has_errors:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.HIGH if depth >= 25 else Severity.MEDIUM,
                    title=f"No query depth limit — depth {depth} query accepted",
                    detail=(
                        f"A query nested {depth} levels deep was accepted without error. "
                        f"Response time: {ms:.0f}ms. "
                        "Without depth limits, attackers can craft queries that trigger "
                        "exponential resolver execution, exhausting database connections."
                    ),
                    evidence=f"depth={depth}, HTTP {resp.status_code}, {ms:.0f}ms",
                    query_used=query[:300],
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=ms,
                    remediation=(
                        "Set a maximum query depth (recommended: 10–15 for most APIs). "
                        "Use graphql-depth-limit (Node.js) or similar. "
                        "Combine with query complexity scoring."
                    ),
                    cwe_id="CWE-400",
                    cvss_score=7.5 if depth >= 25 else 5.3,
                ))
                # Don't keep escalating once we've found the vulnerability
                break

            # Slow response at moderate depth → amplification working
            if baseline_ms and ms > baseline_ms * 5 and depth >= 10:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    title=f"Query depth amplification — {depth} levels causes {ms:.0f}ms response",
                    detail=(
                        f"Depth-{depth} query took {ms:.0f}ms vs baseline {baseline_ms:.0f}ms "
                        f"({ms / baseline_ms:.1f}× amplification). "
                        "Even if depth is limited, response time scaling shows DB amplification."
                    ),
                    evidence=f"baseline={baseline_ms:.0f}ms, depth-{depth}={ms:.0f}ms",
                    query_used=query[:200],
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=ms,
                    remediation="Add query complexity scoring in addition to depth limiting.",
                    cwe_id="CWE-400",
                    cvss_score=5.3,
                ))
                break

        return findings

    def _test_alias_overload(
        self, client: GQLClient, endpoint: str, working_field: tuple
    ) -> list[GraphQLFinding]:
        """Many aliases of the same field → N × resolver cost for 1 request."""
        findings = []
        type_name, field = working_field
        ALIAS_COUNTS = [10, 50, 100, 500]

        baseline_resp = client.query(f"{{ {field} }}")
        baseline_ms   = baseline_resp.elapsed_ms

        for count in ALIAS_COUNTS:
            query = _build_alias_overload(field, count)
            resp  = client.query(query)

            if not resp.has_errors:
                amplification = resp.elapsed_ms / max(baseline_ms, 1)
                severity = Severity.HIGH if count >= 100 else Severity.MEDIUM

                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=AttackCategory.ALIAS_OVERLOAD,
                    severity=severity,
                    title=f"Alias overload accepted — {count} aliases resolved in one request",
                    detail=(
                        f"{count} aliases of '{field}' were resolved in a single query. "
                        f"Response time: {resp.elapsed_ms:.0f}ms ({amplification:.1f}× baseline). "
                        "Aliases bypass naive per-field rate limits because the query "
                        "appears to request only one field type."
                    ),
                    evidence=f"{count} aliases, {resp.elapsed_ms:.0f}ms, amplification={amplification:.1f}×",
                    query_used=query[:400],
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=resp.elapsed_ms,
                    remediation=(
                        "Implement query complexity scoring that counts aliased field "
                        "executions. Reject queries above a complexity threshold (e.g. 1000). "
                        "Libraries: graphql-cost-analysis, graphql-query-complexity."
                    ),
                    cwe_id="CWE-770",
                    cvss_score=7.5 if count >= 100 else 5.3,
                ))
                break   # One finding at the highest accepted count

        return findings

    def _test_circular_reference(
        self, client: GQLClient, endpoint: str
    ) -> list[GraphQLFinding]:
        """Test if circular type references can be exploited for infinite loops."""
        findings = []

        # Common circular patterns in social/content APIs
        circular_queries = [
            ("friends->friends", "{ users { friends { friends { friends { id } } } } }"),
            ("posts->author->posts", "{ posts { author { posts { author { id } } } } }"),
            ("parent->children", "{ categories { children { children { children { id } } } } }"),
        ]

        for label, query in circular_queries:
            resp = client.query(query)
            if not resp.has_errors:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Circular reference accepted: {label}",
                    detail=(
                        f"Query traversing circular type reference ({label}) succeeded. "
                        "Circular references with no depth limit allow infinite recursive "
                        "resolver chains that can exhaust memory and CPU."
                    ),
                    evidence=f"Query: {query} → HTTP {resp.status_code}, {resp.elapsed_ms:.0f}ms",
                    query_used=query,
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=resp.elapsed_ms,
                    remediation=(
                        "Set query depth limits. Detect circular fragments at parse time. "
                        "Use DataLoader to batch+cache resolver calls."
                    ),
                    cwe_id="CWE-400",
                    cvss_score=7.5,
                ))

        return findings

    def _test_field_duplication(
        self, client: GQLClient, endpoint: str, working_field: tuple
    ) -> list[GraphQLFinding]:
        """Duplicate the same fields many times in one selection set."""
        findings = []
        type_name, field = working_field
        count = 200
        fields = " ".join([field] * count)
        query  = f"{{ {type_name} {{ {fields} }} }}"

        resp = client.query(query)
        if not resp.has_errors:
            findings.append(GraphQLFinding(
                probe=self.name,
                category=AttackCategory.DOS,
                severity=Severity.MEDIUM,
                title=f"Field duplication accepted — {count} identical fields in one selection set",
                detail=(
                    f"Requesting the same field {count} times in one selection set was accepted. "
                    "While GraphQL deduplicates field execution in some implementations, "
                    "naive implementations may execute the resolver N times."
                ),
                evidence=f"{count}× '{field}' in selection set → HTTP {resp.status_code}",
                query_used=query[:300],
                endpoint=endpoint,
                status_code=resp.status_code,
                response_ms=resp.elapsed_ms,
                remediation="Reject queries with excessive field duplication using a complexity scorer.",
                cwe_id="CWE-400",
                cvss_score=4.3,
            ))

        return findings
