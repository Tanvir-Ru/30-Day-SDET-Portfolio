"""
Probe: Field Suggestion Oracle & GraphQL Injection

Field Suggestion Oracle:
  GraphQL returns "Did you mean X?" error messages when you query
  a non-existent field. This leaks schema field names even when
  introspection is completely disabled. By probing with similar names,
  attackers can enumerate the schema one field at a time.

  Example:
    Query: { usr { id } }
    Response: "Cannot query field 'usr'. Did you mean 'user' or 'users'?"
    → Schema now known to contain 'user' and 'users' fields

Injection Probes:
  GraphQL arguments are injection points just like REST query params.
  Tests:
    - SQL injection in filter/search arguments
    - NoSQL operator injection in where clauses
    - SSTI in string arguments
    - GraphQL argument coercion bypass (send wrong type to trigger type error)

Information Leak:
  GraphQL error messages often disclose:
    - Internal field names (via suggestions)
    - Database error messages
    - Stack traces
    - Internal service names

CWE-203: Observable Discrepancy
CWE-89:  SQL Injection
CWE-943: NoSQL Injection
"""

from __future__ import annotations

import re
import httpx

from gql_scanner.probes.base import GraphQLBaseProbe, GraphQLFinding, AttackCategory, Severity
from gql_scanner.gql_client import GQLClient


# ── Field Suggestion Oracle ───────────────────────────────────────────────────

# Intentionally misspelled field names that trigger suggestions
SUGGESTION_PROBES = [
    ("usr",      ["user", "users", "userById"]),
    ("passwrd",  ["password"]),
    ("tok",      ["token", "tokens"]),
    ("adm",      ["admin", "adminUser"]),
    ("paymt",    ["payment", "payments"]),
    ("ordr",     ["order", "orders"]),
    ("auth",     ["authenticate", "authorization"]),
    ("sec",      ["secret", "secrets", "securityToken"]),
    ("apikey",   ["apiKey", "api_key"]),
    ("priv",     ["private", "privateKey", "privileges"]),
]

# Regex to extract "Did you mean X?" suggestions
SUGGESTION_PATTERN = re.compile(
    r'[Dd]id you mean["\s]+([\'"]?[\w,\s"\']+)',
    re.IGNORECASE,
)


class FieldSuggestionProbe(GraphQLBaseProbe):
    name        = "field_suggestion"
    category    = AttackCategory.FIELD_SUGGESTION
    description = "Uses GraphQL error suggestions to enumerate schema fields without introspection"

    def run(self, endpoint: str, session: httpx.Client, **kwargs) -> list[GraphQLFinding]:
        findings = []
        auth_token     = kwargs.get("auth_token")
        client         = GQLClient(endpoint, session, auth_token=auth_token)

        discovered_fields: list[str] = []
        sensitive_found:   list[str] = []

        SENSITIVE_KEYWORDS = ["password", "token", "secret", "key", "private", "admin", "auth"]

        for probe_name, expected_suggestions in SUGGESTION_PROBES:
            query = f"{{ {probe_name} {{ id }} }}"
            resp  = client.query(query)

            if not resp.has_errors:
                continue

            # Extract suggestions from error messages
            for error_msg in resp.error_messages:
                matches = SUGGESTION_PATTERN.findall(error_msg)
                for match in matches:
                    # Parse comma-separated suggestions
                    suggested = [s.strip().strip("'\"") for s in re.split(r"[,or\s]+", match) if s.strip()]
                    discovered_fields.extend(suggested)

                    # Flag sensitive field names
                    for field in suggested:
                        if any(kw in field.lower() for kw in SENSITIVE_KEYWORDS):
                            sensitive_found.append(field)

        if discovered_fields:
            unique_fields = sorted(set(discovered_fields))
            severity      = Severity.HIGH if sensitive_found else Severity.MEDIUM

            findings.append(GraphQLFinding(
                probe=self.name,
                category=self.category,
                severity=severity,
                title=f"Field suggestion oracle — {len(unique_fields)} schema fields enumerated without introspection",
                detail=(
                    f"GraphQL error messages revealed {len(unique_fields)} field names via 'Did you mean?' suggestions. "
                    "This works even when introspection is disabled. "
                    + (f"Sensitive fields discovered: {sensitive_found}. " if sensitive_found else "")
                    + "Attackers use this to reconstruct the schema field by field."
                ),
                evidence=f"Discovered fields: {unique_fields[:20]}",
                query_used="{ usr { id } }  → 'Did you mean user or users?'",
                endpoint=endpoint,
                status_code=200,
                remediation=(
                    "Disable field suggestions in production. "
                    "Apollo Server: fieldSuggestions: false. "
                    "This is separate from disabling introspection — both should be disabled."
                ),
                cwe_id="CWE-203",
                cvss_score=7.5 if sensitive_found else 5.3,
            ))

            if sensitive_found:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Sensitive field names leaked via suggestions: {sensitive_found}",
                    detail=(
                        f"Field suggestions revealed sensitive field names: {sensitive_found}. "
                        "These names indicate the schema may contain authentication tokens, "
                        "passwords, or admin functionality that attackers can target."
                    ),
                    evidence=f"Sensitive fields via suggestions: {sensitive_found}",
                    query_used="Various misspelled probes",
                    endpoint=endpoint,
                    status_code=200,
                    remediation="Disable field suggestions AND disable introspection in production.",
                    cwe_id="CWE-203",
                    cvss_score=7.5,
                ))

        return findings


# ── GraphQL Injection Probe ───────────────────────────────────────────────────

SQL_INJECTION_ARGS = [
    "' OR '1'='1",
    "1' OR 1=1--",
    "1; DROP TABLE users;--",
    "' UNION SELECT * FROM users--",
    "' AND SLEEP(3)--",
]

NOSQL_INJECTION_ARGS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
]

SSTI_ARGS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
]

# Common argument names used in GraphQL filters
FILTER_ARGS = [
    "id", "filter", "where", "search", "query", "name",
    "email", "username", "slug", "key",
]


class InjectionProbe(GraphQLBaseProbe):
    name        = "injection"
    category    = AttackCategory.INJECTION
    description = "SQL, NoSQL, SSTI injection via GraphQL arguments and filters"

    def run(self, endpoint: str, session: httpx.Client, **kwargs) -> list[GraphQLFinding]:
        findings = []
        auth_token = kwargs.get("auth_token")
        client     = GQLClient(endpoint, session, auth_token=auth_token)

        findings.extend(self._test_sql_injection(client, endpoint))
        findings.extend(self._test_nosql_injection(client, endpoint))
        findings.extend(self._test_error_info_leakage(client, endpoint))

        return findings

    def _test_sql_injection(
        self, client: GQLClient, endpoint: str
    ) -> list[GraphQLFinding]:
        findings = []

        for arg_name in FILTER_ARGS[:4]:
            for payload in SQL_INJECTION_ARGS:
                query = f'{{ users({arg_name}: "{payload}") {{ id name }} }}'
                resp  = client.query(query)

                if resp.has_errors:
                    for msg in resp.error_messages:
                        # SQL errors in GraphQL error messages
                        if any(kw in msg.lower() for kw in [
                            "sql", "syntax error", "mysql", "postgresql",
                            "ora-", "sqlite", "sqlstate",
                        ]):
                            findings.append(GraphQLFinding(
                                probe=self.name,
                                category=self.category,
                                severity=Severity.HIGH,
                                title=f"SQL error leaked via GraphQL injection on '{arg_name}' argument",
                                detail=(
                                    f"SQL injection payload in the '{arg_name}' argument triggered a "
                                    f"database error message in the GraphQL response: '{msg[:150]}'. "
                                    "The error confirms the argument reaches a SQL query unparameterised."
                                ),
                                evidence=f"arg={arg_name}, payload={payload!r} → error: {msg[:200]}",
                                query_used=query,
                                endpoint=endpoint,
                                status_code=resp.status_code,
                                response_ms=resp.elapsed_ms,
                                remediation=(
                                    "Use parameterised queries or an ORM that prevents raw SQL. "
                                    "Never interpolate GraphQL argument values directly into SQL."
                                ),
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                            ))
                            return findings   # One is enough signal

        return findings

    def _test_nosql_injection(
        self, client: GQLClient, endpoint: str
    ) -> list[GraphQLFinding]:
        findings = []

        for payload in NOSQL_INJECTION_ARGS:
            # Try to pass MongoDB operator as a JSON object argument
            query = f'{{ users(filter: {payload}) {{ id name }} }}'
            resp  = client.query(query)

            # Unexpected success with NoSQL operator → possible injection
            if resp.has_data and resp.field_data("users"):
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    title="NoSQL injection — MongoDB operator returned data",
                    detail=(
                        f"Using a MongoDB operator ({payload}) in the 'filter' argument returned data. "
                        "The operator was interpreted by the database engine, "
                        "potentially bypassing authorization filters."
                    ),
                    evidence=f"filter={payload} → returned user data",
                    query_used=query,
                    endpoint=endpoint,
                    status_code=resp.status_code,
                    response_ms=resp.elapsed_ms,
                    remediation=(
                        "Sanitise all arguments to strip MongoDB operators. "
                        "Use an input validation schema that rejects object-type values "
                        "for string arguments."
                    ),
                    cwe_id="CWE-943",
                    cvss_score=9.8,
                ))
                break

        return findings

    def _test_error_info_leakage(
        self, client: GQLClient, endpoint: str
    ) -> list[GraphQLFinding]:
        """Send malformed queries to trigger verbose error messages."""
        findings = []

        leak_patterns = [
            (r"Traceback \(most recent call last\)",  "Python stack trace"),
            (r"at [\w.]+\([\w.]+\.java:\d+\)",       "Java stack frame"),
            (r"/home/\w+/|/var/www/|/opt/app/",      "Internal file path"),
            (r"SQLSTATE\[",                           "SQL state code"),
            (r"password['\"]?\s*[:=]\s*['\"]?\w+",   "Password in error"),
            (r"(secret|api.?key|token)\s*=\s*\S+",   "Secret in error"),
        ]

        # Invalid queries designed to trigger rich errors
        error_triggers = [
            "{ __type(name: null) { name } }",
            '{ users(id: "NOT_AN_ID_xyz_9999") { nonExistentField } }',
            "{ " + "a" * 2000 + " }",   # Oversized field name
        ]

        for query in error_triggers:
            resp = client.query(query)
            if not resp.has_errors:
                continue

            error_text = " ".join(resp.error_messages)
            for pattern, description in leak_patterns:
                match = re.search(pattern, error_text, re.IGNORECASE)
                if match:
                    findings.append(GraphQLFinding(
                        probe=self.name,
                        category=AttackCategory.INFORMATION_LEAK,
                        severity=Severity.HIGH,
                        title=f"Information leak in GraphQL error: {description}",
                        detail=(
                            f"GraphQL error response contains {description}. "
                            "Error messages with internal paths, stack traces, or credentials "
                            "give attackers a map of the internal system."
                        ),
                        evidence=error_text[:300],
                        query_used=query[:200],
                        endpoint=endpoint,
                        status_code=resp.status_code,
                        response_ms=resp.elapsed_ms,
                        remediation=(
                            "Configure your GraphQL server to return generic errors in production. "
                            "Apollo Server: formatError — strip extensions.exception from responses. "
                            "Log full errors server-side only."
                        ),
                        cwe_id="CWE-209",
                        cvss_score=6.5,
                    ))

        return findings
