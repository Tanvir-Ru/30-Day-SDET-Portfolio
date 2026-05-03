"""
Probe: GraphQL Introspection Exposure

Introspection is GraphQL's built-in schema discovery mechanism.
In development it's invaluable. In production it's an attacker's
roadmap — revealing every type, field, argument, mutation, and
subscription available.

Tests:
  1. Standard introspection query (__schema)
  2. Type introspection (__type on known types)
  3. Introspection via aliases (bypass naive keyword blocking)
  4. Introspection via field suggestions as fallback oracle
  5. __typename probe (sometimes enabled even when introspection is disabled)
  6. Directive introspection
  7. Introspection via GET method

References:
  - https://graphql.org/learn/introspection/
  - https://owasp.org/www-project-web-security-testing-guide/
  - CWE-200: Exposure of Sensitive Information
"""

from __future__ import annotations

import json
import httpx

from gql_scanner.probes.base import GraphQLBaseProbe, GraphQLFinding, AttackCategory, Severity
from gql_scanner.gql_client import GQLClient


# Full introspection query (what GraphiQL uses)
FULL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name type { name kind } }
        type { name kind }
        isDeprecated
        deprecationReason
      }
    }
    directives {
      name
      description
      locations
      args { name type { name kind } }
    }
  }
}
"""

# Minimal introspection — less likely to be blocked
MINIMAL_INTROSPECTION = "{ __schema { types { name } } }"

# Aliased introspection — bypasses keyword-based WAF rules
ALIASED_INTROSPECTION = "{ s: __schema { t: types { n: name } } }"

# Type introspection
TYPE_INTROSPECTION = "{ __type(name: \"Query\") { name fields { name } } }"

# __typename is almost always enabled
TYPENAME_PROBE = "{ __typename }"

# Directive introspection
DIRECTIVE_INTROSPECTION = "{ __schema { directives { name locations args { name } } } }"


class IntrospectionProbe(GraphQLBaseProbe):
    name        = "introspection"
    category    = AttackCategory.INTROSPECTION
    description = "Checks if GraphQL introspection is enabled and schema is publicly accessible"

    def run(self, endpoint: str, session: httpx.Client, **kwargs) -> list[GraphQLFinding]:
        findings = []
        auth_token = kwargs.get("auth_token")
        client     = GQLClient(endpoint, session, auth_token=auth_token)

        # ── 1. Full introspection ──────────────────────────────────────────
        resp = client.query(FULL_INTROSPECTION_QUERY)
        if resp.has_data and resp.field_data("__schema"):
            schema_data = resp.field_data("__schema")
            type_count  = len(schema_data.get("types", []))

            findings.append(GraphQLFinding(
                probe=self.name,
                category=self.category,
                severity=Severity.HIGH,
                title="GraphQL introspection enabled — full schema exposed",
                detail=(
                    f"Introspection query returned the complete schema with {type_count} types. "
                    "An attacker can enumerate all queries, mutations, subscriptions, field names, "
                    "argument types, and deprecated fields without any authentication. "
                    "This is the attacker's complete map of your API."
                ),
                evidence=f"__schema returned {type_count} types including: "
                         + ", ".join(t["name"] for t in schema_data.get("types", [])[:10] if not t["name"].startswith("__")),
                query_used=MINIMAL_INTROSPECTION,
                endpoint=endpoint,
                status_code=resp.status_code,
                response_ms=resp.elapsed_ms,
                remediation=(
                    "Disable introspection in production. In Apollo Server: "
                    "introspection: false in production config. "
                    "Consider field-level introspection blocking with depth limits. "
                    "Use schema allowlists (persisted queries) for public APIs."
                ),
                cwe_id="CWE-200",
                cvss_score=7.5,
            ))

        # ── 2. Aliased introspection bypass ────────────────────────────────
        elif not resp.has_data:
            alias_resp = client.query(ALIASED_INTROSPECTION)
            if alias_resp.has_data:
                findings.append(GraphQLFinding(
                    probe=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    title="Introspection blocking bypassed via field aliasing",
                    detail=(
                        "Standard introspection was blocked, but aliased introspection "
                        "(__schema aliased as 's') returned schema data. "
                        "The introspection block is based on keyword matching, not semantic analysis."
                    ),
                    evidence="Aliased query { s: __schema { t: types { n: name } } } returned data",
                    query_used=ALIASED_INTROSPECTION,
                    endpoint=endpoint,
                    status_code=alias_resp.status_code,
                    response_ms=alias_resp.elapsed_ms,
                    remediation=(
                        "Block introspection at the GraphQL engine level, not via string matching. "
                        "Most GraphQL servers have a native introspection: false config option."
                    ),
                    cwe_id="CWE-200",
                    cvss_score=7.5,
                ))

        # ── 3. __typename probe (nearly always works) ──────────────────────
        tn_resp = client.query(TYPENAME_PROBE)
        if tn_resp.has_data:
            typename_val = tn_resp.field_data("__typename")
            # __typename alone is acceptable — log as INFO only
            findings.append(GraphQLFinding(
                probe=self.name,
                category=self.category,
                severity=Severity.INFO,
                title="GraphQL endpoint confirmed active via __typename",
                detail=(
                    f"__typename returned '{typename_val}'. "
                    "The GraphQL endpoint is reachable and responding to queries. "
                    "__typename is generally safe to expose but confirms the endpoint exists."
                ),
                evidence=f"__typename = {typename_val!r}",
                query_used=TYPENAME_PROBE,
                endpoint=endpoint,
                status_code=tn_resp.status_code,
                response_ms=tn_resp.elapsed_ms,
                remediation="No action required for __typename alone.",
                cwe_id=None,
                cvss_score=0.0,
            ))

        # ── 4. Type introspection ──────────────────────────────────────────
        type_resp = client.query(TYPE_INTROSPECTION)
        if type_resp.has_data and type_resp.field_data("__type"):
            type_data  = type_resp.field_data("__type")
            field_names = [f["name"] for f in (type_data.get("fields") or [])]
            findings.append(GraphQLFinding(
                probe=self.name,
                category=self.category,
                severity=Severity.MEDIUM,
                title="__type introspection reveals Query field names",
                detail=(
                    f"__type(name: 'Query') exposed {len(field_names)} root query fields: "
                    + ", ".join(field_names[:15])
                    + (f"... and {len(field_names)-15} more" if len(field_names) > 15 else "")
                ),
                evidence=f"Query fields: {field_names[:10]}",
                query_used=TYPE_INTROSPECTION,
                endpoint=endpoint,
                status_code=type_resp.status_code,
                response_ms=type_resp.elapsed_ms,
                remediation="Disable __type introspection alongside __schema introspection.",
                cwe_id="CWE-200",
                cvss_score=5.3,
            ))

        # ── 5. Introspection via GET ───────────────────────────────────────
        get_resp = client.query_via_get(MINIMAL_INTROSPECTION)
        if get_resp.has_data and get_resp.field_data("__schema"):
            findings.append(GraphQLFinding(
                probe=self.name,
                category=AttackCategory.CSRF,
                severity=Severity.MEDIUM,
                title="GraphQL introspection works via HTTP GET",
                detail=(
                    "Introspection via GET request succeeded. "
                    "GET-based GraphQL queries are a CSRF vector — "
                    "no CORS preflight is triggered for same-origin GET requests."
                ),
                evidence="GET ?query={__schema{types{name}}} returned schema data",
                query_used=MINIMAL_INTROSPECTION,
                endpoint=endpoint,
                status_code=get_resp.status_code,
                response_ms=get_resp.elapsed_ms,
                remediation=(
                    "Disable GET-based GraphQL queries in production. "
                    "Only accept POST with Content-Type: application/json."
                ),
                cwe_id="CWE-352",
                cvss_score=5.4,
            ))

        return findings
