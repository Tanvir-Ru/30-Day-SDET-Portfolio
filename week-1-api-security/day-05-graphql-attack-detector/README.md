# Day 05 — GraphQL Introspection Attack Detector

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A GraphQL-specific security scanner covering the attack surface that REST API
scanners miss entirely. Five probe classes covering introspection exposure,
depth/complexity attacks, batching-based rate-limit bypass, field suggestion
oracle schema enumeration, and argument injection.

---

## Why GraphQL Needs Its Own Scanner

GraphQL breaks every assumption REST security tools are built on:

| REST assumption | GraphQL reality |
|---|---|
| HTTP status reflects success/failure | Always HTTP 200 — errors in `errors[]` field |
| Endpoints are enumerable | Single endpoint, operations are arbitrary strings |
| 401/403 blocks requests | Must check data vs errors in response body |
| Rate limiting on URL+method | Batching sends N operations in 1 HTTP request |
| Schema is documentation | Schema is executable and self-describing |

---

## Attack Categories Covered

### 1. Introspection Exposure
GraphQL's built-in `__schema` query returns the complete API surface:
every type, field, argument, mutation, subscription, and deprecated field.
In production, this is an attacker's complete map of your API.

The probe also tests:
- **Alias bypass** — `{ s: __schema { t: types { n: name } } }` to bypass keyword filters
- **`__type` introspection** — partial schema disclosure
- **GET-based introspection** — CSRF vector (no preflight for GET)
- **`__typename` fingerprinting** — confirms endpoint exists

### 2. Depth & Complexity Attacks
Without limits, clients control query cost. A single query can trigger
exponential resolver execution:

```graphql
{ users { friends { friends { friends { friends { id } } } } } }
```

The probe also tests:
- **Alias overload** — 100 aliases of the same expensive field in one query
- **Circular references** — `User → friends → User → friends → ...`
- **Field duplication** — same field requested 200× in one selection set

### 3. Batching Abuse — Rate Limit Bypass
GraphQL batching sends multiple operations in one HTTP request.
A WAF limiting to 60 req/min sees **1 request**; the server executes **100 operations**.

```json
[
  {"query": "mutation { login(username: \"admin\", password: \"attempt_1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"attempt_2\") { token } }"},
  ...100 more
]
```

This is how OTP brute-forcing works against GraphQL APIs in the wild.

### 4. Field Suggestion Oracle
GraphQL returns `"Did you mean X?"` error messages even when introspection
is disabled. By probing with misspelled field names, attackers reconstruct
the schema field-by-field:

```
Query:    { passwrd { value } }
Response: "Cannot query field 'passwrd'. Did you mean 'password'?"
→ Schema contains field: password ✓
```

### 5. Argument Injection
GraphQL arguments are injection points identical to REST query params:
- SQL injection via `filter`, `where`, `search` arguments
- NoSQL operator injection (`{"$gt": ""}` as argument value)
- Stack trace/path disclosure in GraphQL error responses

---

## Architecture

```
gql_scanner/
├── gql_client.py                  ← GQLClient + GQLResponse (POST, GET, batch)
├── scanner.py                     ← Orchestrator, GraphQLScanReport, CLI
└── probes/
    ├── base.py                    ← GraphQLBaseProbe + GraphQLFinding model
    ├── introspection_probe.py     ← __schema, __type, alias bypass, GET
    ├── depth_probe.py             ← Depth limits, alias overload, circular refs
    ├── batching_probe.py          ← Batch size limits, credential stuffing via batch
    └── field_injection_probe.py   ← Field suggestion oracle, SQL/NoSQL injection
```

### Design decision: GQLResponse wraps HTTP 200 semantics

GraphQL always returns HTTP 200. The `GQLResponse` object exposes:
- `has_data` — response contains a `data` field
- `has_errors` — response contains an `errors` field
- `error_messages` — list of error message strings
- `field_data(*keys)` — dot-path drill into response data

This prevents every probe from having to re-implement GQL response parsing.

### Design decision: probes receive a shared httpx.Client

The scanner creates one shared session and passes it to all probes. This
preserves cookies, connection pooling, and authentication headers across
the full scan without each probe managing its own lifecycle.

---

## File Structure

```
day-05-graphql-attack-detector/
├── gql_scanner/
│   ├── __init__.py
│   ├── gql_client.py              # GQLClient: POST, GET, batch queries
│   ├── scanner.py                 # Orchestrator + report + CLI
│   ├── probes/
│   │   ├── base.py
│   │   ├── introspection_probe.py
│   │   ├── depth_probe.py
│   │   ├── batching_probe.py
│   │   └── field_injection_probe.py
│   ├── tests/
│   │   └── test_gql_scanner.py    # Unit + integration tests
│   └── targets/
│       └── vulnerable_gql.py      # Strawberry-based vulnerable target
├── .github/workflows/
│   └── gql-scan.yml
└── pyproject.toml
```

---

## Running Locally

```bash
# Install dependencies
poetry install

# Start the vulnerable GraphQL target
poetry run uvicorn gql_scanner.targets.vulnerable_gql:app --port 4000

# GraphiQL UI (explore manually)
open http://localhost:4000/graphql

# Run full scan (text report)
poetry run python -m gql_scanner.scanner \
  --endpoint http://localhost:4000/graphql

# JSON report
poetry run python -m gql_scanner.scanner \
  --endpoint http://localhost:4000/graphql \
  --output json | jq '.summary'

# Authenticated scan
poetry run python -m gql_scanner.scanner \
  --endpoint https://api.example.com/graphql \
  --token "your-bearer-token"

# Run tests
poetry run pytest gql_scanner/tests/ -v
```

**Exit codes:** `0` = no CRITICAL/HIGH · `1` = CRITICAL/HIGH found

---

## Sample Report

```
======================================================================
GRAPHQL ATTACK SURFACE SCAN REPORT
======================================================================
Endpoint     : http://localhost:4000/graphql
Probes run   : introspection, depth_complexity, batching_abuse, field_suggestion, injection
Duration     : 8.3s
Risk Score   : 72/100
Findings     : 7 total (1 CRITICAL, 3 HIGH, 2 MEDIUM, 1 LOW)

  [CRITICAL ] [batching_abuse]
               Credential stuffing via batch — 20 login attempts in 1 HTTP request
               CWE-307  CVSS 9.1
               Fix: Apply rate limiting per operation name, not per HTTP request

  [HIGH     ] [introspection]
               GraphQL introspection enabled — full schema exposed (42 types)
               CWE-200  CVSS 7.5
               Fix: Disable introspection in production. Apollo: introspection: false

  [HIGH     ] [depth_attack]
               No query depth limit — depth 25 query accepted
               CWE-400  CVSS 7.5
               Fix: Set maximum query depth 10–15. Use graphql-depth-limit

  [HIGH     ] [alias_overload]
               Alias overload accepted — 100 aliases resolved in one request
               CWE-770  CVSS 7.5
               Fix: Implement query complexity scoring
======================================================================
```

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `httpx` | HTTP client (sync, timeout handling) |
| `strawberry-graphql` | Vulnerable test target |
| `fastapi` | ASGI framework for test target |
| `pytest` | Test runner |

---

## Recruiter Talking Points

- **What is the field suggestion oracle?** Even with introspection disabled, GraphQL
  returns `"Did you mean X?"` error messages that leak field names. This probe
  reconstructs the schema by probing with misspelled names. Disabling introspection
  without also disabling suggestions gives attackers a slower but complete path to
  the same information.

- **Why is batching a security issue?** Rate limiting is almost always applied at the
  HTTP request level (60 req/min). GraphQL batching sends 100 operations in 1 request —
  so 60 req/min × 100 operations = 6000 operations/min. This is how OTP codes (10000
  combinations) can be brute-forced against a production GraphQL API in under 2 minutes.

- **What's the alias overload attack?** Sending `{ f1: expensiveQuery, f2: expensiveQuery, ..., f100: expensiveQuery }`
  makes the server execute the same resolver 100 times in response to a single field
  request. Naive per-field rate limits see "one field" but the server does 100× the work.

- **Why a custom GQL client instead of a library?** Most GQL client libraries abstract
  away the HTTP layer. For security testing, we need direct control over raw request
  construction (GET vs POST, batch arrays vs single operations, malformed JSON bodies).
