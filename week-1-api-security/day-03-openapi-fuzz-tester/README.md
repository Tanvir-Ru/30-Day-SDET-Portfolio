# Day 03 — OpenAPI Schema-Driven Fuzz Tester

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A spec-aware API fuzzer that reads your OpenAPI 3.x definition and automatically
generates attack payloads targeting boundary conditions, type confusion, injection
attacks, and format violations — **without writing a single test case by hand**.

---

## The Problem This Solves

Manual API testing covers the happy path. Fuzzing covers what you never thought to test.

When a developer adds a new endpoint, the fuzz suite automatically picks it up from
the spec and starts attacking it. Zero manual work. Zero missed endpoints.

```
Traditional approach:
  Developer adds POST /payments → QA writes 5 test cases → 4 edge cases missed

Fuzz approach:
  Developer adds POST /payments → Parser detects it → 200+ mutations generated → 0 edge cases missed
```

---

## Architecture

```
openapi.yaml / URL
       │
       ▼
┌──────────────┐     Extracts every endpoint,
│  spec_parser │  →  parameter, schema constraint
└──────────────┘
       │
       ▼
┌─────────────────┐     7 mutator classes generate
│ payload_mutators│  →  type-specific attack payloads
└─────────────────┘     from each schema field
       │
       ▼
┌─────────────────┐     Assembles httpx.Request
│ request_builder │  →  with one fuzz value injected,
└─────────────────┘     all others use valid baseline
       │
       ▼
┌──────────────────┐     Detects: 5xx, stack traces,
│ response_analyzer│  →  injection hits, slow responses,
└──────────────────┘     path disclosure, amplification
       │
       ▼
┌──────────┐
│  engine  │  →  JSON / text report with CWE IDs
└──────────┘
```

### Key design decision: one parameter at a time

Each fuzz request mutates **exactly one parameter** while all others use valid
baseline values. This is the standard approach in structured fuzzing — it isolates
which parameter caused the anomaly. Mutating all parameters simultaneously
generates noise that's impossible to triage.

### Key design decision: baseline check first

Before fuzzing any endpoint, the engine sends a valid baseline request. If the
baseline returns 5xx, the endpoint is skipped — you can't detect anomalies against
a broken baseline. This eliminates false positives from pre-existing server errors.

---

## 7 Mutator Classes

| Mutator | What it generates | Finds |
|---|---|---|
| `BoundaryMutator` | min-1, min, max, max+1, INT_MAX, overflow | Off-by-one errors, truncation |
| `TypeConfusionMutator` | Wrong types: `[]` where `str` expected | Type coercion bugs, auth bypasses |
| `InjectionMutator` | SQL, NoSQL, SSTI, XSS, CRLF seeds | Injection vulnerabilities |
| `NullMutator` | `null`, `""`, `0`, `false`, `"null"` | Null pointer exceptions, logic bypass |
| `OversizeMutator` | 10x maxLength, 64KB strings, huge arrays | Buffer overflows, DoS |
| `UnicodeMutator` | RTL override, null bytes, homoglyphs | Parser confusion, display injection |
| `FormatMutator` | Malformed UUIDs, dates, emails, SSRF seeds | Format validation bypass, SSRF |

---

## Anomaly Detection

The response analyzer checks every response for:

| Finding Type | Severity | Trigger |
|---|---|---|
| `server_error` | HIGH | HTTP 5xx |
| `stack_trace_disclosure` | HIGH | Python/Java/Go/PHP/SQL error patterns in body |
| `injection_success` | CRITICAL | Injection payload returns HTTP 200 |
| `redos_candidate` | HIGH | Response > 10 seconds |
| `slow_response` | MEDIUM | Response > 3 seconds |
| `path_disclosure` | MEDIUM | `/home/`, `C:\Users\`, `/var/www/` in body |
| `version_disclosure` | LOW | Framework version strings in body or headers |
| `response_amplification` | MEDIUM | Response body > 1MB |

---

## File Structure

```
day-03-openapi-fuzz-tester/
├── fuzzer/
│   ├── spec_parser.py          # OpenAPI 3.x parser + $ref resolution
│   ├── request_builder.py      # Baseline + fuzzed request assembly
│   ├── response_analyzer.py    # Anomaly detection + FuzzFinding model
│   ├── engine.py               # Orchestrator + FuzzReport + CLI
│   ├── sample_target.py        # FastAPI test target (intentionally vulnerable)
│   ├── mutators/
│   │   └── payload_mutators.py # 7 mutator classes + dedup registry
│   └── tests/
│       └── test_fuzzer.py      # Unit + integration test suite
├── openapi.yaml                # Sample OpenAPI spec for the test target
├── .github/workflows/
│   └── fuzz-tests.yml          # CI: unit tests + integration fuzz + nightly staging
└── pyproject.toml
```

---

## Running Locally

```bash
# Install dependencies
poetry install

# Start the sample target
poetry run uvicorn fuzzer.sample_target:app --reload --port 8000

# Run fuzz engine (text report)
poetry run python -m fuzzer.engine \
  --spec openapi.yaml \
  --base-url http://localhost:8000 \
  --verbose

# JSON report
poetry run python -m fuzzer.engine \
  --spec openapi.yaml \
  --output json | jq .

# Fuzz a specific endpoint only
poetry run python -m fuzzer.engine \
  --spec openapi.yaml \
  --endpoint "POST /users" \
  --mutators injection,boundary

# Fuzz a remote API with authentication
poetry run python -m fuzzer.engine \
  --spec https://api.example.com/openapi.json \
  --base-url https://api.example.com \
  --token "your-bearer-token"

# Run unit tests
poetry run pytest fuzzer/tests/ -v
```

**Exit codes:**
- `0` — No CRITICAL or HIGH findings
- `1` — One or more CRITICAL/HIGH findings (CI gate)

---

## Sample Report Output

```
======================================================================
OPENAPI FUZZ TEST REPORT
======================================================================
API              : Sample Vulnerable API v1.0.0
Base URL         : http://localhost:8000
Endpoints tested : 4
Total requests   : 847
Duration         : 12.4s
Requests/sec     : 68

Findings         : 3 total (1 CRITICAL, 1 HIGH, 1 MEDIUM)

  [CRITICAL ] POST /users
               param='email' (body)
               Injection payload returned HTTP 200 — possible injection vulnerability
               CWE-89

  [HIGH     ] GET /users/{user_id}
               param='user_id' (path)
               Server error 500 triggered by fuzz input
               CWE-20

  [MEDIUM   ] GET /echo
               param='message' (query)
               Slow response (3847ms) on fuzz input
               CWE-400
======================================================================
```

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `httpx` | Async-capable HTTP client for request sending |
| `pyyaml` | OpenAPI YAML spec parsing |
| `fastapi` | Sample vulnerable target API |
| `pytest` | Test runner |

---

## Extending the Fuzzer

### Add a new mutator

```python
# fuzzer/mutators/payload_mutators.py
class MyMutator(BaseMutator):
    name = "my_mutator"

    def mutate(self, schema: dict, original=None) -> list:
        if schema.get("type") != "string":
            return []
        return ["my_payload_1", "my_payload_2"]

# Register it
ALL_MUTATORS.append(MyMutator())
```

### Add a new anomaly detector

```python
# fuzzer/response_analyzer.py → ResponseAnalyzer.analyze()
if "YOUR_ERROR_PATTERN" in body_text:
    findings.append(FuzzFinding(
        ...,
        finding_type="my_finding_type",
        severity=FindingSeverity.HIGH,
        title="My new anomaly detected",
        cwe_id="CWE-XXX",
    ))
```

---

## Recruiter Talking Points

- **Why spec-driven over Schemathesis alone?** Schemathesis is excellent but generates
  mostly valid-shaped inputs. This fuzzer specifically targets vulnerability classes with
  payloads that would never appear in property-based testing (SQL injection seeds, SSRF
  URLs, RTL unicode overrides).

- **Why mutate one parameter at a time?** Isolates the cause of each anomaly. If you
  mutate all parameters simultaneously, a 500 response could be caused by any of them —
  you can't triage it without re-running tests anyway.

- **What's the baseline check for?** Without it, a server that's already broken returns
  500 for every request. The fuzzer would generate hundreds of "HIGH" findings that are
  all false positives from the same underlying bug.

- **What's the most valuable finding type?** `injection_success` — a CRITICAL finding
  that fires when an injection seed returns HTTP 200 with the same shape as a legitimate
  response. This is the closest automated approximation to detecting actual injection
  vulnerabilities without executing an exploit.
