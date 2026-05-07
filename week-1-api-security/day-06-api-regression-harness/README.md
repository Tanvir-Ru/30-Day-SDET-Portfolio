# Day 06 — Data-Driven API Regression Harness

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A production-grade API regression framework where test cases live in YAML
fixtures, run in parallel, and report failures with side-by-side HTML diffs.
Zero test code changes needed when adding new test cases — QA and product
teams can contribute test coverage without touching Python.

---

## The Problem This Solves

Traditional regression suites tightly couple test data and test logic:
```python
def test_get_user():
    resp = client.get("/api/users/1")
    assert resp.status_code == 200
    assert resp.json()["name"] == "Alice"
```

When requirements change, you update code. When tests fail, you get `AssertionError`
with no context. This harness separates concerns entirely.

---

## Architecture

```
YAML Fixture File          FixtureLoader          RegressionRunner
────────────────    ──►   ─────────────   ──►    ────────────────
tests:                    [TestCase, ...]         ThreadPoolExecutor
  - id: GET_user_200                              (N workers)
    method: GET                                        │
    path: /api/users/{id}    ResponseAsserter     ◄───┘
    expected:           ──►  ─────────────────
      status: 200             Status ✅
      max_ms: 300             Schema ✅
      fields:                 Fields ✅
        id: 1                 Contains ✅
      not_contains:           max_ms ❌ ── HTML diff
        - '"password"'
                         HTMLReporter / AllureReporter
                         ───────────────────────────
                         Filterable table, side-by-side diffs,
                         expandable request/response bodies
```

### Key design decisions

**YAML fixtures** — test cases are data, not code. Product managers can review them. QA can add
cases without Python knowledge. Different fixture files per domain: `users_api.yaml`, `payments_api.yaml`.

**HTML diff on failure** — instead of `AssertionError: expected 200 got 404`, you get a colour-coded
side-by-side diff showing exactly which fields changed. Cuts debugging time from minutes to seconds.

**dot-path field assertions** — `user.address.city: "NYC"` drills into nested response structures
without writing custom extraction logic.

**`not_contains` security assertions** — `not_contains: ['"password"', '"secret"']` in every user
endpoint test catches accidental field exposure before it reaches production.

---

## Fixture Format

```yaml
tests:
  - id: GET_user_200
    name: Get user by ID returns 200
    method: GET
    path: /api/users/{user_id}
    path_params:
      user_id: 1
    query:
      include_deleted: false
    headers:
      X-Request-ID: "test-001"
    tags: [smoke, regression]
    expected:
      status: 200
      max_ms: 300          # SLA gate
      schema:              # JSON Schema validation
        type: object
        required: [id, name, email]
        properties:
          id:    { type: integer }
          name:  { type: string, minLength: 1 }
          email: { type: string }
      fields:              # dot-path value assertions
        id: 1
        role: "user"
      contains:            # strings that must appear in body
        - "alice@example.com"
      not_contains:        # strings that must NOT appear
        - '"password"'
        - '"secret"'
```

---

## File Structure

```
day-06-api-regression-harness/
├── regression/
│   ├── fixture_loader.py          # YAML/JSON/CSV loader + TestCase model
│   ├── asserter.py                # Response asserter + HTML diff generator
│   ├── runner.py                  # Parallel runner + RunSummary + CLI
│   ├── fixtures/
│   │   └── users_api.yaml         # 13 regression test cases
│   ├── reporters/
│   │   ├── html_reporter.py       # Rich HTML report with diffs
│   │   └── allure_reporter.py     # Allure-compatible JSON output
│   └── tests/
│       └── test_regression.py     # Unit + integration tests
├── .github/workflows/
│   └── regression.yml
└── pyproject.toml
```

---

## Running Locally

```bash
# Install
poetry install

# Start the test target
poetry run uvicorn regression.tests.test_regression:app --port 8000

# Run smoke suite only
poetry run python -m regression.runner \
  --base-url http://localhost:8000 \
  --fixtures regression/fixtures/ \
  --tags smoke \
  --verbose

# Full regression + HTML report
poetry run python -m regression.runner \
  --base-url http://localhost:8000 \
  --fixtures regression/fixtures/ \
  --output html \
  --out-file report
open report.html

# Allure report
poetry run python -m regression.runner \
  --base-url http://localhost:8000 \
  --fixtures regression/fixtures/ \
  --output allure \
  --out-file allure-results
allure generate allure-results -o allure-report --clean
open allure-report/index.html

# Run unit tests
poetry run pytest regression/tests/ -v
```

---

## Recruiter Talking Points

- **Why YAML fixtures?** Separation of test data from test logic is a first-class software
  engineering principle. It enables non-engineers to review test coverage, supports
  fixture generation from OpenAPI specs or Postman collections, and prevents test
  code from becoming a maintenance burden as the API evolves.

- **What's the HTML diff?** On a field assertion failure, instead of `expected 'NYC' got None`,
  the report shows a side-by-side colour-coded diff of the full JSON response vs expected.
  This is what developers actually need to fix the issue.

- **Why `not_contains` security assertions?** Regression suites typically test for presence of
  correct data. Testing for absence of sensitive data (`password`, `secret`, `api_key`) in
  every response is a security quality gate that catches accidental field exposure — one of
  the most common API security mistakes.

- **What's the Allure integration value?** Allure provides historical trend charts, test
  category analysis, and retry statistics over time. Plugging regression results into Allure
  turns a one-shot run into a quality trend dashboard.
