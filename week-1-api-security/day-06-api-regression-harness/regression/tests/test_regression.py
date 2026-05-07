"""
Regression test target (FastAPI) + pytest integration tests.

The target app is used for local development and CI validation.
Tests verify the harness correctly detects pass/fail conditions.
"""

# ── Target app ────────────────────────────────────────────────────────────────
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
import time

app = FastAPI(title="Regression Test Target", version="1.0.0")

USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com",   "role": "admin"},
}

class CreateUser(BaseModel):
    name:  str = Field(..., min_length=1)
    email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")
    role:  Optional[str] = "user"

class SearchBody(BaseModel):
    query:    str = Field(..., min_length=1)
    page:     int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)

@app.get("/api/users")
def list_users(page: int = Query(1, ge=1), per_page: int = Query(20, ge=1, le=100)):
    all_u = list(USERS.values())
    start = (page - 1) * per_page
    return {"users": all_u[start:start+per_page], "total": len(all_u), "page": page, "per_page": per_page}

@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(404, detail={"error": "User not found", "code": "NOT_FOUND"})
    return user

@app.post("/api/users", status_code=201)
def create_user(body: CreateUser):
    new_id = max(USERS.keys(), default=0) + 1
    user = {"id": new_id, **body.model_dump()}
    USERS[new_id] = user
    return user

@app.post("/search")
def search(body: SearchBody):
    q = body.query.lower()
    results = [u for u in USERS.values() if q in u["name"].lower()]
    return {"results": results, "query": body.query, "count": len(results)}


# ── Pytest test suite ─────────────────────────────────────────────────────────
import threading
import pytest
import httpx
import uvicorn

from regression.fixture_loader import FixtureLoader, TestCase, ExpectedSpec
from regression.asserter import ResponseAsserter
from regression.runner import RegressionRunner, RunSummary
from regression.reporters.html_reporter import HTMLReporter


@pytest.fixture(scope="module")
def live_server():
    config = uvicorn.Config(app, host="0.0.0.0", port=8600, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(30):
        try:
            httpx.get("http://localhost:8600/api/users", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    yield "http://localhost:8600"
    server.should_exit = True


# ── Fixture loader tests ──────────────────────────────────────────────────────

class TestFixtureLoader:
    def test_loads_yaml_fixture(self, tmp_path):
        yaml_content = """
tests:
  - id: test_001
    name: Test one
    method: GET
    path: /api/users
    expected:
      status: 200
      max_ms: 500
"""
        f = tmp_path / "test.yaml"
        f.write_text(yaml_content)
        cases = FixtureLoader.from_yaml(f)
        assert len(cases) == 1
        assert cases[0].id == "test_001"
        assert cases[0].expected.max_ms == 500

    def test_path_param_substitution(self):
        tc = TestCase(
            id="t1", name="n", method="GET",
            path="/api/users/{user_id}",
            path_params={"user_id": 42},
            expected=ExpectedSpec(),
        )
        assert tc.resolved_path == "/api/users/42"

    def test_filter_by_tag(self):
        cases = [
            TestCase(id="1", name="a", method="GET", path="/", tags=["smoke"], expected=ExpectedSpec()),
            TestCase(id="2", name="b", method="GET", path="/", tags=["regression"], expected=ExpectedSpec()),
            TestCase(id="3", name="c", method="GET", path="/", tags=["smoke", "regression"], expected=ExpectedSpec()),
        ]
        smoke = FixtureLoader.filter_by_tag(cases, "smoke")
        assert len(smoke) == 2
        assert all("smoke" in c.tags for c in smoke)

    def test_skip_flag_preserved(self):
        import yaml, io
        raw = yaml.safe_load("""
tests:
  - id: skip_me
    name: Skipped test
    method: GET
    path: /
    skip: true
    skip_reason: "Not ready"
    expected:
      status: 200
""")
        cases = [FixtureLoader._parse_case(c) for c in raw["tests"]]
        assert cases[0].skip is True
        assert cases[0].skip_reason == "Not ready"


# ── Asserter tests ────────────────────────────────────────────────────────────

class TestResponseAsserter:
    def _fake_response(self, status: int, body: dict, ms: float = 50):
        import json as _json
        content = _json.dumps(body).encode()
        resp = httpx.Response(status_code=status, content=content,
                              headers={"content-type": "application/json"})
        return resp, ms

    def test_passes_correct_response(self):
        resp, ms = self._fake_response(200, {"id": 1, "name": "Alice"})
        spec   = ExpectedSpec(status=200)
        result = ResponseAsserter().assert_response(
            resp, ms, spec, "t1", "Test", "http://x/users/1", "GET"
        )
        assert result.passed

    def test_fails_wrong_status(self):
        resp, ms = self._fake_response(404, {"error": "not found"})
        spec   = ExpectedSpec(status=200)
        result = ResponseAsserter().assert_response(
            resp, ms, spec, "t1", "Test", "http://x/users/1", "GET"
        )
        assert not result.passed
        assert any("status_code" in a.assertion_type for a in result.failed_assertions)

    def test_fails_slow_response(self):
        resp, _  = self._fake_response(200, {"ok": True})
        spec     = ExpectedSpec(status=200, max_ms=100)
        result   = ResponseAsserter().assert_response(
            resp, 500.0, spec, "t1", "Test", "http://x/", "GET"
        )
        assert not result.passed
        assert any("response_time" in a.assertion_type for a in result.failed_assertions)

    def test_fails_body_not_contains(self):
        resp, ms = self._fake_response(200, {"password": "secret"})
        spec     = ExpectedSpec(status=200, not_contains=['"password"'])
        result   = ResponseAsserter().assert_response(
            resp, ms, spec, "t1", "Test", "http://x/", "GET"
        )
        assert not result.passed

    def test_field_dot_path(self):
        resp, ms = self._fake_response(200, {"user": {"address": {"city": "NYC"}}})
        spec     = ExpectedSpec(status=200, fields={"user.address.city": "NYC"})
        result   = ResponseAsserter().assert_response(
            resp, ms, spec, "t1", "Test", "http://x/", "GET"
        )
        assert result.passed

    def test_schema_validation_catches_missing_field(self):
        resp, ms = self._fake_response(200, {"id": 1})  # missing 'name'
        spec     = ExpectedSpec(
            status=200,
            schema={"type": "object", "required": ["id", "name"],
                    "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}
        )
        result = ResponseAsserter().assert_response(
            resp, ms, spec, "t1", "Test", "http://x/", "GET"
        )
        assert not result.passed


# ── Runner integration tests ──────────────────────────────────────────────────

class TestRegressionRunner:
    def test_runs_yaml_fixtures_against_live_server(self, live_server):
        cases  = FixtureLoader.from_yaml("regression/fixtures/users_api.yaml")
        runner = RegressionRunner(live_server, workers=3, verbose=False)
        summary = runner.run(cases)
        # At minimum smoke tests should pass
        smoke = FixtureLoader.filter_by_tag(cases, "smoke")
        assert summary.passed >= len([t for t in smoke if not t.skip])

    def test_tag_filter_reduces_test_count(self, live_server):
        cases  = FixtureLoader.from_yaml("regression/fixtures/users_api.yaml")
        runner = RegressionRunner(live_server)
        all_summary   = runner.run(cases)
        smoke_summary = runner.run(cases, tag_filter="smoke")
        assert smoke_summary.total < all_summary.total

    def test_html_report_generates(self, live_server, tmp_path):
        cases   = FixtureLoader.from_yaml("regression/fixtures/users_api.yaml")
        runner  = RegressionRunner(live_server)
        summary = runner.run(cases)
        out     = str(tmp_path / "report.html")
        HTMLReporter().write(summary, out)
        content = open(out).read()
        assert "Regression" in content
        assert "Pass Rate" in content

    def test_summary_all_passed_flag(self, live_server):
        cases   = [TestCase(id="t1", name="health", method="GET",
                            path="/api/users", expected=ExpectedSpec(status=200))]
        runner  = RegressionRunner(live_server)
        summary = runner.run(cases)
        assert summary.all_passed
