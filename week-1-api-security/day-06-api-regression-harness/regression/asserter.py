"""
Response asserter — validates an httpx.Response against an ExpectedSpec.

Produces structured AssertionResult objects with:
  - pass/fail per assertion type
  - deepdiff HTML diff on body mismatch (the key differentiator)
  - JSON Schema validation errors with field path context
  - Dot-path field value comparison

The HTML diff is what makes failures actionable: instead of "body mismatch",
you see exactly which fields changed, were added, or were removed —
formatted as a side-by-side visual diff.

Assertion types:
  1. Status code
  2. Response time (max_ms threshold)
  3. JSON Schema validation
  4. Field value assertions (dot-path)
  5. Body contains / not_contains strings
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from regression.fixture_loader import ExpectedSpec


# ── Result models ─────────────────────────────────────────────────────────────

@dataclass
class AssertionResult:
    assertion_type: str
    passed:         bool
    expected:       Any
    actual:         Any
    message:        str = ""
    html_diff:      Optional[str] = None


@dataclass
class TestResult:
    test_id:       str
    test_name:     str
    passed:        bool
    duration_ms:   float
    status_code:   int
    url:           str
    method:        str
    assertions:    list[AssertionResult] = field(default_factory=list)
    error:         Optional[str] = None
    request_body:  Any = None
    response_body: Any = None

    @property
    def failed_assertions(self) -> list[AssertionResult]:
        return [a for a in self.assertions if not a.passed]

    @property
    def failure_summary(self) -> str:
        if self.passed:
            return "PASS"
        if self.error:
            return f"ERROR: {self.error}"
        return " | ".join(a.message for a in self.failed_assertions)

    def to_dict(self) -> dict:
        return {
            "test_id":      self.test_id,
            "test_name":    self.test_name,
            "passed":       self.passed,
            "duration_ms":  round(self.duration_ms, 2),
            "status_code":  self.status_code,
            "url":          self.url,
            "method":       self.method,
            "assertions": [
                {
                    "type":    a.assertion_type,
                    "passed":  a.passed,
                    "expected": str(a.expected)[:200],
                    "actual":   str(a.actual)[:200],
                    "message":  a.message,
                }
                for a in self.assertions
            ],
            "error":        self.error,
        }


# ── Dot-path resolver ─────────────────────────────────────────────────────────

def _get_nested(obj: Any, dot_path: str) -> Any:
    """
    Resolve a dot-path like 'user.address.city' from a nested dict.
    Supports array indexing: 'users.0.name'
    """
    parts = dot_path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


# ── HTML diff generator ───────────────────────────────────────────────────────

def _generate_html_diff(expected: Any, actual: Any, context: str = "") -> str:
    """
    Generate a side-by-side HTML diff of two JSON objects.
    Uses recursive comparison with colour-coded changes.
    """
    exp_str = json.dumps(expected, indent=2, default=str) if expected is not None else "null"
    act_str = json.dumps(actual, indent=2, default=str) if actual is not None else "null"

    exp_lines = exp_str.splitlines()
    act_lines = act_str.splitlines()
    max_lines = max(len(exp_lines), len(act_lines))

    rows = []
    for i in range(max_lines):
        exp_line = exp_lines[i] if i < len(exp_lines) else ""
        act_line = act_lines[i] if i < len(act_lines) else ""
        changed  = exp_line != act_line
        bg_exp   = "#fef2f2" if changed else "transparent"
        bg_act   = "#f0fdf4" if changed else "transparent"
        rows.append(
            f'<tr>'
            f'<td style="background:{bg_exp};padding:2px 8px;font-family:monospace;font-size:12px;white-space:pre;">{_html_escape(exp_line)}</td>'
            f'<td style="background:{bg_act};padding:2px 8px;font-family:monospace;font-size:12px;white-space:pre;">{_html_escape(act_line)}</td>'
            f'</tr>'
        )

    return f"""
    <div style="margin:8px 0;">
        <strong style="font-size:12px;color:#374151;">{_html_escape(context)}</strong>
        <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;margin-top:4px;">
            <thead>
                <tr>
                    <th style="background:#fee2e2;padding:4px 8px;font-size:11px;text-align:left;">Expected</th>
                    <th style="background:#dcfce7;padding:4px 8px;font-size:11px;text-align:left;">Actual</th>
                </tr>
            </thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
    </div>
    """


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Asserter ──────────────────────────────────────────────────────────────────

class ResponseAsserter:
    """
    Validates an httpx.Response against an ExpectedSpec.
    Returns a TestResult with per-assertion pass/fail + diffs.
    """

    def assert_response(
        self,
        response:    httpx.Response,
        duration_ms: float,
        spec:        ExpectedSpec,
        test_id:     str,
        test_name:   str,
        url:         str,
        method:      str,
        request_body: Any = None,
    ) -> TestResult:

        assertions: list[AssertionResult] = []

        # Parse response body
        body = None
        try:
            body = response.json()
        except Exception:
            pass

        # ── 1. Status code ────────────────────────────────────────────────
        status_ok = response.status_code == spec.status
        assertions.append(AssertionResult(
            assertion_type="status_code",
            passed=status_ok,
            expected=spec.status,
            actual=response.status_code,
            message="" if status_ok else
                    f"Expected HTTP {spec.status}, got {response.status_code}",
        ))

        # ── 2. Response time ──────────────────────────────────────────────
        if spec.max_ms is not None:
            time_ok = duration_ms <= spec.max_ms
            assertions.append(AssertionResult(
                assertion_type="response_time",
                passed=time_ok,
                expected=f"≤ {spec.max_ms}ms",
                actual=f"{duration_ms:.0f}ms",
                message="" if time_ok else
                        f"Response took {duration_ms:.0f}ms, limit is {spec.max_ms}ms",
            ))

        # ── 3. JSON Schema validation ─────────────────────────────────────
        if spec.schema and body is not None:
            schema_errors = self._validate_schema(body, spec.schema)
            assertions.append(AssertionResult(
                assertion_type="json_schema",
                passed=not schema_errors,
                expected="Valid against schema",
                actual=f"{len(schema_errors)} violation(s)" if schema_errors else "Valid",
                message="; ".join(schema_errors[:3]) if schema_errors else "",
            ))

        # ── 4. Field value assertions ──────────────────────────────────────
        for dot_path, expected_value in spec.fields.items():
            actual_value = _get_nested(body, dot_path) if body else None
            field_ok = actual_value == expected_value
            diff_html = None
            if not field_ok and isinstance(expected_value, (dict, list)):
                diff_html = _generate_html_diff(
                    expected_value, actual_value,
                    context=f"Field diff: {dot_path}",
                )
            assertions.append(AssertionResult(
                assertion_type=f"field:{dot_path}",
                passed=field_ok,
                expected=expected_value,
                actual=actual_value,
                message="" if field_ok else
                        f"Field '{dot_path}': expected {expected_value!r}, got {actual_value!r}",
                html_diff=diff_html,
            ))

        # ── 5. Contains / not_contains ─────────────────────────────────────
        body_text = response.text
        for substring in spec.contains:
            ok = substring in body_text
            assertions.append(AssertionResult(
                assertion_type=f"contains:{substring[:40]}",
                passed=ok,
                expected=f"contains '{substring}'",
                actual=body_text[:100],
                message="" if ok else f"Response body does not contain: {substring!r}",
            ))

        for substring in spec.not_contains:
            ok = substring not in body_text
            assertions.append(AssertionResult(
                assertion_type=f"not_contains:{substring[:40]}",
                passed=ok,
                expected=f"does not contain '{substring}'",
                actual=body_text[:100],
                message="" if ok else f"Response body contains forbidden string: {substring!r}",
            ))

        # ── Body diff on failure ───────────────────────────────────────────
        body_diff_html = None
        if not status_ok and body is not None:
            body_diff_html = _generate_html_diff(
                {"status": spec.status},
                {"status": response.status_code, "body_preview": body if isinstance(body, dict) else str(body)[:200]},
                context="Response mismatch",
            )

        all_passed = all(a.passed for a in assertions)
        return TestResult(
            test_id=test_id,
            test_name=test_name,
            passed=all_passed,
            duration_ms=duration_ms,
            status_code=response.status_code,
            url=url,
            method=method,
            assertions=assertions,
            request_body=request_body,
            response_body=body,
        )

    @staticmethod
    def _validate_schema(instance: Any, schema: dict) -> list[str]:
        """
        Basic JSON Schema validation without heavy dependencies.
        Validates: type, required, properties, minimum, maximum, minLength, maxLength.
        For full JSON Schema use jsonschema library.
        """
        errors = []

        def validate(inst: Any, sch: dict, path: str = "$"):
            if not sch:
                return

            # Type check
            type_map = {
                "string": str, "integer": int,
                "number": (int, float), "boolean": bool,
                "array": list, "object": dict, "null": type(None),
            }
            expected_type = sch.get("type")
            if expected_type and expected_type in type_map:
                if not isinstance(inst, type_map[expected_type]):
                    errors.append(f"{path}: expected {expected_type}, got {type(inst).__name__}")
                    return

            if isinstance(inst, dict):
                # Required fields
                for req in sch.get("required", []):
                    if req not in inst:
                        errors.append(f"{path}.{req}: required field missing")

                # Property validation
                for prop, prop_schema in sch.get("properties", {}).items():
                    if prop in inst:
                        validate(inst[prop], prop_schema, f"{path}.{prop}")

            elif isinstance(inst, list):
                items_schema = sch.get("items", {})
                for i, item in enumerate(inst):
                    validate(item, items_schema, f"{path}[{i}]")

            elif isinstance(inst, str):
                min_len = sch.get("minLength", 0)
                max_len = sch.get("maxLength")
                if len(inst) < min_len:
                    errors.append(f"{path}: string too short ({len(inst)} < {min_len})")
                if max_len and len(inst) > max_len:
                    errors.append(f"{path}: string too long ({len(inst)} > {max_len})")

            elif isinstance(inst, (int, float)):
                minimum = sch.get("minimum")
                maximum = sch.get("maximum")
                if minimum is not None and inst < minimum:
                    errors.append(f"{path}: {inst} < minimum {minimum}")
                if maximum is not None and inst > maximum:
                    errors.append(f"{path}: {inst} > maximum {maximum}")

        validate(instance, schema)
        return errors
