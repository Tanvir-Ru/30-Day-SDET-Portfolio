"""
Regression test runner.

Executes test cases from fixtures against a live API and collects results.

Features:
  - Parallel execution with configurable worker count
  - Per-test timeout with graceful error handling
  - Tag-based filtering (run only 'smoke' tests in CD pipeline)
  - Environment-aware base URL injection
  - Auth token injection without fixture modification
  - Retry on transient failures (503, timeout) with backoff
  - Progress reporting during long runs

Usage (library):
    runner = RegressionRunner("http://localhost:8000", workers=4)
    results = runner.run(test_cases)

Usage (CLI):
    python -m regression.runner --base-url http://localhost:8000 \
        --fixtures regression/fixtures/ \
        --tags smoke \
        --output html
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from regression.fixture_loader import FixtureLoader, TestCase
from regression.asserter import ResponseAsserter, TestResult
from regression.reporters.html_reporter import HTMLReporter
from regression.reporters.allure_reporter import AllureReporter


@dataclass
class RunSummary:
    base_url:     str
    total:        int
    passed:       int
    failed:       int
    skipped:      int
    errored:      int
    duration_s:   float
    results:      list[TestResult] = field(default_factory=list)
    timestamp:    float = field(default_factory=time.time)

    @property
    def pass_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.passed / self.total) * 100

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.errored == 0

    def summary_line(self) -> str:
        return (
            f"{'✅ PASS' if self.all_passed else '❌ FAIL'}  "
            f"{self.passed}/{self.total} passed  "
            f"({self.failed} failed, {self.skipped} skipped, {self.errored} errored)  "
            f"{self.duration_s:.1f}s  {self.pass_rate:.0f}% pass rate"
        )

    def to_dict(self) -> dict:
        return {
            "base_url":   self.base_url,
            "timestamp":  self.timestamp,
            "duration_s": round(self.duration_s, 2),
            "total":      self.total,
            "passed":     self.passed,
            "failed":     self.failed,
            "skipped":    self.skipped,
            "errored":    self.errored,
            "pass_rate":  round(self.pass_rate, 1),
            "results": [r.to_dict() for r in self.results],
        }


class RegressionRunner:
    """
    Parallel regression test runner.

    Loads test cases, sends HTTP requests, and validates responses using
    the ResponseAsserter. Supports tag filtering, retries, and auth injection.
    """

    def __init__(
        self,
        base_url:    str,
        auth_token:  str = None,
        timeout:     float = 10.0,
        workers:     int = 5,
        retries:     int = 1,
        verbose:     bool = False,
    ):
        self.base_url   = base_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout    = timeout
        self.workers    = workers
        self.retries    = retries
        self.verbose    = verbose
        self._asserter  = ResponseAsserter()

    def run(
        self,
        test_cases: list[TestCase],
        tag_filter: str = None,
    ) -> RunSummary:
        start = time.perf_counter()

        # Apply tag filter
        if tag_filter:
            test_cases = FixtureLoader.filter_by_tag(test_cases, tag_filter)

        # Separate skipped tests
        active  = [t for t in test_cases if not t.skip]
        skipped = [t for t in test_cases if t.skip]

        results: list[TestResult] = []

        if self.verbose:
            print(f"\nRunning {len(active)} tests ({len(skipped)} skipped) with {self.workers} workers\n")

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self._run_single, tc): tc
                for tc in active
            }
            for future in as_completed(futures):
                tc     = futures[future]
                result = future.result()
                results.append(result)
                if self.verbose:
                    icon = "✅" if result.passed else "❌"
                    print(f"  {icon}  {result.test_id:20s}  {result.duration_ms:6.0f}ms  {result.failure_summary}")

        duration = time.perf_counter() - start
        passed   = sum(1 for r in results if r.passed)
        failed   = sum(1 for r in results if not r.passed and not r.error)
        errored  = sum(1 for r in results if r.error)

        return RunSummary(
            base_url=self.base_url,
            total=len(active) + len(skipped),
            passed=passed,
            failed=failed,
            skipped=len(skipped),
            errored=errored,
            duration_s=duration,
            results=results,
        )

    def _run_single(self, tc: TestCase) -> TestResult:
        """Execute one test case with retry logic."""
        url = f"{self.base_url}{tc.resolved_path}"

        for attempt in range(self.retries + 1):
            try:
                result = self._execute(tc, url)
                # Retry on transient server errors
                if result.status_code in (503, 502, 429) and attempt < self.retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return result
            except Exception as e:
                if attempt == self.retries:
                    return TestResult(
                        test_id=tc.id,
                        test_name=tc.name,
                        passed=False,
                        duration_ms=0,
                        status_code=0,
                        url=url,
                        method=tc.method,
                        error=str(e),
                    )
                time.sleep(0.3)

        # Should not reach here
        return TestResult(
            test_id=tc.id, test_name=tc.name, passed=False,
            duration_ms=0, status_code=0, url=url,
            method=tc.method, error="Max retries exceeded",
        )

    def _execute(self, tc: TestCase, url: str) -> TestResult:
        """Execute one HTTP request and assert the response."""
        headers = dict(tc.headers)
        if self.auth_token:
            headers.setdefault("Authorization", f"Bearer {self.auth_token}")

        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            t0   = time.perf_counter()
            resp = client.request(
                method=tc.method,
                url=url,
                params=tc.query or None,
                json=tc.body if tc.body is not None else None,
                headers=headers,
            )
            ms = (time.perf_counter() - t0) * 1000

        return self._asserter.assert_response(
            response=resp,
            duration_ms=ms,
            spec=tc.expected,
            test_id=tc.id,
            test_name=tc.name,
            url=url,
            method=tc.method,
            request_body=tc.body,
        )


def main():
    parser = argparse.ArgumentParser(description="API Regression Harness")
    parser.add_argument("--base-url",  required=True)
    parser.add_argument("--fixtures",  required=True, help="Fixture file or directory")
    parser.add_argument("--tags",      help="Run only tests with this tag")
    parser.add_argument("--token",     help="Bearer token")
    parser.add_argument("--workers",   type=int, default=5)
    parser.add_argument("--output",    choices=["text", "json", "html", "allure"], default="text")
    parser.add_argument("--out-file",  default="regression-report")
    parser.add_argument("--verbose",   action="store_true")
    args = parser.parse_args()

    # Load fixtures
    fixture_path = Path(args.fixtures)
    if fixture_path.is_dir():
        cases = FixtureLoader.from_directory(fixture_path)
    elif fixture_path.suffix in (".yaml", ".yml"):
        cases = FixtureLoader.from_yaml(fixture_path)
    elif fixture_path.suffix == ".json":
        cases = FixtureLoader.from_json(fixture_path)
    elif fixture_path.suffix == ".csv":
        cases = FixtureLoader.from_csv(fixture_path)
    else:
        print(f"Unknown fixture format: {fixture_path.suffix}", file=sys.stderr)
        sys.exit(1)

    runner  = RegressionRunner(args.base_url, auth_token=args.token,
                                workers=args.workers, verbose=args.verbose)
    summary = runner.run(cases, tag_filter=args.tags)
    print(f"\n{summary.summary_line()}\n")

    if args.output == "json":
        out = f"{args.out_file}.json"
        Path(out).write_text(json.dumps(summary.to_dict(), indent=2))
        print(f"JSON report: {out}")
    elif args.output == "html":
        HTMLReporter().write(summary, f"{args.out_file}.html")
    elif args.output == "allure":
        AllureReporter().write(summary, f"{args.out_file}-allure")
    else:
        for r in summary.results:
            if not r.passed:
                print(f"  ❌ {r.test_id}: {r.failure_summary}")

    sys.exit(0 if summary.all_passed else 1)


if __name__ == "__main__":
    main()
