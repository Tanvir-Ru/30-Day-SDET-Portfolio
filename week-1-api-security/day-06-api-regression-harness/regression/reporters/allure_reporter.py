"""
Allure reporter — writes Allure-compatible JSON result files.

Allure is the industry-standard test reporting framework. This reporter
writes the allure-results/ directory format that the Allure CLI can then
render into a full interactive HTML report with history, trends, and categories.

Output format: one JSON file per test case in allure-results/
  - Allure can be installed via: npm install -g allure-commandline
  - Render with: allure generate allure-results -o allure-report
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from regression.asserter import TestResult, RunSummary


class AllureReporter:

    def write(self, summary: RunSummary, output_dir: str) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        for result in summary.results:
            self._write_result(result, out)

        # Write environment.properties for Allure environment tab
        env_file = out / "environment.properties"
        env_file.write_text(
            f"Base.URL={summary.base_url}\n"
            f"Total.Tests={summary.total}\n"
            f"Pass.Rate={summary.pass_rate:.1f}%\n"
        )

        print(f"Allure results written to: {output_dir}/")
        print(f"Render with: allure generate {output_dir} -o allure-report --clean")

    def _write_result(self, result: TestResult, out: Path) -> None:
        allure_result = {
            "uuid": str(uuid.uuid4()),
            "historyId": result.test_id,
            "name": result.test_name,
            "status": "passed" if result.passed else "failed",
            "stage": "finished",
            "start": int((result.duration_ms - result.duration_ms) * 1000 + time.time() * 1000),
            "stop": int(time.time() * 1000),
            "labels": [
                {"name": "suite",    "value": "API Regression"},
                {"name": "testId",   "value": result.test_id},
                {"name": "method",   "value": result.method},
                {"name": "severity", "value": "critical" if not result.passed else "normal"},
            ],
            "links": [
                {"name": "API Endpoint", "url": result.url, "type": "link"}
            ],
            "steps": [
                {
                    "name": f"[{a.assertion_type}] {'✅' if a.passed else '❌'} {a.message or 'passed'}",
                    "status": "passed" if a.passed else "failed",
                    "stage": "finished",
                    "attachments": [],
                    "parameters": [
                        {"name": "expected", "value": str(a.expected)[:200]},
                        {"name": "actual",   "value": str(a.actual)[:200]},
                    ],
                }
                for a in result.assertions
            ],
            "attachments": [],
            "parameters": [
                {"name": "URL",         "value": result.url},
                {"name": "Method",      "value": result.method},
                {"name": "Status Code", "value": str(result.status_code)},
                {"name": "Duration",    "value": f"{result.duration_ms:.0f}ms"},
            ],
        }

        if not result.passed:
            allure_result["statusDetails"] = {
                "message": result.failure_summary,
                "trace": result.error or "",
            }

        file_path = out / f"{result.test_id}-result.json"
        file_path.write_text(json.dumps(allure_result, indent=2))
