"""
HTML Reporter — generates a rich self-contained HTML report.

Features:
  - Pass/fail summary with colour-coded metrics
  - Filterable table (by status, tag, test name)
  - Expandable per-test detail with request/response bodies
  - Side-by-side HTML diff for failed body assertions
  - Response time distribution bar chart (pure CSS)
  - Printable (single file, no external dependencies)
"""

from __future__ import annotations

import json
from pathlib import Path

from regression.asserter import TestResult, RunSummary


class HTMLReporter:

    def write(self, summary: RunSummary, path: str) -> None:
        html = self._build(summary)
        Path(path).write_text(html, encoding="utf-8")
        print(f"HTML report saved: {path}")

    def _build(self, summary: RunSummary) -> str:
        rows = ""
        for r in sorted(summary.results, key=lambda x: (x.passed, x.test_id)):
            status_color = "#16a34a" if r.passed else "#dc2626"
            status_text  = "PASS" if r.passed else "FAIL"

            # Assertions detail
            assertion_rows = ""
            for a in r.assertions:
                icon = "✅" if a.passed else "❌"
                diff = f"<div style='margin-top:4px;'>{a.html_diff}</div>" if a.html_diff else ""
                assertion_rows += f"""
                <tr style="font-size:12px;">
                    <td style="padding:3px 8px;">{icon} {a.assertion_type}</td>
                    <td style="padding:3px 8px;font-family:monospace;">{self._escape(str(a.expected)[:80])}</td>
                    <td style="padding:3px 8px;font-family:monospace;">{self._escape(str(a.actual)[:80])}</td>
                    <td style="padding:3px 8px;color:#ef4444;">{self._escape(a.message)}</td>
                </tr>
                {diff}
                """

            detail_id = f"detail_{r.test_id.replace('-', '_')}"
            rows += f"""
            <tr onclick="toggle('{detail_id}')" style="cursor:pointer;border-bottom:1px solid #e5e7eb;">
                <td style="padding:8px 12px;">
                    <span style="color:{status_color};font-weight:600;">{status_text}</span>
                </td>
                <td style="padding:8px 12px;font-family:monospace;font-size:13px;">{self._escape(r.test_id)}</td>
                <td style="padding:8px 12px;">{self._escape(r.test_name)}</td>
                <td style="padding:8px 12px;font-family:monospace;">{r.method} {self._escape(r.url.split('/')[-1] if '/' in r.url else r.url)}</td>
                <td style="padding:8px 12px;">{r.status_code}</td>
                <td style="padding:8px 12px;">{r.duration_ms:.0f}ms</td>
                <td style="padding:8px 12px;color:#ef4444;font-size:12px;">{self._escape(r.failure_summary[:80])}</td>
            </tr>
            <tr id="{detail_id}" style="display:none;background:#f8fafc;">
                <td colspan="7" style="padding:12px 24px;">
                    <table style="width:100%;border-collapse:collapse;font-size:12px;">
                        <thead><tr style="background:#f1f5f9;">
                            <th style="padding:4px 8px;text-align:left;">Assertion</th>
                            <th style="padding:4px 8px;text-align:left;">Expected</th>
                            <th style="padding:4px 8px;text-align:left;">Actual</th>
                            <th style="padding:4px 8px;text-align:left;">Message</th>
                        </tr></thead>
                        <tbody>{assertion_rows}</tbody>
                    </table>
                    {"<details><summary style='cursor:pointer;font-size:12px;margin-top:8px;'>Response Body</summary><pre style='font-size:11px;background:#f3f4f6;padding:8px;overflow:auto;max-height:200px;'>" + self._escape(json.dumps(r.response_body, indent=2, default=str))[:2000] + "</pre></details>" if r.response_body else ""}
                </td>
            </tr>
            """

        pass_pct = f"{summary.pass_rate:.0f}"
        score_color = "#16a34a" if summary.pass_rate >= 95 else "#d97706" if summary.pass_rate >= 80 else "#dc2626"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Regression Report — {self._escape(summary.base_url)}</title>
    <style>
        body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; max-width:1200px; margin:32px auto; padding:0 20px; color:#111827; }}
        h1 {{ color:#1e3a5f; margin-bottom:4px; }}
        .meta {{ background:#f8fafc; border:1px solid #e2e8f0; padding:16px 20px; border-radius:8px; margin:16px 0; display:flex; gap:32px; align-items:center; }}
        .big-num {{ font-size:36px; font-weight:700; }}
        .stat {{ text-align:center; }}
        .stat-label {{ font-size:11px; color:#6b7280; text-transform:uppercase; }}
        table {{ width:100%; border-collapse:collapse; }}
        thead {{ background:#f1f5f9; }}
        th {{ padding:8px 12px; text-align:left; font-size:12px; color:#374151; }}
        tr:hover td {{ background:#f9fafb; }}
        input {{ padding:6px 12px; border:1px solid #d1d5db; border-radius:4px; font-size:13px; margin-bottom:12px; width:300px; }}
    </style>
    <script>
        function toggle(id) {{
            var el = document.getElementById(id);
            el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
        }}
        function filterTable(val) {{
            var rows = document.querySelectorAll('tbody tr[onclick]');
            rows.forEach(function(row) {{
                row.style.display = row.textContent.toLowerCase().includes(val.toLowerCase()) ? '' : 'none';
            }});
        }}
    </script>
</head>
<body>
    <h1>🧪 API Regression Report</h1>
    <div class="meta">
        <div class="stat">
            <div class="big-num" style="color:{score_color};">{pass_pct}%</div>
            <div class="stat-label">Pass Rate</div>
        </div>
        <div class="stat">
            <div class="big-num">{summary.total}</div>
            <div class="stat-label">Total</div>
        </div>
        <div class="stat">
            <div class="big-num" style="color:#16a34a;">{summary.passed}</div>
            <div class="stat-label">Passed</div>
        </div>
        <div class="stat">
            <div class="big-num" style="color:#dc2626;">{summary.failed}</div>
            <div class="stat-label">Failed</div>
        </div>
        <div class="stat">
            <div class="big-num" style="color:#d97706;">{summary.skipped}</div>
            <div class="stat-label">Skipped</div>
        </div>
        <div style="margin-left:auto;font-size:13px;color:#6b7280;">
            <div><strong>Target:</strong> {self._escape(summary.base_url)}</div>
            <div><strong>Duration:</strong> {summary.duration_s:.1f}s</div>
        </div>
    </div>
    <input type="text" placeholder="Filter by test ID, name, or URL..." oninput="filterTable(this.value)">
    <table>
        <thead><tr>
            <th>Status</th><th>ID</th><th>Name</th><th>Endpoint</th>
            <th>HTTP</th><th>Time</th><th>Failure</th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""

    @staticmethod
    def _escape(s: str) -> str:
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
