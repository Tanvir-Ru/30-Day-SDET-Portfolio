"""
Chaos Engine — orchestrates all resilience probes and produces
a resilience scorecard showing which failure modes are handled
gracefully vs which cause consumer crashes.

Usage (CLI):
    python -m chaos.engine --target http://localhost:8000 --scenarios all
    python -m chaos.engine --target http://localhost:8000 --scenarios latency,timeout
    python -m chaos.engine --target http://localhost:8000 --output json

Usage (library):
    from chaos.engine import ChaosEngine
    engine = ChaosEngine("http://localhost:8000")
    scorecard = engine.run()
    print(scorecard.summary())

Architecture:
    ChaosEngine creates a Toxiproxy proxy that sits between the test
    client and the real API. Each probe injects a failure mode via
    Toxiproxy and measures how the consumer responds.

    [TestClient] → localhost:18000 (Toxiproxy) → localhost:8000 (Real API)
                       ↑
                   Toxics injected here
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from chaos.toxiproxy_client import ToxiproxyClient, ToxicConfig
from chaos.probes.resilience_probes import (
    LatencyProbe, TimeoutProbe, PacketLossProbe, BandwidthProbe,
    ResilienceResult,
)


@dataclass
class ResilienceScorecard:
    target_url:     str
    proxy_url:      str
    results:        list[ResilienceResult]
    duration_s:     float
    timestamp:      float = field(default_factory=time.time)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def graceful_count(self) -> int:
        return sum(1 for r in self.results if r.graceful)

    @property
    def ungraceful_count(self) -> int:
        return sum(1 for r in self.results if not r.graceful)

    @property
    def resilience_score(self) -> float:
        if not self.results:
            return 0.0
        return (self.graceful_count / self.total) * 100

    @property
    def critical_failures(self) -> list[ResilienceResult]:
        """Failure modes that caused complete consumer crashes or hangs."""
        return [
            r for r in self.results
            if not r.graceful and r.success_rate == 0
        ]

    def by_probe(self) -> dict[str, list[ResilienceResult]]:
        result: dict[str, list[ResilienceResult]] = {}
        for r in self.results:
            result.setdefault(r.probe, []).append(r)
        return result

    def summary(self) -> str:
        lines = [
            "=" * 70,
            "API RESILIENCE SCORECARD",
            "=" * 70,
            f"Target            : {self.target_url}",
            f"Proxy (Toxiproxy) : {self.proxy_url}",
            f"Duration          : {self.duration_s:.1f}s",
            f"",
            f"Resilience Score  : {self.resilience_score:.0f}%  "
            f"({self.graceful_count} graceful / {self.total} scenarios)",
            "",
        ]

        for probe, probe_results in self.by_probe().items():
            lines.append(f"  ── {probe.upper()} PROBE ──")
            for r in probe_results:
                icon = "✅" if r.graceful else "❌"
                lines.append(f"  {icon}  {r.failure_mode}")
                lines.append(f"       Expected : {r.expected_behaviour}")
                lines.append(f"       Actual   : {r.actual_behaviour}")
                lines.append(f"       Requests : {r.requests_success}/{r.requests_sent} succeeded  "
                              f"p95={r.p95_ms:.0f}ms  median={r.median_ms:.0f}ms")
                if r.errors:
                    lines.append(f"       Errors   : {r.errors[0]}")
                lines.append("")

        if self.critical_failures:
            lines.append("❗ CRITICAL FAILURES (0% success rate):")
            for r in self.critical_failures:
                lines.append(f"   • {r.failure_mode}: {r.actual_behaviour}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target_url":       self.target_url,
            "proxy_url":        self.proxy_url,
            "timestamp":        self.timestamp,
            "duration_s":       round(self.duration_s, 2),
            "resilience_score": round(self.resilience_score, 1),
            "summary": {
                "total":    self.total,
                "graceful": self.graceful_count,
                "failed":   self.ungraceful_count,
            },
            "results": [r.to_dict() for r in self.results],
        }


class ChaosEngine:
    """
    Orchestrates Toxiproxy-based chaos experiments against a target API.

    Requires Toxiproxy running on localhost:8474 (management API).
    Docker: docker run -d -p 8474:8474 -p 18000-18010:18000-18010 \\
                ghcr.io/shopify/toxiproxy
    """

    PROXY_NAME = "api_under_test"
    PROXY_PORT = 18000

    def __init__(
        self,
        target_url:      str,
        toxi_host:       str = "localhost",
        toxi_port:       int = 8474,
        proxy_port:      int = None,
        client_timeout:  float = 5.0,
        scenarios:       list[str] = None,
    ):
        self.target_url     = target_url.rstrip("/")
        self.toxi_host      = toxi_host
        self.toxi_port      = toxi_port
        self.proxy_port     = proxy_port or self.PROXY_PORT
        self.client_timeout = client_timeout
        self.scenarios      = scenarios or ["latency", "timeout", "packet_loss", "bandwidth"]

        # Extract upstream host:port from target URL
        import urllib.parse
        parsed = urllib.parse.urlparse(target_url)
        self._upstream = f"{parsed.hostname}:{parsed.port or 80}"

    def run(self) -> ResilienceScorecard:
        start = time.perf_counter()
        toxi  = ToxiproxyClient(self.toxi_host, self.toxi_port)

        if not toxi.is_running():
            print("⚠️  Toxiproxy not running — using mock mode (no actual chaos injection)")
            return self._mock_run(time.perf_counter() - start)

        all_results: list[ResilienceResult] = []
        proxy_url = f"http://localhost:{self.proxy_port}"

        with toxi.proxy(
            name=self.PROXY_NAME,
            listen=f"0.0.0.0:{self.proxy_port}",
            upstream=self._upstream,
        ) as proxy:

            if "latency" in self.scenarios:
                print("  → Running latency probe...", flush=True)
                results = LatencyProbe().run(proxy, client_timeout=self.client_timeout)
                all_results.extend(results)
                print(f"     {sum(1 for r in results if r.graceful)}/{len(results)} graceful")

            if "timeout" in self.scenarios:
                print("  → Running timeout/reset probe...", flush=True)
                results = TimeoutProbe().run(proxy)
                all_results.extend(results)
                print(f"     {sum(1 for r in results if r.graceful)}/{len(results)} graceful")

            if "packet_loss" in self.scenarios:
                print("  → Running packet loss probe...", flush=True)
                results = PacketLossProbe().run(proxy, loss_rate=0.3)
                all_results.extend(results)
                print(f"     {sum(1 for r in results if r.graceful)}/{len(results)} graceful")

            if "bandwidth" in self.scenarios:
                print("  → Running bandwidth throttle probe...", flush=True)
                results = BandwidthProbe().run(proxy, rate_kbps=10)
                all_results.extend(results)
                print(f"     {sum(1 for r in results if r.graceful)}/{len(results)} graceful")

        toxi.close()
        return ResilienceScorecard(
            target_url=self.target_url,
            proxy_url=proxy_url,
            results=all_results,
            duration_s=time.perf_counter() - start,
        )

    def _mock_run(self, elapsed: float) -> ResilienceScorecard:
        """Return a mock scorecard when Toxiproxy is not available."""
        from chaos.probes.resilience_probes import ResilienceResult
        mock = [ResilienceResult(
            probe="mock",
            failure_mode="Toxiproxy unavailable",
            graceful=False,
            expected_behaviour="Toxiproxy running on localhost:8474",
            actual_behaviour="Toxiproxy not reachable — start with: docker run -d -p 8474:8474 -p 18000:18000 ghcr.io/shopify/toxiproxy",
            requests_sent=0, requests_success=0, requests_failed=0,
            latencies_ms=[], errors=["Toxiproxy not running"],
        )]
        return ResilienceScorecard(
            target_url=self.target_url,
            proxy_url="N/A",
            results=mock,
            duration_s=elapsed,
        )


def main():
    parser = argparse.ArgumentParser(description="API Chaos & Resilience Engine")
    parser.add_argument("--target",    required=True, help="Target API base URL")
    parser.add_argument("--toxi-host", default="localhost")
    parser.add_argument("--toxi-port", type=int, default=8474)
    parser.add_argument("--scenarios", default="latency,timeout,packet_loss,bandwidth",
                        help="Comma-separated: latency,timeout,packet_loss,bandwidth")
    parser.add_argument("--timeout",   type=float, default=5.0, help="Client timeout seconds")
    parser.add_argument("--output",    choices=["text", "json"], default="text")
    parser.add_argument("--out-file",  default="chaos-report")
    args = parser.parse_args()

    scenarios = [s.strip() for s in args.scenarios.split(",")]
    print(f"\nChaos Engine → {args.target}")
    print(f"Scenarios: {', '.join(scenarios)}\n")

    engine    = ChaosEngine(
        target_url=args.target,
        toxi_host=args.toxi_host,
        toxi_port=args.toxi_port,
        client_timeout=args.timeout,
        scenarios=scenarios,
    )
    scorecard = engine.run()
    print()

    if args.output == "json":
        out = f"{args.out_file}.json"
        Path(out).write_text(json.dumps(scorecard.to_dict(), indent=2))
        print(f"JSON report: {out}")
    else:
        print(scorecard.summary())

    sys.exit(0 if scorecard.ungraceful_count == 0 else 1)


if __name__ == "__main__":
    main()
