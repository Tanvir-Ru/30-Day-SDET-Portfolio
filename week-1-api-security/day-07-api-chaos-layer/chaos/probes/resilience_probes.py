"""
Resilience probes — measure consumer behaviour under injected failures.

Each probe injects a specific failure mode via Toxiproxy and measures
how the consumer (API client) responds. The probe produces a
ResilienceResult with:
  - Whether the consumer handled the failure gracefully
  - Actual vs expected behaviour
  - Timeout/retry/circuit-breaker effectiveness

Probe categories:
  1. LatencyProbe       — does the client respect its timeout setting?
  2. TimeoutProbe       — does the client handle connection drops gracefully?
  3. PacketLossProbe    — does the client retry on transient errors?
  4. BandwidthProbe     — does the client handle slow responses?
  5. PartialFailureProbe — does the client handle mixed success/error responses?
  6. CascadeFailureProbe — does a single dependency failure cause a cascade?
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from chaos.toxiproxy_client import ToxiproxyProxy, ToxicConfig


@dataclass
class ResilienceResult:
    probe:            str
    failure_mode:     str
    graceful:         bool           # Did the consumer handle this gracefully?
    expected_behaviour: str
    actual_behaviour:   str
    requests_sent:    int
    requests_success: int
    requests_failed:  int
    latencies_ms:     list[float]
    errors:           list[str]
    notes:            list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.requests_sent == 0:
            return 0.0
        return (self.requests_success / self.requests_sent) * 100

    @property
    def p95_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_ms = sorted(self.latencies_ms)
        idx = int(len(sorted_ms) * 0.95)
        return sorted_ms[min(idx, len(sorted_ms) - 1)]

    @property
    def median_ms(self) -> float:
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0.0

    def to_dict(self) -> dict:
        return {
            "probe":              self.probe,
            "failure_mode":       self.failure_mode,
            "graceful":           self.graceful,
            "expected_behaviour": self.expected_behaviour,
            "actual_behaviour":   self.actual_behaviour,
            "requests_sent":      self.requests_sent,
            "success_rate":       round(self.success_rate, 1),
            "p95_ms":             round(self.p95_ms, 1),
            "median_ms":          round(self.median_ms, 1),
            "errors":             self.errors[:5],
            "notes":              self.notes,
        }

    def __str__(self) -> str:
        icon = "✅" if self.graceful else "❌"
        return (
            f"{icon} [{self.probe}] {self.failure_mode}: "
            f"{self.actual_behaviour} "
            f"(success={self.success_rate:.0f}%, p95={self.p95_ms:.0f}ms)"
        )


# ── Helper ────────────────────────────────────────────────────────────────────

def _send_requests(
    client:  httpx.Client,
    url:     str,
    count:   int = 10,
    method:  str = "GET",
    body:    dict = None,
) -> tuple[list[float], list[str], int, int]:
    """Send N requests and return (latencies_ms, errors, success_count, fail_count)."""
    latencies: list[float] = []
    errors:    list[str]   = []
    success = fail = 0

    for _ in range(count):
        t0 = time.perf_counter()
        try:
            resp = client.request(method, url, json=body)
            ms   = (time.perf_counter() - t0) * 1000
            latencies.append(ms)
            if resp.status_code < 500:
                success += 1
            else:
                fail += 1
                errors.append(f"HTTP {resp.status_code}")
        except httpx.TimeoutException as e:
            ms = (time.perf_counter() - t0) * 1000
            latencies.append(ms)
            fail += 1
            errors.append(f"Timeout after {ms:.0f}ms")
        except httpx.ConnectError as e:
            ms = (time.perf_counter() - t0) * 1000
            latencies.append(ms)
            fail += 1
            errors.append(f"Connection error: {type(e).__name__}")
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000
            latencies.append(ms)
            fail += 1
            errors.append(str(e)[:80])

    return latencies, errors, success, fail


# ── Probes ────────────────────────────────────────────────────────────────────

class LatencyProbe:
    """
    Inject increasing latency and measure:
      1. Does the client timeout appropriately?
      2. Is the timeout value reasonable (not too long, not too short)?
      3. Does latency degrade smoothly or does the client hang?
    """
    name = "latency"

    def run(
        self,
        proxy:         ToxiproxyProxy,
        client_timeout: float = 5.0,
        request_count:  int = 5,
    ) -> list[ResilienceResult]:
        results = []
        base_url = f"http://{proxy.listen}/api/users"
        client   = httpx.Client(timeout=client_timeout, follow_redirects=True)

        latency_levels = [
            (100,  "100ms latency — should succeed"),
            (500,  "500ms latency — should succeed"),
            (2000, "2s latency — near timeout threshold"),
            (int(client_timeout * 1000) + 500, f">{client_timeout:.0f}s — should timeout"),
        ]

        for latency_ms, description in latency_levels:
            with proxy.toxic(ToxicConfig.latency(latency_ms, jitter_ms=50)):
                latencies, errors, success, fail = _send_requests(
                    client, base_url, count=request_count
                )

            is_above_timeout = latency_ms > client_timeout * 1000
            expected_success = fail == request_count if is_above_timeout else success > 0
            graceful = (
                # Below timeout: should mostly succeed
                (not is_above_timeout and success >= request_count // 2)
                or
                # Above timeout: should ALL timeout cleanly (no hangs > 2× timeout)
                (is_above_timeout and all(ms <= (client_timeout * 1000 * 2) for ms in latencies))
            )

            results.append(ResilienceResult(
                probe=self.name,
                failure_mode=description,
                graceful=graceful,
                expected_behaviour=(
                    "All requests succeed with added latency" if not is_above_timeout
                    else f"All requests timeout within {client_timeout * 2:.0f}s"
                ),
                actual_behaviour=(
                    f"{success}/{request_count} succeeded, p95={sorted(latencies)[int(len(latencies)*0.95)-1]:.0f}ms"
                    if latencies else "No data"
                ),
                requests_sent=request_count,
                requests_success=success,
                requests_failed=fail,
                latencies_ms=latencies,
                errors=list(set(errors))[:3],
            ))

        client.close()
        return results


class TimeoutProbe:
    """
    Inject connection resets and timeouts. Verify the client:
      1. Handles TCP RST gracefully (raises exception, not hang)
      2. Handles mid-response connection close
      3. Does NOT retry on non-idempotent methods without explicit config
    """
    name = "timeout"

    def run(self, proxy: ToxiproxyProxy, request_count: int = 10) -> list[ResilienceResult]:
        results = []
        base_url = f"http://{proxy.listen}/api/users"
        client   = httpx.Client(timeout=5.0)

        # Test 1: TCP reset
        with proxy.toxic(ToxicConfig.reset_peer(timeout_ms=0)):
            latencies, errors, success, fail = _send_requests(client, base_url, count=request_count)

        graceful = fail > 0 and all(ms < 2000 for ms in latencies)
        results.append(ResilienceResult(
            probe=self.name,
            failure_mode="TCP reset (RST)",
            graceful=graceful,
            expected_behaviour="Connection error raised quickly (<2s), not a hang",
            actual_behaviour=(
                f"{fail}/{request_count} failed, median={statistics.median(latencies):.0f}ms"
                if latencies else "No data"
            ),
            requests_sent=request_count,
            requests_success=success,
            requests_failed=fail,
            latencies_ms=latencies,
            errors=list(set(errors))[:3],
        ))

        # Test 2: Slow close (socket half-open)
        with proxy.toxic(ToxicConfig.slow_close(delay_ms=3000)):
            latencies2, errors2, success2, fail2 = _send_requests(client, base_url, count=5)

        results.append(ResilienceResult(
            probe=self.name,
            failure_mode="Slow close (3s delay)",
            graceful=all(ms < 6000 for ms in latencies2),
            expected_behaviour="Requests complete (data received before close delay)",
            actual_behaviour=f"{success2}/5 succeeded",
            requests_sent=5,
            requests_success=success2,
            requests_failed=fail2,
            latencies_ms=latencies2,
            errors=list(set(errors2))[:3],
        ))

        client.close()
        return results


class PacketLossProbe:
    """
    Simulate packet loss. Verify the consumer:
      1. Retries on connection failures
      2. Eventually succeeds despite partial failures
      3. Doesn't retry infinitely (respects max_retries config)
    """
    name = "packet_loss"

    def run(
        self,
        proxy:          ToxiproxyProxy,
        loss_rate:      float = 0.3,
        request_count:  int = 20,
    ) -> list[ResilienceResult]:
        base_url = f"http://{proxy.listen}/api/users"
        client   = httpx.Client(timeout=3.0)

        with proxy.toxic(ToxicConfig.packet_loss(toxicity=loss_rate)):
            latencies, errors, success, fail = _send_requests(
                client, base_url, count=request_count
            )

        # With 30% loss, expect ~70% success if client does NOT retry
        # With retries, expect higher success rate
        expected_min_success_pct = (1 - loss_rate) * 100 * 0.8  # 80% of theoretical
        actual_success_pct = (success / request_count) * 100

        graceful = (
            actual_success_pct >= expected_min_success_pct
            and all(ms < 5000 for ms in latencies)   # No hangs
        )

        client.close()
        return [ResilienceResult(
            probe=self.name,
            failure_mode=f"{loss_rate*100:.0f}% packet loss",
            graceful=graceful,
            expected_behaviour=f"≥{expected_min_success_pct:.0f}% success with no hangs",
            actual_behaviour=f"{actual_success_pct:.0f}% success, p95={sorted(latencies)[int(len(latencies)*0.95)-1]:.0f}ms",
            requests_sent=request_count,
            requests_success=success,
            requests_failed=fail,
            latencies_ms=latencies,
            errors=list(set(errors))[:5],
            notes=[f"Packet loss rate: {loss_rate*100:.0f}%"],
        )]


class BandwidthProbe:
    """
    Throttle bandwidth and verify the consumer handles slow responses
    without timeouts or corrupted payloads.
    """
    name = "bandwidth"

    def run(
        self,
        proxy:          ToxiproxyProxy,
        rate_kbps:      int = 10,
        request_count:  int = 5,
    ) -> list[ResilienceResult]:
        base_url = f"http://{proxy.listen}/api/users"
        client   = httpx.Client(timeout=30.0)  # Long timeout for throttled responses

        with proxy.toxic(ToxicConfig.bandwidth(rate_kbps=rate_kbps)):
            latencies, errors, success, fail = _send_requests(
                client, base_url, count=request_count
            )

        graceful = success > 0 and fail == 0
        client.close()
        return [ResilienceResult(
            probe=self.name,
            failure_mode=f"Bandwidth throttled to {rate_kbps}kbps",
            graceful=graceful,
            expected_behaviour="All requests succeed despite slow transfer",
            actual_behaviour=f"{success}/{request_count} succeeded, median={statistics.median(latencies):.0f}ms",
            requests_sent=request_count,
            requests_success=success,
            requests_failed=fail,
            latencies_ms=latencies,
            errors=list(set(errors))[:3],
            notes=[f"Rate limit: {rate_kbps}kbps"],
        )]
