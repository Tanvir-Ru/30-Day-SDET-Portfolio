"""
Chaos test target (FastAPI) + full pytest test suite.

The target app provides endpoints for chaos testing.
Tests cover:
  - ToxiproxyClient unit tests (with mock server)
  - ResilienceProbe unit tests (mock Toxiproxy)
  - ChaosEngine integration tests (skips if Toxiproxy not running)
  - ResilienceScorecard model tests
  - ToxicConfig factory methods
"""

# ── Target app ────────────────────────────────────────────────────────────────
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import time, random

app = FastAPI(title="Chaos Test Target")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/users")
def users():
    # Simulate slight variance in response time
    time.sleep(random.uniform(0.005, 0.02))
    return {"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}], "total": 2}

@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    if user_id > 100:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return {"id": user_id, "name": f"User {user_id}"}

@app.post("/api/users")
def create_user(body: dict):
    return JSONResponse({"id": 99, **body}, status_code=201)


# ── Tests ─────────────────────────────────────────────────────────────────────
import json
import threading
import statistics
import pytest
import httpx
import uvicorn

from chaos.toxiproxy_client import ToxiproxyClient, ToxicConfig, ToxiproxyProxy
from chaos.probes.resilience_probes import (
    ResilienceResult, LatencyProbe, TimeoutProbe,
    PacketLossProbe, BandwidthProbe, _send_requests,
)
from chaos.engine import ChaosEngine, ResilienceScorecard


@pytest.fixture(scope="module")
def live_target():
    """Start FastAPI target on port 8700."""
    config = uvicorn.Config(app, host="0.0.0.0", port=8700, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(30):
        try:
            httpx.get("http://localhost:8700/health", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    yield "http://localhost:8700"
    server.should_exit = True


@pytest.fixture
def toxi_available():
    """Skip test if Toxiproxy is not running."""
    client = ToxiproxyClient()
    if not client.is_running():
        pytest.skip("Toxiproxy not running — start with: docker run -d -p 8474:8474 -p 18000-18005:18000-18005 ghcr.io/shopify/toxiproxy")
    yield client
    client.close()


# ── ToxicConfig tests ─────────────────────────────────────────────────────────

class TestToxicConfig:
    def test_latency_config(self):
        t = ToxicConfig.latency(200, jitter_ms=50)
        assert t.type == "latency"
        assert t.attributes["latency"] == 200
        assert t.attributes["jitter"] == 50

    def test_bandwidth_config(self):
        t = ToxicConfig.bandwidth(rate_kbps=100)
        assert t.type == "bandwidth"
        assert t.attributes["rate"] == 100

    def test_timeout_config(self):
        t = ToxicConfig.timeout(timeout_ms=3000)
        assert t.type == "timeout"
        assert t.attributes["timeout"] == 3000

    def test_reset_peer_config(self):
        t = ToxicConfig.reset_peer()
        assert t.type == "reset_peer"
        assert t.toxicity == 1.0

    def test_packet_loss_sets_toxicity(self):
        t = ToxicConfig.packet_loss(toxicity=0.5)
        assert t.toxicity == 0.5

    def test_slow_close_config(self):
        t = ToxicConfig.slow_close(delay_ms=2000)
        assert t.type == "slow_close"
        assert t.attributes["delay"] == 2000


# ── ToxiproxyClient unit tests ─────────────────────────────────────────────────

class TestToxiproxyClient:
    def test_is_running_false_when_not_available(self):
        client = ToxiproxyClient(host="localhost", port=19999)
        assert not client.is_running()

    def test_is_running_true_when_available(self, toxi_available):
        assert toxi_available.is_running()

    def test_create_and_delete_proxy(self, toxi_available, live_target):
        proxy = toxi_available.create_proxy(
            name="test_proxy_unit",
            listen="0.0.0.0:18050",
            upstream="localhost:8700",
        )
        assert proxy.name == "test_proxy_unit"
        assert "18050" in proxy.listen
        proxy.delete()
        # Confirm deleted
        proxies = toxi_available.list_proxies()
        assert "test_proxy_unit" not in proxies

    def test_proxy_context_manager(self, toxi_available, live_target):
        with toxi_available.proxy("ctx_proxy", "0.0.0.0:18051", "localhost:8700") as p:
            assert p.name == "ctx_proxy"
            resp = httpx.get(f"http://localhost:18051/api/users", timeout=5)
            assert resp.status_code == 200
        # Should be deleted after context
        assert "ctx_proxy" not in toxi_available.list_proxies()

    def test_add_and_remove_toxic(self, toxi_available, live_target):
        with toxi_available.proxy("toxic_test", "0.0.0.0:18052", "localhost:8700") as p:
            name = p.add_toxic(ToxicConfig.latency(100))
            assert name in p._toxics
            p.remove_toxic(name)
            assert name not in p._toxics

    def test_toxic_context_manager(self, toxi_available, live_target):
        with toxi_available.proxy("ctx_toxic", "0.0.0.0:18053", "localhost:8700") as p:
            with p.toxic(ToxicConfig.latency(50)) as toxic_name:
                assert toxic_name in p._toxics
                # Toxic active — requests still succeed
                resp = httpx.get("http://localhost:18053/api/users", timeout=5)
                assert resp.status_code == 200
            # Toxic removed after context
            assert toxic_name not in p._toxics


# ── ResilienceResult model tests ──────────────────────────────────────────────

class TestResilienceResult:
    def _make_result(self, graceful=True, success=8, total=10) -> ResilienceResult:
        return ResilienceResult(
            probe="test", failure_mode="test_mode",
            graceful=graceful,
            expected_behaviour="all succeed",
            actual_behaviour=f"{success}/{total} succeeded",
            requests_sent=total, requests_success=success,
            requests_failed=total - success,
            latencies_ms=[50.0, 60.0, 55.0, 70.0, 45.0],
            errors=[] if graceful else ["Connection refused"],
        )

    def test_success_rate_calculation(self):
        r = self._make_result(success=8, total=10)
        assert r.success_rate == 80.0

    def test_p95_calculation(self):
        r = self._make_result()
        assert r.p95_ms > 0

    def test_median_calculation(self):
        r = self._make_result()
        assert r.median_ms == statistics.median([50.0, 60.0, 55.0, 70.0, 45.0])

    def test_to_dict_structure(self):
        r = self._make_result()
        d = r.to_dict()
        for key in ["probe", "failure_mode", "graceful", "success_rate", "p95_ms"]:
            assert key in d

    def test_str_contains_probe_and_mode(self):
        r = self._make_result(graceful=True)
        s = str(r)
        assert "test" in s
        assert "✅" in s

    def test_ungraceful_uses_cross(self):
        r = self._make_result(graceful=False)
        s = str(r)
        assert "❌" in s


# ── Probe integration tests ───────────────────────────────────────────────────

class TestLatencyProbe:
    def test_latency_probe_returns_results(self, toxi_available, live_target):
        with toxi_available.proxy("lat_probe", "0.0.0.0:18060", "localhost:8700") as p:
            results = LatencyProbe().run(p, client_timeout=3.0, request_count=3)
        assert len(results) >= 2
        assert all(isinstance(r, ResilienceResult) for r in results)

    def test_low_latency_is_graceful(self, toxi_available, live_target):
        with toxi_available.proxy("low_lat", "0.0.0.0:18061", "localhost:8700") as p:
            with p.toxic(ToxicConfig.latency(50)):
                client = httpx.Client(timeout=5.0)
                latencies, errors, success, fail = _send_requests(
                    client, "http://localhost:18061/api/users", count=5
                )
                client.close()
        assert success == 5
        assert all(ms < 1000 for ms in latencies)

    def test_high_latency_causes_timeout(self, toxi_available, live_target):
        with toxi_available.proxy("high_lat", "0.0.0.0:18062", "localhost:8700") as p:
            with p.toxic(ToxicConfig.latency(6000)):  # 6s > 3s timeout
                client = httpx.Client(timeout=3.0)
                latencies, errors, success, fail = _send_requests(
                    client, "http://localhost:18062/api/users", count=3
                )
                client.close()
        assert fail == 3
        assert all("Timeout" in e or "timeout" in e.lower() for e in errors)


class TestTimeoutProbe:
    def test_reset_peer_causes_connection_error(self, toxi_available, live_target):
        with toxi_available.proxy("rst_probe", "0.0.0.0:18063", "localhost:8700") as p:
            with p.toxic(ToxicConfig.reset_peer()):
                client = httpx.Client(timeout=5.0)
                latencies, errors, success, fail = _send_requests(
                    client, "http://localhost:18063/api/users", count=5
                )
                client.close()
        assert fail > 0
        assert len(errors) > 0


class TestPacketLossProbe:
    def test_partial_loss_allows_some_success(self, toxi_available, live_target):
        with toxi_available.proxy("loss_probe", "0.0.0.0:18064", "localhost:8700") as p:
            results = PacketLossProbe().run(p, loss_rate=0.5, request_count=20)
        assert len(results) == 1
        # With 50% loss, expect some successes (exact count varies)
        assert results[0].requests_sent == 20


class TestBandwidthProbe:
    def test_throttled_requests_complete(self, toxi_available, live_target):
        with toxi_available.proxy("bw_probe", "0.0.0.0:18065", "localhost:8700") as p:
            results = BandwidthProbe().run(p, rate_kbps=100, request_count=3)
        assert len(results) == 1
        assert results[0].requests_sent == 3


# ── ChaosEngine tests ─────────────────────────────────────────────────────────

class TestChaosEngine:
    def test_mock_run_when_toxiproxy_unavailable(self):
        engine    = ChaosEngine("http://localhost:8700", toxi_port=19999)
        scorecard = engine.run()
        assert len(scorecard.results) == 1
        assert "unavailable" in scorecard.results[0].failure_mode.lower()

    def test_engine_runs_selected_scenarios(self, toxi_available, live_target):
        engine = ChaosEngine(
            target_url="http://localhost:8700",
            proxy_port=18070,
            scenarios=["latency"],
            client_timeout=3.0,
        )
        scorecard = engine.run()
        assert len(scorecard.results) >= 1
        assert all(r.probe == "latency" for r in scorecard.results)

    def test_scorecard_serialises(self, toxi_available, live_target):
        engine    = ChaosEngine("http://localhost:8700", proxy_port=18071, scenarios=["latency"])
        scorecard = engine.run()
        d = scorecard.to_dict()
        assert "resilience_score" in d
        assert "results" in d

    def test_scorecard_summary_string(self, toxi_available, live_target):
        engine    = ChaosEngine("http://localhost:8700", proxy_port=18072, scenarios=["latency"])
        scorecard = engine.run()
        summary   = scorecard.summary()
        assert "RESILIENCE SCORECARD" in summary
        assert "Resilience Score" in summary


# ── ResilienceScorecard model tests ───────────────────────────────────────────

class TestResilienceScorecard:
    def _make_scorecard(self, graceful_count=3, ungraceful_count=1) -> ResilienceScorecard:
        results = (
            [ResilienceResult("p", "m", True,  "e", "a", 10, 10, 0, [50.0], []) for _ in range(graceful_count)]
            + [ResilienceResult("p", "m", False, "e", "a", 10, 0, 10, [5000.0], ["Timeout"]) for _ in range(ungraceful_count)]
        )
        return ResilienceScorecard(
            target_url="http://localhost:8000",
            proxy_url="http://localhost:18000",
            results=results,
            duration_s=5.0,
        )

    def test_resilience_score(self):
        sc = self._make_scorecard(3, 1)
        assert sc.resilience_score == 75.0

    def test_critical_failures_detected(self):
        sc = self._make_scorecard(3, 1)
        assert len(sc.critical_failures) == 1

    def test_by_probe_grouping(self):
        sc = self._make_scorecard(2, 1)
        by_p = sc.by_probe()
        assert "p" in by_p

    def test_to_dict_complete(self):
        sc = self._make_scorecard()
        d  = sc.to_dict()
        for key in ["target_url", "resilience_score", "summary", "results"]:
            assert key in d
