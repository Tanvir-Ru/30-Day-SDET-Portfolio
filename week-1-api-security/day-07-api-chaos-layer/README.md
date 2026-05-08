# Day 07 — API Chaos & Latency Injection Layer

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A Toxiproxy-based chaos engineering framework that injects real network
failures between tests and the API under test — not simulated failures in
code, but actual TCP-level conditions. Produces a resilience scorecard
showing which failure modes your consumer handles gracefully vs which
cause crashes or hangs.

---

## The Problem This Solves

Every API integration test runs in ideal conditions: zero latency, perfect
connectivity, instantaneous responses. Production has none of these.

**Without chaos testing**, you discover resilience failures in production:
- Service A is down → Service B hangs for 30 seconds (no timeout configured)
- Database is slow → API returns 504s (no circuit breaker)
- 30% packet loss → Client retries infinitely (no retry limit)

**With this suite**, you discover these failures in CI.

---

## Architecture

```
┌────────────────┐     TCP     ┌─────────────────────┐     TCP     ┌──────────────┐
│  Test Client   │ ──────────► │  Toxiproxy Proxy     │ ──────────► │  Real API    │
│  (httpx)       │             │  localhost:18000      │             │  :8000       │
└────────────────┘             │                      │             └──────────────┘
                               │  Toxics injected:    │
                               │  • latency(500ms)    │
                               │  • reset_peer()      │
                               │  • bandwidth(10kbps) │
                               │  • packet_loss(30%)  │
                               └─────────────────────┘
                                          ↑
                               Toxiproxy Management API
                               localhost:8474 (REST)
                               ← ToxiproxyClient controls this
```

Tests point at the Toxiproxy port. Toxiproxy forwards to the real API and
injects the configured failure in the TCP stream. The consumer under test
never knows it's talking to a proxy — it just experiences real network conditions.

### Why Toxiproxy over in-code mocking?

In-code mocking (`mock.patch`) simulates failures at the application layer.
Toxiproxy injects failures at the TCP layer — the same layer where production
failures actually occur. This means timeout behaviour, connection error
handling, and retry logic are tested exactly as they run in production.

---

## Failure Modes Covered

| Probe | Failure Mode | What It Tests |
|---|---|---|
| `LatencyProbe` | 100ms / 500ms / 2s / >timeout | Timeout configuration, latency tolerance |
| `TimeoutProbe` | TCP RST (hard reset) | Connection error handling, no hangs |
| `TimeoutProbe` | Slow close (3s delay) | Half-open socket handling |
| `PacketLossProbe` | 30% random connection drops | Retry logic, partial failure tolerance |
| `BandwidthProbe` | 10 kbps throttle | Slow response handling, read timeouts |

---

## File Structure

```
day-07-api-chaos-layer/
├── chaos/
│   ├── __init__.py
│   ├── toxiproxy_client.py       # ToxiproxyClient + ToxiproxyProxy + ToxicConfig
│   ├── engine.py                 # ChaosEngine orchestrator + ResilienceScorecard
│   ├── probes/
│   │   └── resilience_probes.py  # LatencyProbe, TimeoutProbe, PacketLossProbe, BandwidthProbe
│   └── tests/
│       └── test_chaos.py         # Unit + integration tests (skips without Toxiproxy)
├── docker-compose.yml            # API + Toxiproxy + test runner
├── .github/workflows/
│   └── chaos-tests.yml           # CI with Toxiproxy service container
└── pyproject.toml
```

---

## Running Locally

```bash
# Install dependencies
poetry install

# Start Toxiproxy + test target (Docker required)
docker compose up -d api toxiproxy

# Run full chaos suite
poetry run python -m chaos.engine \
  --target http://localhost:8000 \
  --scenarios latency,timeout,packet_loss,bandwidth \
  --output text

# JSON report
poetry run python -m chaos.engine \
  --target http://localhost:8000 \
  --output json | jq '.resilience_score'

# Run only specific scenarios
poetry run python -m chaos.engine \
  --target http://localhost:8000 \
  --scenarios latency,timeout

# Run tests (unit tests work without Toxiproxy)
poetry run pytest chaos/tests/ -v -k "not toxi_available"

# Run integration tests (requires Toxiproxy)
docker run -d -p 8474:8474 -p 18000-18080:18000-18080 ghcr.io/shopify/toxiproxy
poetry run pytest chaos/tests/ -v
```

---

## Sample Resilience Scorecard

```
======================================================================
API RESILIENCE SCORECARD
======================================================================
Target            : http://localhost:8000
Proxy (Toxiproxy) : http://localhost:18000
Duration          : 45.3s

Resilience Score  : 75%  (3 graceful / 4 scenarios)

  ── LATENCY PROBE ──
  ✅  100ms latency — should succeed
       Expected : All requests succeed with added latency
       Actual   : 5/5 succeeded, p95=163ms, median=145ms

  ✅  500ms latency — should succeed
       Expected : All requests succeed with added latency
       Actual   : 5/5 succeeded, p95=562ms, median=528ms

  ✅  >5s — should timeout
       Expected : All requests timeout within 10s
       Actual   : 5/5 timed out cleanly, p95=5102ms

  ── TIMEOUT PROBE ──
  ❌  TCP reset (RST)
       Expected : Connection error raised quickly (<2s), not a hang
       Actual   : 10/10 failed, median=4823ms  ← HANGING
       Errors   : Connection refused
======================================================================
```

---

## ToxicConfig API

```python
from chaos.toxiproxy_client import ToxicConfig

# Add 500ms latency with ±50ms jitter
ToxicConfig.latency(latency_ms=500, jitter_ms=50)

# Limit to 10 KB/s
ToxicConfig.bandwidth(rate_kbps=10)

# Timeout connection after 3s
ToxicConfig.timeout(timeout_ms=3000)

# Send TCP RST immediately
ToxicConfig.reset_peer()

# Randomly drop 30% of connections
ToxicConfig.packet_loss(toxicity=0.3)

# Delay connection close by 2s (half-open sockets)
ToxicConfig.slow_close(delay_ms=2000)
```

### Context manager usage

```python
from chaos.toxiproxy_client import ToxiproxyClient, ToxicConfig

toxi = ToxiproxyClient()

with toxi.proxy("my_service", "0.0.0.0:18000", "api:8000") as proxy:
    # No toxics — baseline
    run_tests(proxy.url)

    with proxy.toxic(ToxicConfig.latency(1000)):
        # 1s latency injected
        run_tests(proxy.url)

    # Latency removed — back to normal
    run_tests(proxy.url)
```

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `httpx` | HTTP client for test requests |
| `fastapi` / `uvicorn` | Test target API |
| `pytest` | Test runner |
| `ghcr.io/shopify/toxiproxy` | TCP proxy for failure injection (Docker) |

---

## Recruiter Talking Points

- **Why Toxiproxy over mocking?** Mocking in Python patches the function call —
  it never hits the network. Toxiproxy injects failure at the TCP layer, so timeout
  handling, connection pooling, retry logic, and circuit breakers are tested exactly
  as they behave in production. You can't discover "client hangs for 30s on connection
  reset" with a mock.

- **What's the most critical finding type?** A client that hangs instead of timing out
  is worse than a client that fails. If Service A hangs for 30s waiting for Service B,
  that 30s ties up a thread, exhausts connection pools, and causes cascading failures.
  This probe finds hangs before they reach production.

- **What's the resilience score?** A weighted metric (graceful/total) that gives teams
  a single number to track across releases. A score drop from 80% to 60% after a
  dependency change is immediately visible in CI.

- **What's the difference between packet_loss toxicity and disable?** `toxicity=0.3`
  drops 30% of connections randomly — some requests succeed, some fail. `disable=true`
  drops 100%. The random failure mode is the realistic production scenario; 100% failure
  is easy to handle. 30% intermittent failure is where clients misbehave.
