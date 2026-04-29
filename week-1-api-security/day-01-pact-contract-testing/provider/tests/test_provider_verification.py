"""
Provider verification tests.

The Pact Verifier downloads every contract from the Pact Broker that
mentions "user-service" as the provider, then replays each interaction
against a running instance of the FastAPI app.

Any interaction that returns a different status code, body, or headers
than the contract specifies will cause this test to FAIL — blocking the
deployment via the CI gate.
"""

import pytest
import threading
import uvicorn
from pact import Verifier
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from provider.app import app
from provider.provider_states import setup_state, teardown_state

PROVIDER_PORT = 8000
PROVIDER_BASE_URL = f"http://localhost:{PROVIDER_PORT}"
PACT_BROKER_URL = "http://localhost:9292"
PROVIDER_VERSION = "1.1.0"


# ── Provider state endpoint ───────────────────────────────────────────────────
# Pact verifier calls POST /_pact/provider_states before each interaction
# to seed the application into the correct state.

@app.post("/_pact/provider_states")
async def provider_states(body: dict):
    """
    Endpoint called by Pact verifier before each interaction.
    Receives: { "state": "user 123 exists", "action": "setup" }
    """
    state = body.get("state", "")
    action = body.get("action", "setup")

    if action == "setup":
        setup_state(state)
    elif action == "teardown":
        teardown_state(state)

    return JSONResponse({"result": "OK"})


# ── Server fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def provider_server():
    """Start the FastAPI provider in a background thread for verification."""
    config = uvicorn.Config(app, host="0.0.0.0", port=PROVIDER_PORT, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    import time
    import httpx
    for _ in range(20):
        try:
            httpx.get(f"{PROVIDER_BASE_URL}/users/123", timeout=1)
            break
        except Exception:
            time.sleep(0.3)

    yield

    server.should_exit = True


# ── Verification test ─────────────────────────────────────────────────────────

def test_provider_satisfies_all_consumer_contracts():
    """
    Download all contracts from the Pact Broker and verify each one
    against the running User Service.

    This single test covers ALL consumer versions registered in the broker.
    Adding a new consumer or a new consumer version requires zero changes here.
    """
    verifier = Verifier(
        provider="user-service",
        provider_base_url=PROVIDER_BASE_URL,
    )

    output, _ = verifier.verify_with_broker(
        broker_url=PACT_BROKER_URL,
        provider_states_setup_url=f"{PROVIDER_BASE_URL}/_pact/provider_states",
        publish_verification_results=True,
        provider_version=PROVIDER_VERSION,
        enable_pending=True,  # Won't fail on WIP contracts
    )

    assert output == 0, (
        "One or more consumer contracts were violated. "
        "Check the Pact Broker UI for details: "
        f"{PACT_BROKER_URL}/matrix"
    )


def test_provider_satisfies_local_pact_file():
    """
    Fallback: verify against the locally committed pact file.
    Useful for local development without a running Pact Broker.
    """
    verifier = Verifier(
        provider="user-service",
        provider_base_url=PROVIDER_BASE_URL,
    )

    output, _ = verifier.verify_pacts(
        sources=["./consumer/pacts/order-service-user-service.json"],
        provider_states_setup_url=f"{PROVIDER_BASE_URL}/_pact/provider_states",
    )

    assert output == 0
