"""
Consumer test fixtures.

Sets up the Pact MockServer which intercepts HTTP calls made by the
UserServiceClient and records them as a JSON contract file.
"""

import pytest
from pact import Consumer, Provider

from consumer.client import UserServiceClient

PACT_MOCK_HOST = "localhost"
PACT_MOCK_PORT = 1234
PACT_DIR = "./consumer/pacts"
PACT_BROKER_URL = "http://localhost:9292"


@pytest.fixture(scope="session")
def pact():
    """
    Session-scoped Pact instance.

    - Consumer name  : order-service
    - Provider name  : user-service
    - Pact directory : ./consumer/pacts  (committed for review; real projects use broker)

    The MockServer starts on localhost:1234 and intercepts all HTTP traffic
    for the duration of the test session.
    """
    pact = Consumer("order-service").has_pact_with(
        Provider("user-service"),
        host_name=PACT_MOCK_HOST,
        port=PACT_MOCK_PORT,
        pact_dir=PACT_DIR,
        log_dir="./logs",
        log_level="WARNING",
    )
    pact.start_service()
    yield pact
    pact.stop_service()


@pytest.fixture(scope="session")
def user_client():
    """Real client pointed at the Pact MockServer."""
    with UserServiceClient(
        base_url=f"http://{PACT_MOCK_HOST}:{PACT_MOCK_PORT}"
    ) as client:
        yield client
