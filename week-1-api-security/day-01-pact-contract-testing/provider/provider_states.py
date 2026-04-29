"""
Provider state handlers.

This is what most Pact tutorials skip. Each Pact interaction has a `given()`
clause — a named state like "user 123 exists". Before the Pact verifier
replays that interaction against the real API, it hits a special
/_pact/provider_states endpoint that seeds the application into that state.

Without state handlers, the provider verification is meaningless — you're
testing against whatever data happens to be in the DB, not the specific
scenario the consumer assumed.
"""

from provider.app import USERS, ORDERS


def setup_state(state: str) -> None:
    """
    Dispatch table for provider states.
    Maps state strings (from pact.given()) to setup functions.
    """
    handlers = {
        "user 123 exists": _user_123_exists,
        "user 123 exists with email": _user_123_exists,
        "user 999 does not exist": _user_999_deleted,
        "user 456 is a legacy account with no email": _user_456_legacy,
        "at least one user exists": _user_123_exists,
        "user 123 has 2 orders": _user_123_with_orders,
        "no valid auth token is provided": _no_op,
    }

    handler = handlers.get(state)
    if handler is None:
        raise ValueError(
            f"Unknown provider state: '{state}'. "
            f"Add a handler in provider_states.py."
        )
    handler()


def teardown_state(state: str) -> None:
    """Optional: reset state after verification."""
    # In a real app you'd roll back DB transactions here
    pass


# ── State setup functions ─────────────────────────────────────────────────────

def _user_123_exists():
    USERS[123] = {"id": 123, "name": "Alice Johnson", "email": "alice@example.com"}


def _user_999_deleted():
    USERS.pop(999, None)


def _user_456_legacy():
    USERS[456] = {"id": 456, "name": "Legacy User", "email": None}


def _user_123_with_orders():
    _user_123_exists()
    ORDERS[123] = [
        {
            "order_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "status": "processing",
        },
        {
            "order_id": "b2c3d4e5-f6a7-8901-bcde-f01234567890",
            "status": "delivered",
        },
    ]


def _no_op():
    """State requires no data setup — the auth check is in the handler logic."""
    pass
