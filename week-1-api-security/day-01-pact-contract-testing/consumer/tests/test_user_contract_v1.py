"""
Consumer contract tests — v1 schema.

These tests define what Order Service *expects* from User Service today.
Each test sets up an interaction (request + expected response) and
verifies the client can handle it correctly.

The Pact file generated from these tests becomes the binding contract
that User Service must satisfy.
"""

import pytest
from pact import Like, EachLike, Term


class TestGetUserV1:
    """Contract: GET /users/:id returns basic user shape."""

    def test_get_existing_user_returns_id_and_name(self, pact, user_client):
        """
        Happy path — user exists.

        Like() means: "I don't care about the exact value,
        only that it matches this TYPE." This prevents brittle
        tests that break when test data changes.
        """
        expected_body = {
            "id": Like(123),
            "name": Like("Alice Johnson"),
        }

        (
            pact.given("user 123 exists")
            .upon_receiving("a GET request for user 123")
            .with_request(method="GET", path="/users/123")
            .will_respond_with(
                status=200,
                headers={"Content-Type": "application/json"},
                body=expected_body,
            )
        )

        with pact:
            result = user_client.get_user(123)

        assert result["id"] == 123
        assert isinstance(result["name"], str)

    def test_get_nonexistent_user_returns_404(self, pact, user_client):
        """
        User does not exist — provider must return 404 with error body.
        Defining error contracts is just as important as happy-path contracts.
        """
        (
            pact.given("user 999 does not exist")
            .upon_receiving("a GET request for nonexistent user 999")
            .with_request(method="GET", path="/users/999")
            .will_respond_with(
                status=404,
                headers={"Content-Type": "application/json"},
                body={"error": Like("User not found"), "code": Like("USER_NOT_FOUND")},
            )
        )

        with pact:
            import httpx
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                user_client.get_user(999)
            assert exc_info.value.response.status_code == 404


class TestListUsersV1:
    """Contract: GET /users returns paginated list."""

    def test_list_users_returns_paginated_response(self, pact, user_client):
        """
        EachLike() means: "I expect an array where EACH item looks like this."
        The second argument is min items (default 1).
        """
        expected_body = {
            "users": EachLike({"id": Like(1), "name": Like("Bob")}),
            "total": Like(42),
            "page": Like(1),
            "per_page": Like(20),
        }

        (
            pact.given("at least one user exists")
            .upon_receiving("a GET request for paginated users")
            .with_request(
                method="GET",
                path="/users",
                query={"page": ["1"], "per_page": ["20"]},
            )
            .will_respond_with(
                status=200,
                headers={"Content-Type": "application/json"},
                body=expected_body,
            )
        )

        with pact:
            result = user_client.list_users(page=1, per_page=20)

        assert "users" in result
        assert isinstance(result["users"], list)
        assert len(result["users"]) >= 1


class TestGetUserOrdersV1:
    """Contract: GET /users/:id/orders returns orders list."""

    def test_get_orders_for_existing_user(self, pact, user_client):
        """
        Term() allows regex matching — here we ensure order_id follows
        a UUID-like pattern without hardcoding a specific value.
        """
        expected_body = {
            "user_id": Like(123),
            "orders": EachLike(
                {
                    "order_id": Term(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    ),
                    "status": Term(
                        r"(pending|processing|shipped|delivered|cancelled)",
                        "processing",
                    ),
                }
            ),
        }

        (
            pact.given("user 123 has 2 orders")
            .upon_receiving("a GET request for user 123's orders")
            .with_request(method="GET", path="/users/123/orders")
            .will_respond_with(
                status=200,
                headers={"Content-Type": "application/json"},
                body=expected_body,
            )
        )

        with pact:
            result = user_client.get_user_orders(123)

        assert result["user_id"] == 123
        assert len(result["orders"]) >= 1
