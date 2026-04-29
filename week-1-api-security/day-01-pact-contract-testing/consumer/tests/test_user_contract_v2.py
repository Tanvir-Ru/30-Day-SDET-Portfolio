"""
Consumer contract tests — v2 schema (after migration).

Order Service v2 requires the `email` field from User Service.
These tests define the NEW contract shape that User Service must satisfy
WITHOUT breaking the v1 contract above.

This is the core value proposition of Pact: the provider must satisfy
ALL consumer contracts simultaneously across all registered versions.
"""

import pytest
from pact import Like


class TestGetUserV2:
    """Contract: GET /users/:id now REQUIRES email field."""

    def test_get_user_includes_email_field(self, pact, user_client):
        """
        v2 consumer now depends on the email field.
        If User Service removes or renames this field, this contract breaks
        and the can-i-deploy gate blocks the deployment.
        """
        expected_body = {
            "id": Like(123),
            "name": Like("Alice Johnson"),
            "email": Like("alice@example.com"),  # NEW FIELD in v2
        }

        (
            pact.given("user 123 exists with email")
            .upon_receiving("a v2 GET request for user 123 expecting email")
            .with_request(method="GET", path="/users/123")
            .will_respond_with(
                status=200,
                headers={"Content-Type": "application/json"},
                body=expected_body,
            )
        )

        with pact:
            result = user_client.get_user(123)

        assert "email" in result, (
            "v2 contract requires 'email' field — User Service is breaking this consumer"
        )
        assert "@" in result["email"], "email field must be a valid email address"

    def test_get_user_email_can_be_null_for_legacy_accounts(self, pact, user_client):
        """
        Edge case: legacy accounts pre-dating email collection may have null email.
        Explicitly contracting this prevents the provider from accidentally
        returning a 500 on legacy records.
        """
        expected_body = {
            "id": Like(456),
            "name": Like("Legacy User"),
            "email": None,  # Explicitly nullable
        }

        (
            pact.given("user 456 is a legacy account with no email")
            .upon_receiving("a v2 GET request for legacy user 456")
            .with_request(method="GET", path="/users/456")
            .will_respond_with(
                status=200,
                headers={"Content-Type": "application/json"},
                body=expected_body,
            )
        )

        with pact:
            result = user_client.get_user(456)

        # Consumer must handle null email gracefully
        assert result.get("email") is None


class TestAuthHeaderContract:
    """Contract: endpoints require Authorization header in v2."""

    def test_missing_auth_header_returns_401(self, pact, user_client):
        """
        v2 introduces authentication. Contracting the 401 response
        means the provider can't silently drop auth or change error shape.
        """
        (
            pact.given("no valid auth token is provided")
            .upon_receiving("a request with missing Authorization header")
            .with_request(
                method="GET",
                path="/users/123",
                headers={"Authorization": "Bearer invalid-token"},
            )
            .will_respond_with(
                status=401,
                headers={"Content-Type": "application/json"},
                body={
                    "error": Like("Unauthorized"),
                    "code": Like("INVALID_TOKEN"),
                },
            )
        )

        with pact:
            import httpx
            # Temporarily override client to send bad token
            bad_client = type(user_client)(
                base_url=user_client.base_url
            )
            bad_client._client.headers["Authorization"] = "Bearer invalid-token"
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                bad_client.get_user(123)
            assert exc_info.value.response.status_code == 401
            bad_client.close()
