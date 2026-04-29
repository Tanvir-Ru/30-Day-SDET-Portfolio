"""
Order Service → User Service HTTP client.

This is the real production client that Order Service uses to talk to
User Service. The Pact consumer tests mock this client's HTTP layer to
record the exact shape of requests and expected responses.
"""

import httpx
from typing import Optional


class UserServiceClient:
    """HTTP client for the User Service API."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(base_url=self.base_url, timeout=self.timeout)

    def get_user(self, user_id: int) -> dict:
        """
        Fetch a single user by ID.

        Expected response shape (v1):
            { "id": int, "name": str }

        Expected response shape (v2, after migration):
            { "id": int, "name": str, "email": str }
        """
        response = self._client.get(f"/users/{user_id}")
        response.raise_for_status()
        return response.json()

    def list_users(self, page: int = 1, per_page: int = 20) -> dict:
        """
        Fetch a paginated list of users.

        Expected response shape:
            {
                "users": [{ "id": int, "name": str }],
                "total": int,
                "page": int,
                "per_page": int
            }
        """
        response = self._client.get(
            "/users", params={"page": page, "per_page": per_page}
        )
        response.raise_for_status()
        return response.json()

    def get_user_orders(self, user_id: int) -> dict:
        """
        Fetch all orders belonging to a user.

        Expected response shape:
            { "user_id": int, "orders": [{ "order_id": str, "status": str }] }
        """
        response = self._client.get(f"/users/{user_id}/orders")
        response.raise_for_status()
        return response.json()

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
