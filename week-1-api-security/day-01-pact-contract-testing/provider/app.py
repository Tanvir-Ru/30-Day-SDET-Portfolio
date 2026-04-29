"""
User Service — FastAPI provider.

This is the real provider that Order Service consumes. The Pact provider
verification tests replay every interaction defined in the consumer contracts
against this running application to confirm all contracts are satisfied.
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Optional
from pydantic import BaseModel

app = FastAPI(title="User Service", version="1.1.0")


# ── In-memory data store (replace with real DB in production) ─────────────────

USERS: dict[int, dict] = {
    123: {"id": 123, "name": "Alice Johnson", "email": "alice@example.com"},
    456: {"id": 456, "name": "Legacy User", "email": None},
}

ORDERS: dict[int, list] = {
    123: [
        {"order_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "status": "processing"},
        {"order_id": "b2c3d4e5-f6a7-8901-bcde-f01234567890", "status": "delivered"},
    ]
}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/users/{user_id}")
async def get_user(user_id: int, authorization: Optional[str] = Header(None)):
    """Return a user by ID. Satisfies both v1 and v2 consumer contracts."""
    if authorization == "Bearer invalid-token":
        raise HTTPException(
            status_code=401,
            detail={"error": "Unauthorized", "code": "INVALID_TOKEN"},
        )

    user = USERS.get(user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error": "User not found", "code": "USER_NOT_FOUND"},
        )
    return user


@app.get("/users")
async def list_users(page: int = 1, per_page: int = 20):
    """Return paginated users."""
    all_users = list(USERS.values())
    start = (page - 1) * per_page
    end = start + per_page
    return {
        "users": all_users[start:end],
        "total": len(all_users),
        "page": page,
        "per_page": per_page,
    }


@app.get("/users/{user_id}/orders")
async def get_user_orders(user_id: int):
    """Return all orders for a user."""
    if user_id not in USERS:
        raise HTTPException(
            status_code=404,
            detail={"error": "User not found", "code": "USER_NOT_FOUND"},
        )
    return {
        "user_id": user_id,
        "orders": ORDERS.get(user_id, []),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
