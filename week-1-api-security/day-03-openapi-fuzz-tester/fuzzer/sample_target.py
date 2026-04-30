"""
Sample target API — used for local testing of the fuzz engine.

Contains intentional vulnerabilities to verify the fuzzer finds them:
  - /users/{user_id} — no input validation on user_id (SQL injection surface)
  - /search           — verbose error response exposes stack trace
  - /files            — path parameter used in file lookup (path traversal surface)
  - /echo             — reflects input back (XSS seed detection)

DO NOT deploy this to production. It is intentionally vulnerable for testing.

Run: uvicorn fuzzer.sample_target:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
import time

app = FastAPI(
    title="Sample Vulnerable API",
    version="1.0.0",
    description="Intentionally vulnerable test target for fuzz testing",
)

# In-memory store
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com",   "role": "admin"},
}

class CreateUserRequest(BaseModel):
    name:  str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")
    age:   Optional[int] = Field(None, ge=0, le=150)
    role:  Optional[str] = Field("user")

class SearchRequest(BaseModel):
    query:    str = Field(..., min_length=1)
    page:     int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)


@app.get("/users")
def list_users(page: int = Query(1, ge=1), per_page: int = Query(20, ge=1, le=100)):
    all_users = list(USERS.values())
    start = (page - 1) * per_page
    return {"users": all_users[start:start + per_page], "total": len(all_users)}


@app.get("/users/{user_id}")
def get_user(user_id: int):
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(404, detail={"error": "User not found", "code": "USER_NOT_FOUND"})
    return user


@app.post("/users", status_code=201)
def create_user(body: CreateUserRequest):
    new_id = max(USERS.keys(), default=0) + 1
    user = {"id": new_id, **body.model_dump()}
    USERS[new_id] = user
    return user


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int):
    if user_id not in USERS:
        raise HTTPException(404, detail={"error": "User not found"})
    del USERS[user_id]


@app.post("/search")
def search(body: SearchRequest):
    query = body.query.lower()
    results = [u for u in USERS.values() if query in u["name"].lower()]
    return {"results": results, "query": body.query, "count": len(results)}


@app.get("/echo")
def echo(message: str = Query(...)):
    """Echoes input — intentionally reflects content for XSS seed testing."""
    return {"message": message, "timestamp": time.time()}
