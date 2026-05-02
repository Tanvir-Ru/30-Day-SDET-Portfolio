"""
Vulnerable test target for OWASP probe validation.

Contains intentional vulnerabilities matching OWASP Top-10:
  A01 - No access control on /admin
  A02 - Missing security headers, HTTP allowed
  A03 - SQL-like error messages on invalid input
  A05 - Swagger exposed, debug endpoint active
  A07 - No rate limiting, default admin/admin accepted
  A10 - /api/fetch with no SSRF protection

DO NOT deploy to production.

Run: uvicorn probe_suite.targets.vulnerable_app:app --port 8000
"""

import time
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import httpx

app = FastAPI(
    title="Vulnerable Test API",
    version="0.1.0",
    docs_url="/swagger-ui",         # A05: Swagger UI exposed
    openapi_url="/openapi.json",
)

# A05: CORS allows all origins
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "password": "secret123"},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com",   "password": "hunter2"},
}
SESSIONS: dict[str, int] = {}
LOGIN_ATTEMPTS: dict[str, int] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str   # A07: No strength enforcement


# A02: No security headers added anywhere

@app.get("/api/users")
def list_users():
    # A02: Returns passwords in response
    return {"users": list(USERS.values())}


@app.get("/api/users/{user_id}")
def get_user(user_id: str):
    # A03: Verbose SQL-like error on non-integer
    try:
        uid = int(user_id)
    except ValueError:
        # A05: Exposes internal error info
        raise HTTPException(500, detail={
            "error": f"SQLSTATE[22P02]: invalid input syntax for type integer: '{user_id}'",
            "query": f"SELECT * FROM users WHERE id = {user_id}",
        })
    user = USERS.get(uid)
    if not user:
        raise HTTPException(404, detail={"error": "User not found"})
    return user  # A02: Includes password field


@app.get("/admin")          # A01: No auth required
@app.get("/admin/users")
def admin_panel():
    return {"admin": True, "users": list(USERS.values()), "message": "Admin panel — no auth required"}


@app.post("/api/auth/login")
def login(body: LoginRequest):
    # A07: No rate limiting
    user = next((u for u in USERS.values() if u["name"].lower() == body.username.lower()), None)

    # A07: Different messages for valid vs invalid username (enumeration)
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=401)

    # A07: Accept default credentials
    if body.username == "admin" and body.password == "admin":
        return {"access_token": "fake-admin-token", "user_id": 0, "role": "admin"}

    if user["password"] == body.password:
        token = f"token-{user['id']}-{int(time.time())}"
        SESSIONS[token] = user["id"]
        return {"access_token": token, "user_id": user["id"]}

    return JSONResponse({"error": "Wrong password"}, status_code=401)   # A07: Enumeration via different message


@app.post("/api/auth/register", status_code=201)
def register(body: RegisterRequest):
    # A07: Accepts any password including "password", "123456"
    new_id = max(USERS.keys(), default=0) + 1
    USERS[new_id] = {"id": new_id, "name": body.username, "email": body.email, "password": body.password}
    return {"id": new_id, "username": body.username}


@app.get("/api/fetch")
def fetch_url(url: str = Query(...)):
    # A10: No SSRF protection at all
    try:
        resp = httpx.get(url, timeout=5, follow_redirects=True)
        return {"status": resp.status_code, "body": resp.text[:2000]}
    except Exception as e:
        return {"error": str(e)}


@app.get("/metrics")         # A05: Metrics exposed without auth
def metrics():
    return {"requests_total": 1234, "memory_mb": 256, "db_connections": 5}


@app.get("/debug")           # A05: Debug endpoint exposed
def debug():
    return {
        "env": {"DATABASE_URL": "postgresql://user:password@localhost/db"},   # A02: Creds in debug
        "config": {"SECRET_KEY": "super-secret-key-do-not-share"},
    }


@app.get("/health/detail")   # A05: Detailed health
def health_detail():
    return {"status": "ok", "db": "connected", "version": "uvicorn/0.27.0", "python": "3.11.4"}
