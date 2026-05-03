"""
Vulnerable GraphQL target for probe validation.

Built with Strawberry (Python GraphQL library).
Intentional vulnerabilities:
  - Introspection enabled (no production guard)
  - No query depth limit
  - No complexity analysis
  - Batching enabled with no size limit
  - Field suggestions enabled
  - Verbose error messages
  - No rate limiting on login mutation

Run:
    pip install strawberry-graphql[fastapi] uvicorn
    uvicorn gql_scanner.targets.vulnerable_gql:app --port 4000
"""

from __future__ import annotations

import time
from typing import Optional, List
from fastapi import FastAPI
import strawberry
from strawberry.fastapi import GraphQLRouter


# ── Types ─────────────────────────────────────────────────────────────────────

@strawberry.type
class User:
    id:       int
    name:     str
    email:    str
    password: str           # Intentionally exposed — A02
    role:     str

@strawberry.type
class Post:
    id:      int
    title:   str
    content: str
    author:  Optional["User"] = None

@strawberry.type
class LoginPayload:
    token:   str
    user_id: int

@strawberry.type
class CreateUserPayload:
    id:   int
    name: str


# ── Data store ────────────────────────────────────────────────────────────────

USERS = {
    1: User(id=1, name="Alice",  email="alice@example.com", password="secret123",  role="user"),
    2: User(id=2, name="Bob",    email="bob@example.com",   password="hunter2",    role="admin"),
    3: User(id=3, name="Charlie",email="charlie@example.com",password="password",  role="user"),
}

POSTS = {
    1: Post(id=1, title="Hello World", content="First post", author=USERS[1]),
    2: Post(id=2, title="GraphQL Tips", content="...", author=USERS[2]),
}


# ── Resolvers ─────────────────────────────────────────────────────────────────

@strawberry.type
class Query:
    @strawberry.field
    def users(self, filter: Optional[str] = None, id: Optional[str] = None) -> List[User]:
        """No SQL injection protection, no auth check."""
        if id:
            try:
                uid = int(id)
                user = USERS.get(uid)
                return [user] if user else []
            except ValueError:
                raise ValueError(
                    f"SQLSTATE[22P02]: invalid input syntax for type integer: '{id}' "
                    f"at /home/app/resolvers/user.py line 42"   # Verbose error
                )
        if filter:
            return [u for u in USERS.values() if filter.lower() in u.name.lower()]
        return list(USERS.values())

    @strawberry.field
    def user(self, id: int) -> Optional[User]:
        return USERS.get(id)

    @strawberry.field
    def posts(self) -> List[Post]:
        return list(POSTS.values())

    @strawberry.field
    def me(self) -> Optional[User]:
        return USERS[1]   # Always returns Alice (no auth)

    @strawberry.field
    def admin_users(self) -> List[User]:
        """No admin check — A01."""
        return [u for u in USERS.values() if u.role == "admin"]

    @strawberry.field
    def secret_config(self) -> str:
        """Sensitive data exposed — A02."""
        return "SECRET_KEY=super-secret-do-not-share DATABASE_URL=postgresql://admin:password@db/prod"


@strawberry.type
class Mutation:
    @strawberry.mutation
    def login(self, username: str, password: str) -> LoginPayload:
        """No rate limiting — A07."""
        user = next((u for u in USERS.values() if u.name.lower() == username.lower()), None)
        if not user:
            raise ValueError(f"User '{username}' not found")   # A07: Username enumeration
        if user.password == password:
            return LoginPayload(token=f"token-{user.id}-{int(time.time())}", user_id=user.id)
        raise ValueError("Wrong password")   # A07: Different error per condition

    @strawberry.mutation
    def create_user(self, name: str, email: str) -> CreateUserPayload:
        new_id = max(USERS.keys(), default=0) + 1
        USERS[new_id] = User(id=new_id, name=name, email=email, password="", role="user")
        return CreateUserPayload(id=new_id, name=name)


# ── App setup ─────────────────────────────────────────────────────────────────

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    # No depth limit, no complexity limit, introspection enabled (default)
)

graphql_router = GraphQLRouter(
    schema,
    graphql_ide="graphiql",     # A05: GraphiQL exposed
)

app = FastAPI(title="Vulnerable GraphQL API")
app.include_router(graphql_router, prefix="/graphql")


@app.get("/health")
def health():
    return {"status": "ok", "server": "strawberry/0.219.0", "python": "3.11"}
