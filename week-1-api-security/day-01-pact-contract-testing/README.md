# Day 01 — Pact Contract Testing Suite

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A production-grade contract testing suite using [Pact](https://pact.io/) to prevent
breaking API changes in a microservices architecture. Demonstrates how to decouple
consumer and provider test cycles, manage schema evolution across versions, and block
unsafe deployments at the CI gate.

---

## The Problem This Solves

**Without contract testing**, this happens:

```
Team A renames /users/:id response field `id` → `user_id`
  → Order Service breaks in production
  → Nobody caught it because integration tests weren't running in CI
  → Hotfix deploy at 2am
```

**With Pact**, this gets caught the moment Team A opens a PR — before merge,
before deploy, before anything reaches staging.

---

## Architecture

```
┌─────────────────┐    publish contract    ┌─────────────────┐
│  Order Service  │ ──────────────────────▶│   Pact Broker   │
│  (Consumer)     │                        │  (Contract DB)  │
└─────────────────┘                        └────────┬────────┘
     pytest +                                       │ fetch contracts
     pact-python                                    ▼
     generates                             ┌─────────────────┐
     pact.json                             │  User Service   │
                                           │  (Provider)     │
                                           │  FastAPI        │
                                           └─────────────────┘
                                                verifies each
                                                interaction against
                                                real running API
```

### Three-phase CI pipeline

```
PR opened
    │
    ├── [consumer-tests]
    │     Run pytest consumer/tests/
    │     Generate pact.json
    │     Publish to Pact Broker with version=SHA
    │
    ├── [provider-verification]
    │     Download all contracts from broker
    │     Start FastAPI provider
    │     Replay each interaction → assert response matches contract
    │     Publish verification results
    │
    └── [can-i-deploy gate]           ← blocks merge if violated
          pact-broker can-i-deploy
          --pacticipant user-service
          --to-environment production
```

---

## File Structure

```
day-01-pact-contract-testing/
├── consumer/
│   ├── client.py                         # HTTP client for User Service
│   └── tests/
│       ├── conftest.py                   # Pact MockServer fixtures
│       ├── test_user_contract_v1.py      # v1 schema: id + name
│       └── test_user_contract_v2.py      # v2 schema: id + name + email
│
├── provider/
│   ├── app.py                            # FastAPI User Service
│   ├── provider_states.py                # State handlers (DB seeding)
│   └── tests/
│       └── test_provider_verification.py # Verifies all consumer contracts
│
├── scripts/
│   ├── publish_pacts.py                  # Publishes contracts to broker
│   └── can_i_deploy.py                   # Deployment safety gate
│
├── .github/workflows/
│   └── contract-tests.yml               # Full 3-stage CI pipeline
├── docker-compose.yml                   # Pact Broker + Postgres
└── pyproject.toml
```

---

## What Makes This Non-Trivial

### 1. Provider state handlers
Most Pact tutorials demo without state handlers. Here, every `given()` clause
in the consumer maps to a setup function in `provider/provider_states.py` that
seeds the database into the correct state before verification. Without this,
you're testing against whatever data happens to exist — not the scenario the
consumer assumed.

### 2. Multi-version contract compatibility
Both v1 (`id + name`) and v2 (`id + name + email`) consumer contracts are
registered in the broker. The provider must satisfy **both simultaneously**.
This is the real-world scenario: you have consumers at different upgrade stages.

### 3. `can-i-deploy` gate
The final CI step is not just "tests passed" — it's a formal query to the
Pact Broker: *"Given all currently deployed versions, is it safe to deploy
this version of user-service?"* This is the difference between contract testing
as a quality check and contract testing as a deployment safety net.

### 4. Error contract testing
The 404 and 401 responses are also contracted. If User Service changes its
error response shape (e.g., `error` → `message`), consumers that parse that
field break. Contracting error responses catches this category of breakage.

---

## Running Locally

**Prerequisites:** Docker, Python 3.11+, Poetry

```bash
# 1. Start the Pact Broker
docker-compose up -d pact-broker

# 2. Install dependencies
poetry install

# 3. Run consumer tests (generates pact.json)
poetry run pytest consumer/tests/ -v

# 4. Publish contracts to broker
poetry run python scripts/publish_pacts.py \
  --version 1.0.0 \
  --broker-url http://localhost:9292

# 5. Run provider verification
poetry run pytest provider/tests/ -v

# 6. Check can-i-deploy
poetry run python scripts/can_i_deploy.py \
  --service user-service \
  --version 1.0.0

# 7. View the Pact Broker UI
open http://localhost:9292
```

---

## Key Dependencies

| Package | Version | Purpose |
|---|---|---|
| `pact-python` | ^2.2 | Pact consumer + provider DSL |
| `fastapi` | ^0.110 | Provider API framework |
| `httpx` | ^0.27 | Consumer HTTP client |
| `pytest` | ^8.1 | Test runner |

---

## Recruiter Talking Points

- **Why Pact over integration tests?** Integration tests require both services
  running simultaneously, making them slow and fragile. Pact decouples the test
  cycle — consumer runs independently, provider verifies independently.

- **What's `can-i-deploy`?** A formal compatibility check against the broker's
  version matrix. It answers: "Will deploying this version break any currently
  deployed consumer?" No other testing strategy provides this guarantee.

- **What are provider state handlers?** Setup functions that seed the system
  under test into the exact state the consumer assumed when it wrote the contract.
  The missing piece in 90% of Pact tutorials.
