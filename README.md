# 🧪 30-Day Senior SDET Portfolio

> A structured, project-driven portfolio demonstrating mastery across API security testing, advanced UI automation, DevOps/CI infrastructure, and performance engineering — built to meet the bar at top-tier tech companies.

---

## 👤 About This Portfolio

This repository documents 30 consecutive days of production-grade SDET engineering work. Each day is a self-contained project with real code, architectural decisions, and a professional README.

Every project covers one or more of these senior competencies:

- **Systems thinking** — tests designed around *why* failures happen, not just whether tests pass
- **Security-first quality** — OWASP, JWT attacks, dependency auditing, secrets scanning
- **Infrastructure ownership** — Terraform, Docker, GitHub Actions, ephemeral environments
- **Observability integration** — traces, logs, metrics connected to test failures

```
Languages   : Python 3.11+ · TypeScript
Test Tools  : Playwright · PyTest · Pact · k6 · Requests
CI/CD       : GitHub Actions · Docker · Terraform
Observability: OpenTelemetry · Datadog/New Relic · Grafana
```

---

## 📅 30-Day Roadmap

| # | Title | Phase | Tools | Difficulty |
|---|-------|-------|-------|------------|
| 01 | [Contract Testing Suite with Pact](#day-01--contract-testing-suite-with-pact) | Foundations | Pact, FastAPI, PyTest | ⭐⭐⭐⭐ |
| 02 | [JWT / OAuth 2.0 Security Scanner](#day-02--jwt--oauth-20-security-scanner) | Foundations | PyTest, PyJWT, httpx | ⭐⭐⭐⭐ |
| 03 | [OpenAPI Fuzz Tester](#day-03--openapi-schema-driven-fuzz-tester) | Foundations | Schemathesis, PyTest | ⭐⭐⭐⭐ |
| 04 | [OWASP Top-10 Probe Suite](#day-04--automated-owasp-top-10-probe-suite) | Foundations | Requests, PyTest | ⭐⭐⭐⭐⭐ |
| 05 | [GraphQL Introspection Attack Detector](#day-05--graphql-introspection-attack-detector) | Foundations | GQL, PyTest | ⭐⭐⭐⭐ |
| 06 | [Data-Driven API Regression Harness](#day-06--data-driven-api-regression-harness) | Foundations | PyTest, Allure | ⭐⭐⭐ |
| 07 | [API Chaos & Latency Injection Layer](#day-07--api-chaos--latency-injection-layer) | Foundations | Toxiproxy, PyTest | ⭐⭐⭐⭐ |
| 08 | [Self-Healing Playwright Wrapper](#day-08--self-healing-playwright-wrapper) | Advanced UI | Playwright, TypeScript | ⭐⭐⭐⭐⭐ |
| 09 | [Visual Regression Pipeline](#day-09--visual-regression-pipeline) | Advanced UI | Playwright, Percy | ⭐⭐⭐⭐ |
| 10 | [Accessibility Audit Bot](#day-10--accessibility-audit-bot) | Advanced UI | Playwright, axe-core | ⭐⭐⭐⭐ |
| 11 | [Cross-Browser Matrix Runner](#day-11--cross-browser-matrix-runner) | Advanced UI | Playwright, BrowserStack | ⭐⭐⭐⭐ |
| 12 | [Network Intercept & Mock Layer](#day-12--playwright-network-intercept-layer) | Advanced UI | Playwright, TypeScript | ⭐⭐⭐⭐ |
| 13 | [Shadow DOM & Web Components Harness](#day-13--shadow-dom--web-components-harness) | Advanced UI | Playwright, TypeScript | ⭐⭐⭐⭐ |
| 14 | [Flakiness Scorer & Stability Tracker](#day-14--flakiness-scorer--stability-tracker) | Advanced UI | Playwright, TypeScript | ⭐⭐⭐⭐⭐ |
| 15 | [Ephemeral Docker Env GitHub Action](#day-15--ephemeral-docker-environment-github-action) | DevOps/CI | GitHub Actions, Docker | ⭐⭐⭐⭐⭐ |
| 16 | [Terraform Test Infrastructure Module](#day-16--terraform-disposable-test-infrastructure) | DevOps/CI | Terraform, AWS | ⭐⭐⭐⭐⭐ |
| 17 | [Parallel Test Sharding Orchestrator](#day-17--parallel-test-sharding-orchestrator) | DevOps/CI | GitHub Actions, PyTest | ⭐⭐⭐⭐ |
| 18 | [Secrets Scanning Pre-Commit Gate](#day-18--secrets-scanning-pre-commit-gate) | DevOps/CI | truffleHog, gitleaks | ⭐⭐⭐⭐ |
| 19 | [SBOM Generator & Vulnerability Gate](#day-19--sbom-generator--dependency-vulnerability-gate) | DevOps/CI | Syft, Grype, GitHub Actions | ⭐⭐⭐⭐ |
| 20 | [Containerised Test Environment](#day-20--containerised-test-environment) | DevOps/CI | Docker Compose, PyTest | ⭐⭐⭐⭐ |
| 21 | [Multi-Environment Promotion Gate](#day-21--multi-environment-promotion-gate) | DevOps/CI | GitHub Actions, PyTest | ⭐⭐⭐⭐⭐ |
| 22 | [Log-Driven Load Test Generator](#day-22--log-driven-load-test-generator) | Performance | Datadog API, k6, Python | ⭐⭐⭐⭐⭐ |
| 23 | [Distributed Load Test Stack](#day-23--distributed-load-test-stack) | Performance | k6, InfluxDB, Grafana | ⭐⭐⭐⭐⭐ |
| 24 | [SLA Breach Detector](#day-24--sla-breach-detector) | Performance | k6, Python, Alerting | ⭐⭐⭐⭐ |
| 25 | [Database Query Profiler](#day-25--database-query-profiler) | Performance | Python, pg_stat_statements | ⭐⭐⭐⭐ |
| 26 | [Memory Leak Detector](#day-26--memory-leak-detector-for-playwright) | Performance | Playwright, CDP, TypeScript | ⭐⭐⭐⭐⭐ |
| 27 | [Synthetic Monitoring Suite](#day-27--synthetic-monitoring-on-aws-lambda) | Performance | AWS Lambda, CloudWatch | ⭐⭐⭐⭐⭐ |
| 28 | [Trace-Driven Test Generator](#day-28--trace-driven-test-generator) | Performance | OpenTelemetry, Playwright | ⭐⭐⭐⭐⭐ |
| 29 | [Full Observability Stack Integration](#day-29--full-observability-stack-integration) | Performance | OTel, Jaeger, PyTest | ⭐⭐⭐⭐⭐ |
| 30 | [Quality Engineering Dashboard](#day-30--capstone-quality-engineering-dashboard) | Capstone | Python, React, All tools | ⭐⭐⭐⭐⭐ |

---

## 🗓 Week 1 — API Foundations & Security

> Build the base layer: contract safety, authentication attacks, and chaos. Every project in this week is deployable as a real quality gate in a microservices pipeline.

---

### Day 01 — Contract Testing Suite with Pact

**Theme:** Prevent breaking API changes in microservices before they reach production.

**The problem:** Team A renames a response field. Every downstream consumer breaks in production. Nobody caught it because integration tests weren't running against the real API. Pact makes this class of failure impossible.

**What it does:**
- Consumer (Order Service) records its expectations as a JSON contract file using a mock server
- Pact Broker stores and versions contracts across all consumer versions
- Provider (User Service, FastAPI) downloads and replays every interaction against the real API
- `can-i-deploy` gate blocks any deployment that would break a registered contract

**Key architecture decisions:**
- Provider state handlers seed the database into the exact scenario each interaction assumed — the detail most tutorials omit
- v1 and v2 consumer contracts are registered simultaneously; the provider must satisfy both
- Three-way verification: consumer expectations → provider behaviour → OpenAPI spec agreement

**Tools:** `pact-python`, FastAPI, PyTest, Docker Compose (Pact Broker + Postgres), GitHub Actions

**What impresses recruiters:** `can-i-deploy` — the formal deployment safety query against the compatibility matrix. This is contract testing as infrastructure, not just as a test suite.

```
day-01-pact-contract-testing/
├── consumer/tests/            # Records interactions with Like(), EachLike(), Term()
├── provider/provider_states.py  # DB seeding per interaction (the detail most skip)
├── scripts/can_i_deploy.py    # Deployment gate — exit 1 if contracts broken
└── .github/workflows/         # 3-stage CI: consumer → provider → can-i-deploy
```

---

### Day 02 — JWT / OAuth 2.0 Security Scanner

**Theme:** Automated probe suite for token-layer vulnerabilities across four attack categories.

**The problem:** JWT vulnerabilities are structural — they're in the token itself, independent of the API endpoint. Most QA engineers test endpoints; this project tests the trust mechanism underneath them.

**What it does:**
- Decodes JWT structure without signature verification (intentional: scanning, not authenticating)
- `algorithm_probe` — detects `alg=none` (CVSS 9.8), RS256→HS256 confusion, and `kid` SQL/path injection
- `expiry_probe` — missing `exp`, excessive lifetime, future `iat` (clock skew abuse)
- `scope_probe` — wildcard scopes, dangerous combinations, scope creep beyond expected set
- `replay_probe` — missing `jti`, unbound audience, absent issuer, no DPoP/mTLS binding
- Produces structured JSON reports with CWE IDs, CVSS scores, and remediation guidance

**Tools:** Python 3.11, PyJWT, httpx, PyTest

**What impresses recruiters:** The probe architecture — each attack category is isolated and independently extensible. The weighted risk score (CRITICAL=25pts) enables trend tracking across releases. CWE IDs make the output directly importable into security trackers.

```
scanner/
├── jwt_decoder.py       # Structural decode, no sig verification (by design)
├── scanner.py           # Orchestrator, risk score, CLI with exit codes
└── probes/
    ├── algorithm_probe.py  # alg=none, confusion attacks, kid injection
    ├── expiry_probe.py     # Lifetime, clock skew, missing exp
    ├── scope_probe.py      # Wildcard, privilege escalation, creep
    └── replay_probe.py     # jti, aud, iss, DPoP binding
```

---

### Day 03 — OpenAPI Schema-Driven Fuzz Tester

**Theme:** Auto-generate attack payloads from the OpenAPI spec itself — no manual test case writing.

**What it does:**
- Parses the OpenAPI 3.x spec and extracts every endpoint, parameter, and schema
- Generates mutation payloads: boundary values, type confusion, null injection, oversized strings, Unicode edge cases
- Sends each mutated request and asserts on response code, error shape, and latency
- Produces a coverage report showing which schema paths were exercised

**Tools:** Schemathesis, Hypothesis, PyTest, httpx

**What impresses recruiters:** The spec-driven approach means the test suite automatically expands when new endpoints are added — zero maintenance overhead for coverage growth.

---

### Day 04 — Automated OWASP Top-10 Probe Suite

**Theme:** Systematic probe of the ten most critical web application security risks.

**What it does:**
- SQL injection probes across all query parameters and request bodies
- Broken authentication: credential stuffing simulation, brute-force rate-limit bypass
- Security misconfiguration: exposed debug endpoints, verbose error messages, open CORS
- Sensitive data exposure: PII in responses, cleartext secrets in headers
- Each probe has a severity rating and links to the specific OWASP category

**Tools:** Requests, PyTest, custom assertion library

**What impresses recruiters:** OWASP coverage in a CI pipeline is rare outside dedicated security teams. Owning this as a QA engineer demonstrates security engineering breadth.

---

### Day 05 — GraphQL Introspection Attack Detector

**Theme:** GraphQL-specific security surface: introspection, batching, depth attacks, and rate limit bypass.

**What it does:**
- Introspection probe: checks whether schema is publicly exposed in production
- Depth/complexity attack: nested queries that exponentially amplify server cost
- Batching abuse: 100 queries in one request to bypass per-request rate limits
- Field suggestion oracle: uses GraphQL error messages to enumerate schema without introspection

**Tools:** `gql`, `graphql-core`, PyTest

**What impresses recruiters:** GraphQL attack surface is a blind spot in most QA plans. This demonstrates that you understand protocol-specific vulnerabilities, not just generic HTTP testing.

---

### Day 06 — Data-Driven API Regression Harness

**Theme:** Parameterised regression suite with professional reporting and response diff on failure.

**What it does:**
- Loads test cases from YAML/CSV fixtures — swap data sources without touching test code
- Runs full regression on every API endpoint after each deployment
- Allure report with request/response bodies, timing waterfall, and failure screenshots
- HTML diff on failure: shows exactly which fields changed between baseline and current response

**Tools:** PyTest, Allure, httpx, deepdiff

**What impresses recruiters:** The HTML diff on failure cuts debugging time dramatically. Showing you care about developer experience, not just pass/fail counts.

---

### Day 07 — API Chaos & Latency Injection Layer

**Theme:** Simulate network conditions and partial failures to verify consumer resilience.

**What it does:**
- Wraps requests through Toxiproxy to inject configurable latency, packet loss, and connection resets
- Tests timeout handling, retry logic, and circuit breaker behaviour in the consumer
- Validates that partial failures (provider returns 200 for some requests, 503 for others) are handled gracefully
- Generates a resilience scorecard: which failure modes caused consumer crashes vs. graceful degradation

**Tools:** Toxiproxy, PyTest, Docker Compose

**What impresses recruiters:** Testing failure handling is more valuable than testing the happy path. This project shows you think about production failure modes, not just functional correctness.

---

## 🗓 Week 2 — Advanced UI & Resilience

> Go beyond record-and-playback. Build Playwright infrastructure that handles real-world brittleness: flaky locators, third-party dependencies, visual regressions, and accessibility at scale.

---

### Day 08 — Self-Healing Playwright Wrapper

**Theme:** A locator strategy that survives UI refactors through an AI-assisted fallback chain.

**What it does:**
- Primary locator strategy: `data-testid` attributes (stable by design)
- Fallback chain: ARIA role → visible text → CSS selector → XPath
- If all fallbacks fail, sends the DOM snapshot to an LLM and asks it to propose a new selector
- Logs every healing event with old selector, new selector, and confidence score
- After 10+ healing events on the same element, files a GitHub issue automatically

**Tools:** Playwright, TypeScript, OpenAI API (fallback only)

**What impresses recruiters:** Self-healing selectors are discussed in theory; this is a working implementation. The automatic issue filing closes the loop — locator drift gets fixed at source.

---

### Day 09 — Visual Regression Pipeline

**Theme:** Pixel-level visual diff integrated into CI with configurable thresholds.

**What it does:**
- Captures baseline screenshots across all breakpoints (mobile, tablet, desktop)
- Compares on every PR with configurable per-region thresholds (header: 0%, body: 2%)
- Masks dynamic content (timestamps, avatars) before comparison to eliminate false positives
- Integrates with Percy/Argos for cross-browser visual history

**Tools:** Playwright, Percy (or Argos), TypeScript, GitHub Actions

**What impresses recruiters:** Dynamic content masking is the difference between a visual regression suite that works and one that floods Slack with false positives at 3am.

---

### Day 10 — Accessibility Audit Bot

**Theme:** Automated WCAG 2.2 AA compliance scanning with auto-filed issues.

**What it does:**
- Runs axe-core against every page in the sitemap
- Categorises violations by WCAG success criterion (1.1.1, 4.1.2, etc.)
- Generates a prioritised remediation report with element selectors and fix guidance
- Automatically files GitHub issues for CRITICAL violations (tagged `accessibility`, `P1`)
- Tracks violation count trend over time to measure accessibility debt paydown

**Tools:** Playwright, axe-core, TypeScript, GitHub API

**What impresses recruiters:** Auto-filing issues bridges the gap between finding and fixing. Showing trend tracking demonstrates you understand accessibility as a quality metric, not a one-time audit.

---

### Day 11 — Cross-Browser Matrix Runner

**Theme:** Multi-browser test execution with adaptive retry logic and failure analysis.

**What it does:**
- Matrix execution across Chrome, Firefox, Safari, Edge on Windows and macOS
- Adaptive retry: failed tests retry with screenshot capture and network trace recording
- Failure classification: browser-specific vs. common failures isolated automatically
- Generates a browser compatibility matrix report showing which tests are consistently unstable on specific browsers

**Tools:** Playwright, BrowserStack, TypeScript, GitHub Actions

**What impresses recruiters:** Browser compatibility testing without false confidence. The failure classification proves you understand that a failure on Safari only is a different problem from a failure everywhere.

---

### Day 12 — Playwright Network Intercept Layer

**Theme:** Decouple UI tests from third-party services through a structured mock layer.

**What it does:**
- Intercepts all outbound requests and classifies them: first-party API, analytics, CDN, payment provider
- Allows per-test override of any intercepted route with fixture responses
- Records real traffic in a passthrough mode to generate mock fixtures automatically
- Validates that the application correctly handles third-party failure (Stripe timeout, analytics 503)

**Tools:** Playwright, TypeScript, HAR file parsing

**What impresses recruiters:** Tests that break because Stripe's sandbox is down are useless. This project demonstrates the architectural thinking to isolate what you're actually testing.

---

### Day 13 — Shadow DOM & Web Components Harness

**Theme:** Test automation for modern component-based UIs that break standard selectors.

**What it does:**
- Custom `pierceSelector()` utility that traverses shadow DOM boundaries automatically
- Test harness for Lit, Stencil, and native Web Component patterns
- Slot content testing: verifies that projected content renders correctly inside components
- Isolation testing: confirms component state does not leak across instances

**Tools:** Playwright, TypeScript

**What impresses recruiters:** Shadow DOM is the fastest-growing blind spot in UI test coverage. Most frameworks can't handle it. A working harness here demonstrates deep browser internals knowledge.

---

### Day 14 — Flakiness Scorer & Stability Tracker

**Theme:** Quantify test reliability and automatically quarantine chronic flakers.

**What it does:**
- Runs every test 50 times and records pass/fail/timing across all runs
- Computes a stability score: `(pass_count / total_runs) × (1 - timing_variance)`
- Tests below threshold (< 90% stability) are automatically tagged `@flaky` and moved to quarantine suite
- Root cause categorisation: timing dependency, state leak, selector brittleness, network flakiness
- Generates a weekly flakiness report for engineering leadership

**Tools:** Playwright, TypeScript, GitHub Actions, JSON report aggregation

**What impresses recruiters:** Flakiness measurement is the first step to a healthy test suite. Most teams tolerate flaky tests indefinitely; this project provides the tooling to systematically eliminate them.

---

## 🗓 Week 3 — DevOps, CI/CD & Infrastructure

> Own the pipeline, not just the tests. Build the infrastructure that makes testing fast, isolated, secure, and deployable anywhere.

---

### Day 15 — Ephemeral Docker Environment GitHub Action

**Theme:** Spin up a full application stack per PR, run tests, and tear everything down on merge.

**What it does:**
- Composite GitHub Action that builds Docker images for all services in the stack
- Launches the stack with Docker Compose, waits for health checks on all services
- Runs the full test suite (API + UI + contract) against the isolated environment
- Tears down all containers and networks on workflow completion (success or failure)
- Posts a comment on the PR with environment URL, test results, and coverage delta

**Tools:** GitHub Actions, Docker Compose, bash, PR comment API

**What impresses recruiters:** Ephemeral environments eliminate "works on my machine" and "shared staging is broken again". This is table stakes infrastructure at companies that deploy dozens of times per day.

---

### Day 16 — Terraform Disposable Test Infrastructure

**Theme:** Infrastructure-as-code for on-demand test environments on AWS.

**What it does:**
- Terraform module that provisions: VPC, ECS cluster, RDS Postgres, ElastiCache, ALB
- Environment tagged with PR number and TTL — auto-destruction after 4 hours via Lambda
- Outputs environment URL, database connection string, and API keys to GitHub Actions secrets
- Module is parameterised: dev/staging/prod use the same module with different variable files

**Tools:** Terraform, AWS (ECS, RDS, ElastiCache, Lambda), GitHub Actions

**What impresses recruiters:** Writing Terraform for test infrastructure demonstrates you can operate at the platform level. Most SDETs can write tests; few can provision the infrastructure that runs them.

---

### Day 17 — Parallel Test Sharding Orchestrator

**Theme:** Distribute tests across workers dynamically to minimise total CI time.

**What it does:**
- Analyses test history to estimate each test's average duration
- Distributes tests across N workers to achieve equal completion time (bin-packing algorithm)
- Handles worker failure: incomplete shards are redistributed to healthy workers
- Merges coverage reports from all workers into a single unified report
- Calculates optimal shard count based on current test suite size and target CI time

**Tools:** GitHub Actions matrix strategy, PyTest, coverage.py, Python bin-packing

**What impresses recruiters:** Naive sharding (alphabetical split) leaves fast workers idle while slow workers are still running. Duration-aware sharding demonstrates algorithmic thinking applied to CI efficiency.

---

### Day 18 — Secrets Scanning Pre-Commit Gate

**Theme:** Block secrets from reaching the repository before they're committed.

**What it does:**
- Pre-commit hook using truffleHog and gitleaks to scan staged changes
- Custom pattern library for internal secret formats (API key prefixes, service account patterns)
- CI gate that rescans the full repository history on every PR (catches secrets added in amended commits)
- Audit log of all detected secrets with file path, line number, and entropy score
- Integration with GitHub Advanced Security for organisation-wide enforcement

**Tools:** truffleHog, gitleaks, pre-commit framework, GitHub Actions

**What impresses recruiters:** Secrets in git history are a persistent, undeletable vulnerability. Preventing them at commit time is engineering discipline. Rescanning history in CI catches the 20% that pre-commit misses.

---

### Day 19 — SBOM Generator & Dependency Vulnerability Gate

**Theme:** Generate a Software Bill of Materials and block deployments with known CVEs.

**What it does:**
- Generates SBOM in CycloneDX format for every Docker image produced in CI
- Scans SBOM with Grype against the NVD and OSV vulnerability databases
- Blocks deployment if any CRITICAL CVE is found in a direct dependency
- Publishes SBOM to GitHub Releases as an attestation artifact
- Weekly scheduled scan re-checks existing SBOMs against newly published CVEs

**Tools:** Syft (SBOM generation), Grype (vulnerability scanning), GitHub Actions, Docker

**What impresses recruiters:** SBOM generation is now required for US federal software supply chain compliance (EO 14028). Implementing it as a CI gate demonstrates awareness of the regulatory and security landscape.

---

### Day 20 — Containerised Test Environment

**Theme:** Fully reproducible test environment with Docker Compose and deterministic health checks.

**What it does:**
- Docker Compose stack: application, test database, mock third-party services (WireMock), message broker
- Custom health check orchestration: tests only start after all services pass their health probes
- Seed data management: deterministic dataset applied before each test run via init containers
- Network isolation: test traffic cannot reach production endpoints

**Tools:** Docker Compose, WireMock, PyTest, bash

**What impresses recruiters:** Deterministic test environments are rarer than they should be. Demonstrating seed data management and network isolation shows production-grade operational thinking.

---

### Day 21 — Multi-Environment Promotion Gate

**Theme:** Automated smoke suite that blocks promotion from staging to production.

**What it does:**
- Environment-aware test suite: same tests, different base URLs and data fixtures per environment
- Smoke gate runs on every push to `staging` and `main` branches
- Promotion blocked if: any critical path fails, p95 latency exceeds SLA, or error rate exceeds 0.1%
- Rollback trigger: posts a webhook to the deployment platform if the gate fails after deployment
- Parallel health checks across all microservices in the stack

**Tools:** GitHub Actions, PyTest, httpx, deployment platform webhooks

**What impresses recruiters:** A gate that blocks promotion AND triggers rollback is a complete deployment safety loop. This is the difference between a quality gate and a quality net.

---

## 🗓 Week 4 — Performance Engineering & Observability

> Connect testing to production signals. Build tools that generate tests from real traffic, measure SLA compliance under load, and correlate test failures to distributed traces.

---

### Day 22 — Log-Driven Load Test Generator

**Theme:** Parse production observability data to automatically generate targeted load tests.

**What it does:**
- Queries Datadog/New Relic API for the slowest 20 endpoints by p95 response time
- Generates a k6 load test script for each endpoint with realistic request patterns
- Configures load levels based on production traffic volume (p50, p95, p99 RPS from logs)
- Produces a prioritised test brief: which endpoints have the worst latency/traffic combination

**Tools:** Datadog API (or New Relic), k6, Python, jinja2 (script templating)

**What impresses recruiters:** Generating tests from production data means you're testing the right things at the right scale. This closes the gap between synthetic load tests and real-world behaviour.

---

### Day 23 — Distributed Load Test Stack

**Theme:** k6 load test with real-time dashboards and multi-region execution.

**What it does:**
- k6 load test with realistic user journey scenarios (login → browse → checkout)
- Metrics streamed to InfluxDB in real time
- Grafana dashboard: RPS, p50/p95/p99 latency, error rate, active VUs over time
- Multi-region execution from AWS Lambda@Edge (3 regions simultaneously)
- Automatic comparison report: baseline vs. this run, delta on all key metrics

**Tools:** k6, InfluxDB, Grafana, Docker Compose, AWS Lambda

**What impresses recruiters:** Real-time dashboards turn load testing from a batch job into an observable experiment. Multi-region execution detects geographic latency asymmetries.

---

### Day 24 — SLA Breach Detector

**Theme:** Real-time alerting when latency thresholds are breached during a load run.

**What it does:**
- Monitors p95 and p99 latency in real time during load test execution
- Configurable SLA thresholds per endpoint category (read: 200ms, write: 500ms, checkout: 1000ms)
- Fires Slack/PagerDuty alert the moment a threshold is exceeded — not after the run
- Attaches a flame graph snapshot at the moment of breach
- Generates a breach report: which thresholds, when, at what load level, for how long

**Tools:** k6, Python, Slack API, PagerDuty API, Grafana

**What impresses recruiters:** Catching a breach during a test run allows immediate investigation while the load is still active. Post-run detection loses the window for live debugging.

---

### Day 25 — Database Query Profiler

**Theme:** Correlate slow database queries to API response spikes.

**What it does:**
- Instruments the application to log query execution times via `pg_stat_statements`
- Correlates slow queries to the API endpoints that triggered them during load tests
- Detects N+1 query patterns automatically (query count grows linearly with data volume)
- Generates an optimisation report: slowest queries, missing indexes, and suggested fixes

**Tools:** Python, PostgreSQL (`pg_stat_statements`), sqlparse, PyTest

**What impresses recruiters:** N+1 query detection demonstrates understanding of the database layer beneath the API. Most QA engineers test the HTTP layer; this tests the full stack.

---

### Day 26 — Memory Leak Detector for Playwright

**Theme:** Detect JavaScript memory leaks in long-running UI test sessions using Chrome DevTools Protocol.

**What it does:**
- Attaches to Chrome via CDP to capture heap snapshots at intervals
- Runs a user journey 100 times and tracks heap growth across iterations
- Classifies growth: linear (likely leak) vs. plateau (GC operating correctly)
- Generates a retained objects report: which object types are accumulating
- Compares heap snapshots to identify leak source (detached DOM nodes, event listener accumulation)

**Tools:** Playwright, TypeScript, Chrome DevTools Protocol, `@playwright/test`

**What impresses recruiters:** Memory leak detection via heap snapshots is performance engineering at the browser layer. Very few QA engineers operate at this level.

---

### Day 27 — Synthetic Monitoring on AWS Lambda

**Theme:** Continuously running health checks deployed as serverless functions with alerting.

**What it does:**
- Critical user journeys packaged as Lambda functions (login, search, checkout)
- Runs every 5 minutes from 3 AWS regions
- CloudWatch alarm fires when any journey fails or exceeds latency threshold
- Structured logs in JSON for cross-region aggregation and dashboard display
- On-call rotation integration: routes alerts to PagerDuty based on service ownership

**Tools:** AWS Lambda, CloudWatch, Playwright (headless), Terraform, PagerDuty

**What impresses recruiters:** Synthetic monitoring is the first line of defence against production regressions between deployments. Owning the deployment as Terraform + Lambda demonstrates full-stack operational capability.

---

### Day 28 — Trace-Driven Test Generator

**Theme:** Convert production OpenTelemetry traces into executable Playwright test scripts.

**What it does:**
- Reads distributed traces from Jaeger/Tempo
- Extracts the sequence of HTTP requests that constitute a user journey
- Generates a Playwright test script that replays the exact sequence with parameterised assertions
- Identifies gaps in existing test coverage by comparing trace patterns to existing test inventory

**Tools:** OpenTelemetry, Jaeger, Playwright, TypeScript, Python (trace parsing)

**What impresses recruiters:** Generating tests from real traces guarantees you're testing actual usage patterns. This is the most rigorous form of test coverage — grounded in what users actually do.

---

### Day 29 — Full Observability Stack Integration

**Theme:** Correlate test failures directly to distributed traces, logs, and metrics.

**What it does:**
- Instruments the test runner to emit OpenTelemetry spans for every test case
- On failure, automatically attaches the distributed trace ID from the application under test
- Correlates test failure timestamp to logs and metrics from that exact time window
- Generates a failure report linking: test name → trace → slow span → error log → metrics anomaly

**Tools:** OpenTelemetry, Jaeger, Grafana, Python, PyTest plugin

**What impresses recruiters:** Connecting test failures to distributed traces collapses the MTTR for production incidents. This is observability-driven quality engineering.

---

### Day 30 — Capstone: Quality Engineering Dashboard

**Theme:** A single dashboard aggregating metrics from all 29 previous projects.

**What it does:**
- Pulls data from all project outputs: contract compatibility matrices, security scan risk scores, flakiness scores, load test p99s, accessibility violation trends
- Renders a unified quality posture view: green/amber/red per dimension
- Trend charts: 30-day history for each quality signal
- Executive summary export: one-page PDF with key metrics and risk areas
- Live demo mode: runs a subset of each project's test suite on demand

**Tools:** Python (FastAPI backend), React (dashboard frontend), all tools from Days 01–29

**What impresses recruiters:** The capstone proves this is a coherent system, not 30 disconnected scripts. A recruiter who opens your profile and sees one artifact that links to everything else gets the full picture in under 30 seconds.

```
day-30-quality-dashboard/
├── backend/              # FastAPI — aggregates metrics from all projects
├── frontend/             # React dashboard — quality posture at a glance
├── connectors/           # One connector per project, standardised interface
└── README.md             # The portfolio story told through data
```

---

## 🛠 Tech Stack Reference

| Category | Tools |
|---|---|
| Test frameworks | PyTest, Playwright (`@playwright/test`) |
| API testing | httpx, Requests, Pact, Schemathesis |
| Security | pyjwt, truffleHog, gitleaks, Grype, Syft |
| Performance | k6, InfluxDB, Grafana, Toxiproxy |
| CI/CD | GitHub Actions, Docker, Docker Compose |
| Infrastructure | Terraform, AWS (ECS, Lambda, RDS, CloudWatch) |
| Observability | OpenTelemetry, Jaeger, Datadog/New Relic |
| UI | Playwright, axe-core, Percy/Argos |
| Languages | Python 3.11+, TypeScript 5+ |

---

## 📁 Repository Structure

```
30-day-sdet-portfolio/
│
├── README.md                                   ← You are here
│
├── week-1-api-security/
│   ├── day-01-pact-contract-testing/
│   ├── day-02-jwt-oauth-security-scanner/
│   ├── day-03-openapi-fuzz-tester/
│   ├── day-04-owasp-probe-suite/
│   ├── day-05-graphql-attack-detector/
│   ├── day-06-api-regression-harness/
│   └── day-07-api-chaos-layer/
│
├── week-2-advanced-ui/
│   ├── day-08-self-healing-playwright/
│   ├── day-09-visual-regression-pipeline/
│   ├── day-10-accessibility-audit-bot/
│   ├── day-11-cross-browser-matrix/
│   ├── day-12-network-intercept-layer/
│   ├── day-13-shadow-dom-harness/
│   └── day-14-flakiness-scorer/
│
├── week-3-devops-ci/
│   ├── day-15-ephemeral-docker-action/
│   ├── day-16-terraform-test-infra/
│   ├── day-17-parallel-sharding/
│   ├── day-18-secrets-scanning-gate/
│   ├── day-19-sbom-vulnerability-gate/
│   ├── day-20-containerised-test-env/
│   └── day-21-promotion-gate/
│
├── week-4-performance/
│   ├── day-22-log-driven-load-generator/
│   ├── day-23-distributed-load-stack/
│   ├── day-24-sla-breach-detector/
│   ├── day-25-db-query-profiler/
│   ├── day-26-memory-leak-detector/
│   ├── day-27-synthetic-monitoring/
│   ├── day-28-trace-driven-test-gen/
│   └── day-29-observability-integration/
│
└── day-30-quality-dashboard/                  ← Capstone: all signals in one view
```

---

## 🎯 Competency Map

Each project maps to one or more Senior SDET competencies. Colour-coded for quick reference.

| Competency | Days |
|---|---|
| API contract safety | 01, 06, 21 |
| Security engineering | 02, 03, 04, 05, 18, 19 |
| Chaos & resilience | 07, 12, 20 |
| UI automation architecture | 08, 09, 11, 12, 13 |
| Accessibility | 10 |
| Test reliability | 14, 17 |
| CI/CD infrastructure | 15, 16, 17, 18, 19, 20, 21 |
| Infrastructure as code | 16, 27 |
| Performance engineering | 22, 23, 24, 25 |
| Browser internals | 08, 13, 26 |
| Observability | 22, 27, 28, 29, 30 |
| Full-stack integration | 25, 28, 29, 30 |

---

## 🚀 Getting Started

Each project is self-contained. Clone the repo and navigate to any day:

```bash
git clone https://github.com/yourusername/30-day-sdet-portfolio.git
cd 30-day-sdet-portfolio/week-1-api-security/day-01-pact-contract-testing

# Install dependencies (Poetry)
poetry install

# Or pip
pip install -r requirements.txt

# Run that day's tests
pytest -v
# or
npx playwright test
```

**Prerequisites:**
- Python 3.11+
- Node.js 20+ (for TypeScript/Playwright days)
- Docker Desktop (for days requiring containers)
- AWS CLI configured (for Days 16, 27)
- Terraform 1.6+ (for Day 16)

---

## 📖 Daily README Format

Every project README follows the same structure to make evaluation fast:

```
1. The Problem This Solves    ← Real incident or failure mode, not theory
2. Architecture               ← Decisions and the reasoning behind them
3. File Structure             ← What lives where and why
4. What Makes This Non-Trivial ← The 20% that separates senior from mid-level
5. Running Locally            ← Copy-paste commands, no surprises
6. Recruiter Talking Points   ← Why this matters in production
```

---

## 📊 Portfolio Metrics

| Metric | Value |
|---|---|
| Total projects | 30 |
| Languages | Python, TypeScript |
| Test frameworks used | 8 |
| CI/CD workflows | 15+ |
| Security vulnerability classes covered | 12 |
| AWS services used | 6 |
| Lines of test code | ~8,000+ |

---

## 💬 Contact

Built by a QA Engineer targeting Senior SDET roles at top-tier tech companies.

If you're a recruiter or hiring manager reviewing this portfolio, every project is designed to demonstrate not just technical proficiency, but the engineering judgment that separates senior engineers from mid-level ones: choosing the right tool, understanding why a technique matters in production, and building systems rather than scripts.

---

*Built over 30 consecutive days. Each project ships with production-ready code, not toy examples.*
