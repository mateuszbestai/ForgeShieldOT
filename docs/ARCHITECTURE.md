# ForgeShield OT — Architecture

ForgeShield OT is a **defensive** OT/ICS cybersecurity console with an AI analyst
layer. It is a production-grade MVP that runs entirely on **simulated / demo data**:
it is passive-first and read-only with respect to the network — it never writes to
PLCs, changes firewalls, or performs active scanning, and the AI analyst is
advisory-only.

This document describes the system components, the backend/frontend package layout,
the background jobs, and the two principal data-flow paths (simulated passive
discovery and AI RAG).

---

## 1. System components

```
                              ┌───────────────────────────────────────────┐
                              │              Browser (SPA)                 │
                              │  React 18 + Vite + Tailwind + shadcn-style │
                              │  TanStack Query · React Flow · Recharts    │
                              └───────────────┬───────────────┬───────────┘
                  Supabase JS  (login)        │               │  Axios + Bearer JWT
                  ┌───────────────────────────┘               │  (Supabase access token)
                  ▼                                            ▼
        ┌──────────────────┐                       ┌──────────────────────────┐
        │  Supabase Cloud  │  HS256 JWT            │   FastAPI backend         │
        │  (Auth / users)  │  (app_metadata.role)  │   /api/* · /docs · /health│
        └──────────────────┘ ───────────────────► │                           │
                                  verify only      │  routers → services → ORM │
                                                   └───────┬───────────┬───────┘
                                                           │           │
                                       ┌───────────────────┘           └─────────────┐
                                       ▼                                             ▼
                              ┌──────────────────┐                          ┌──────────────────┐
                              │  PostgreSQL 16   │                          │     Redis 7      │
                              │ ~25 SQLModel     │                          │ rate-limit +     │
                              │ tables           │                          │ Celery broker    │
                              └──────────────────┘                          └────────┬─────────┘
                                                                                     │
                ┌──────────────────────────────┐                          ┌──────────▼─────────┐
                │  AI provider (OpenAI-compat)  │ ◄────────────────────────│ Celery worker+beat │
                │  Foundation-Sec-8B-Reasoning  │   advisory RAG calls     │ daily brief +      │
                │  (vLLM / TGI / Ollama) | mock │                          │ hourly risk recompute
                └──────────────────────────────┘                          └────────────────────┘
```

**Stack**

| Layer        | Technology |
|--------------|------------|
| Backend API  | FastAPI, SQLModel, Pydantic v2, `python-jose` (JWT verify), `httpx` |
| Database     | PostgreSQL 16 (SQLite is used by the backend test suite) |
| Cache/broker | Redis 7 (rate limiting + Celery broker/result backend) |
| Background   | Celery worker with embedded beat scheduler |
| Auth         | Supabase Cloud (frontend `@supabase/supabase-js`; backend **verifies** HS256 JWT) |
| AI           | Provider abstraction: `local_foundation_sec` (default) / `openai_compatible` / `mock` |
| Frontend     | React 18, Vite, TypeScript, Tailwind CSS, shadcn-style UI, TanStack Query, React Flow, Recharts |

The API exposes ~70 routes under the `/api` prefix; interactive OpenAPI/Swagger docs
are served at `http://localhost:8000/docs` (and the schema at `/openapi.json`).

---

## 2. Request flow

1. The SPA authenticates the user directly against **Supabase Cloud** via
   `@supabase/supabase-js` (`signInWithPassword`).
2. Every API request carries the Supabase-issued access token as a
   `Authorization: Bearer <jwt>` header (attached by an Axios request interceptor in
   `frontend/src/lib/api/client.ts`).
3. The FastAPI dependency `get_current_user` (`backend/app/core/security.py`)
   **verifies** the JWT signature (HS256 with `SUPABASE_JWT_SECRET`), reads the RBAC
   role from `app_metadata.role`, and JIT-provisions a local mirror `User` row for
   ownership FKs and audit.
4. Routers enforce RBAC via the `require_role(...)` dependency factory (ADMIN is
   always permitted) and delegate to **services**, which own all business logic and
   database access.
5. Errors are normalized by registered exception handlers into a consistent
   `{ "error": { "code", "message" } }` shape; a `401` causes the SPA to sign out and
   redirect to login.

The FastAPI app is constructed in `backend/app/main.py` (`create_app()`), which wires
CORS, the exception handlers, the aggregated API router, and two unauthenticated
health endpoints (`GET /` and `GET /health`).

---

## 3. Backend package layout

```
backend/app/
├── main.py                 # FastAPI app factory (CORS, routers, /health, /)
├── core/
│   ├── config.py           # Pydantic Settings (env / .env; no hardcoded secrets)
│   ├── enums.py            # Single source of truth for all enumerations
│   ├── security.py         # Supabase JWT verify, AuthenticatedUser, require_role, role groups
│   ├── rate_limit.py       # Redis fixed-window limiter (in-memory fallback) for /api/ai/chat
│   ├── db.py               # Engine, session dependency, init_db
│   ├── redis.py            # Redis client + health
│   ├── exceptions.py       # AppError hierarchy + FastAPI handlers
│   └── logging.py          # Structured logging setup
├── models/                 # ~25 SQLModel tables (see DATA_MODEL.md)
│   ├── base.py             # UUID / Timestamp / Demo mixins, utcnow, json_column
│   ├── org.py · user.py · asset.py · vuln.py · detection.py
│   ├── config_mgmt.py · compliance.py · incident.py
│   ├── report.py · integration.py · audit.py · ai.py
├── schemas/                # Pydantic request/response DTOs (asset, vuln, risk, ai, …)
├── api/
│   ├── router.py           # Aggregates all domain routers under /api
│   ├── deps.py             # Shared deps (get_or_404, re-exported auth/pagination)
│   └── routers/            # One module per domain (see API.md)
│       ├── auth · assets · sites · network_map · detections · vulnerabilities
│       ├── config_mgmt · compliance · incidents · reports · integrations
│       └── risk · ai · audit · ingestion
├── services/               # Business logic (no HTTP concerns)
│   ├── risk_engine.py      # Explainable additive risk model (see RISK_SCORING.md)
│   ├── asset_service · vuln_service · detection_service · compliance_service
│   ├── config_service · incident_service · integration_service · report_service
│   ├── audit_service · csv_io
│   └── discovery/          # Simulated passive-discovery pipeline
│       ├── pipeline.py     # ingest(): adapter → handlers → risk recompute → audit
│       ├── handlers.py     # NormalizedEvent → assets/protocols/relationships/detections
│       ├── protocol_registry.py
│       └── adapters/       # pcap_meta · network_obs · syslog · edr · firewall · manual
├── ai/                     # AI analyst layer (see AI_DESIGN.md)
│   ├── factory.py          # Provider selection from settings
│   ├── service.py          # Orchestration: retrieve → prompt → provider → validate → persist + audit
│   ├── retrieval.py        # Structured RAG over the app's own records
│   ├── schema.py           # AIAnswer contract + validate_answer (citation allow-listing)
│   ├── sanitize.py         # Prompt-injection neutralization for untrusted data
│   ├── system_prompt.py    # Persona + grounding/safety/injection/output rules
│   ├── prompts/builders.py # Per-use-case task instructions + message assembly
│   └── providers/          # base · openai_compatible · local_foundation_sec · mock
├── workers/
│   ├── celery_app.py       # Celery app + beat schedule
│   └── tasks.py            # generate_daily_brief, recompute_all_risk
└── seed/                   # Idempotent demo data (see SEED_SCENARIO.md)
    ├── loaders.py          # seed_all(): sites/zones/assets/vulns/detections/incidents/compliance/AI
    ├── supabase_users.py   # Provision 5 demo auth users via Supabase Admin API
    └── cli.py              # `python -m app.seed.cli`
```

**Design note:** models use explicit foreign-key columns and explicit `select()`
queries in services rather than ORM `Relationship()` objects. With ~25 interlinked
tables (several with multiple FKs to the same table, e.g.
`AssetRelationship.src/dst → Asset`) this keeps mapper configuration simple and
behavior predictable across PostgreSQL and the SQLite test database.

---

## 4. Frontend layout

```
frontend/src/
├── main.tsx · router.tsx        # App bootstrap + React Router routes
├── lib/
│   ├── supabase.ts              # Single Supabase client + getAccessToken()
│   ├── auth.tsx                 # AuthProvider/useAuth, canWrite() role helper
│   ├── api/client.ts            # Axios instance, Bearer interceptor, error normalization
│   ├── api/endpoints.ts         # Typed endpoint helpers
│   ├── queryClient.ts           # TanStack Query client
│   ├── riskBands.ts             # Band thresholds + color tokens (mirrors backend bands)
│   ├── siteStore.ts · theme.tsx · env.ts · format.ts · markdown.ts · utils.ts
├── components/
│   ├── layout/  (AppShell, Sidebar, TopBar, SiteSelector, DemoBanner, GlobalSearch)
│   ├── ui/      (shadcn-style primitives: button, card, dialog, table, …)
│   ├── common/  (DataTable, KpiCard, RiskBadge, SeverityBadge, StatusBadge, …)
│   ├── charts/  (Recharts: RiskTrend, BandDistribution, VulnExposure, AttckIcsCoverage, …)
│   ├── network/ (PurdueGraph — React Flow Purdue-level network map)
│   └── ai/      (ChatPanel, AnswerCard, AiActionCard)
└── pages/
    ├── Dashboard · NetworkMap · ChangeManagement · Reports · Integrations · Settings
    ├── AiAnalyst · Login · NotFound
    ├── assets/ · detections/ · vulns/ · compliance/ · incidents/
```

Routing (`frontend/src/router.tsx`): a `ProtectedRoute` gate redirects unauthenticated
users to `/login`; all application pages render inside `AppShell`. The route table maps
to Dashboard, Assets, Network Map, Detections, Vulnerabilities, Change Management,
Compliance, Incidents, Reports, Integrations, AI Analyst, and Settings.

UI write actions are role-gated client-side via `canWrite(role)` (ADMIN or
OT_SECURITY_ENGINEER); the **server** is the authoritative enforcement point.

---

## 5. Background jobs (Celery + beat)

The Celery app (`backend/app/workers/celery_app.py`) uses Redis as both broker and
result backend. Importing the module never connects to the broker, so it is safe even
when Redis is down. In Docker, a single `worker` service runs the worker **and** the
embedded beat scheduler (`celery ... worker --beat`).

| Beat schedule key             | Task                                   | Cadence              |
|-------------------------------|----------------------------------------|----------------------|
| `generate-daily-brief`        | `app.workers.tasks.generate_daily_brief` | Daily at 06:00 UTC   |
| `recompute-all-risk-hourly`   | `app.workers.tasks.recompute_all_risk`   | Top of every hour    |

- **`generate_daily_brief`** generates an `AI_DAILY_BRIEF` report via
  `report_service.generate`. It is resilient: `report_service` has a deterministic
  fallback brief if the AI provider is unavailable, and the task itself catches and
  reports errors rather than crashing.
- **`recompute_all_risk`** calls `risk_engine.recompute_all`, recomputing and
  persisting `risk_score` / `risk_band` for every asset.

Both tasks open their own database session and stand in a lightweight system user
(falling back to the seeded admin) for any ownership/audit references.

---

## 6. Data flow (a): simulated passive-discovery ingestion

Triggered by `POST /api/ingest/{source}` (write roles only) and orchestrated by
`services/discovery/pipeline.py:ingest`. **No live capture, scanning, or active
probing happens** — adapters parse already-supplied JSON metadata.

```
POST /api/ingest/{source}  (pcap_meta | network_obs | syslog | edr | firewall | manual)
        │  payload: lenient JSON metadata (size-guarded ≤ 2 MB)
        ▼
  SourceAdapter.parse(payload)  ──►  list[NormalizedEvent]
        │   (tolerant: skips malformed records rather than raising)
        ▼
  per event → handlers:
     • ASSET/COMM/REMOTE_ACCESS  → upsert_asset (match by IP→MAC→hostname, else create)
                                     ↳ new asset emits NEW_DEVICE_IN_ZONE (≤L2) / UNKNOWN_ASSET
                                   → record_protocol_observation (passive fingerprint)
                                   → upsert_relationship (classify EW_TO_PLC / REMOTE_ACCESS / COMM)
                                     ↳ new path is flagged is_unknown + emits a path detection
     • EDR_ALERT / USB_EVENT     → handle_edr_alert → MALWARE / USB_INSERTION / YARA / SUSPICIOUS_PROCESS
     • FIREWALL_EVENT            → handle_firewall_event → FIREWALL_EXPOSURE (only if it exposes OT)
        ▼
  collect set of affected asset_ids
        ▼
  risk_engine.score_asset(...)  for every affected asset  (persist new score/band)
        ▼
  record_audit(action=INGEST, meta=IngestSummary)
        ▼
  return IngestSummary { events_processed, assets_created/updated, detections_created,
                         protocols_recorded, relationships_recorded, notes }
```

Adapters are pluggable behind the `SourceAdapter` ABC. The same handler/risk-recompute
path runs regardless of source, so a real PCAP/syslog/EDR/firewall collector can be
added later by implementing `parse()` without touching the rest of the pipeline.
`SEED` has no live adapter (it is produced by the seed routine directly).

---

## 7. Data flow (b): AI RAG (retrieve → prompt → provider → validate → persist + audit)

Triggered by `POST /api/ai/chat` (authenticated, rate-limited per user) and
orchestrated by `ai/service.py:run_ai_query`.

```
POST /api/ai/chat { question, use_case, entity_id?, conversation_id? }
        │  (ai_rate_limiter dependency: 20/minute per user, Redis fixed-window)
        ▼
  retrieval.build_context(use_case, entity_id, question)
        │   • structured, deterministic RAG over the app's OWN records
        │   • each record → EvidenceRecord(ref, label, fields); free text sanitized
        │   • RetrievalContext.allowed_citations = {record.ref}   ← the allow-list
        ▼
  prompts.build_messages(context, question)
        │   • system prompt: persona + grounding + OT safety + injection defense + JSON contract
        │   • user message embeds context as ONE delimited <<UNTRUSTED_DATA … UNTRUSTED_DATA>> block
        ▼
  factory.get_provider().complete(messages, temperature, max_tokens)
        │   local_foundation_sec (default) | openai_compatible | mock
        │   (Foundation-Sec: requests JSON, strips <think> reasoning blocks)
        ▼
  schema.validate_answer(raw, allowed_citations)  →  AIAnswer
        │   • parse JSON (best-effort; falls back to Low-confidence summary)
        │   • DROP any citation not in the allow-list  ← anti-fabrication guarantee
        │   • force the safety disclaimer
        ▼
  persist AIConversation + user/assistant AIMessage (structured fields retained)
  record_audit(AI_PROMPT)  before  +  record_audit(AI_RESPONSE)  after
        ▼
  return AIChatResponse { summary, findings, citations, confidence,
                          assumptions, safe_ot_actions, disclaimer,
                          provider_name, model_name, latency_ms }
```

The AI never executes actions: it returns advice plus a forced disclaimer, citing only
allow-listed internal records, and every prompt/response is audit-logged. See
`AI_DESIGN.md` for full detail and `SECURITY.md` for the safety boundaries.

---

## 8. Docker Compose services

`docker compose up --build` (or `make up`) brings up the full local stack. Auth is
Supabase Cloud, so there is **no** Supabase container.

| Service    | Image / build              | Ports        | Purpose |
|------------|----------------------------|--------------|---------|
| `postgres` | `postgres:16-alpine`       | `5432`       | Primary database (volume `pgdata`, `initdb.sql` bootstrap) |
| `redis`    | `redis:7-alpine`           | `6379`       | Rate-limit store + Celery broker/result backend |
| `backend`  | `./backend`                | `8000`       | FastAPI API + `/docs`; entrypoint runs migrations and (optionally) seeds |
| `worker`   | `./backend`                | —            | `celery ... worker --beat` (daily brief + hourly risk recompute); `SEED_ON_START=false` |
| `frontend` | `./frontend`               | `5173`       | Vite dev server for the React SPA |
| `adminer`  | `adminer:4` (profile `tools`) | `8080`    | Optional DB UI (`docker compose --profile tools up adminer`) |

`postgres` and `redis` expose healthchecks; `backend` waits for both to be healthy,
and `worker`/`frontend` start after `backend`. Configuration is supplied via
environment variables (see `.env.example`); `SEED_ON_START=true` makes the backend
load idempotent demo data on startup.

Useful `make` targets: `up`, `down`, `reset` (wipe DB volume), `logs`, `migrate`,
`seed`, `test`, `lint`, `fmt`, `fe-test`, `shell`.
