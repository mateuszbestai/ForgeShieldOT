# ForgeShield OT — Security

ForgeShield OT is a **defensive** OT/ICS console. Its security posture is built around a
core principle: **it is passive and read-only with respect to operational technology**.
It does not generate offensive content, does not touch real networks or controllers, and
its AI layer is advisory-only. This document covers the threat model, authentication /
authorization, input and upload validation, rate limiting, the no-secrets policy, and an
explicit list of capabilities that are **intentionally not implemented**.

> This is an MVP running on **simulated / demo data**; all risky operations are mocked
> and labeled as demo (`is_demo` flag on records, demo banners in the UI, `demo_data:
> true` in `/health`).

---

## 1. Threat model

**Assets to protect.** OT asset inventory and posture data, vulnerability/detection/
incident records, compliance evidence, audit trail, AI conversations, and the Supabase
credentials/JWT secret.

**Trust boundaries.**

```
 Browser (untrusted)  ──TLS──►  Supabase Cloud (auth)        [issues JWT]
 Browser (untrusted)  ──TLS──►  FastAPI backend  [verifies JWT, RBAC, validates input]
 Backend (trusted)    ──────►  PostgreSQL / Redis            [internal]
 Backend (trusted)    ──────►  AI inference endpoint         [advisory; output treated as untrusted]
 Ingested metadata / record free-text  ──────►  treated as UNTRUSTED everywhere it reaches the AI
```

**Threats considered & mitigations.**

| Threat | Mitigation |
|--------|------------|
| Forged / tampered tokens | Backend verifies the Supabase HS256 JWT signature, audience, and (when configured) issuer; rejects on any failure. |
| Privilege escalation | RBAC from `app_metadata.role`; write endpoints gated by `require_role(...)`; server is the authoritative enforcement point (UI gating is convenience only). |
| Prompt injection via record text / uploads | Delimited untrusted-data block + sanitizer + citation allow-listing + JSON validation (see `AI_DESIGN.md`). |
| AI fabricating records / actions | Citations restricted to a retrieval allow-list; forced disclaimer; AI cannot execute anything. |
| Abuse / DoS of the AI endpoint | Per-user fixed-window rate limit on `/api/ai/chat`. |
| Oversized / malformed ingestion or import payloads | Size guards and tolerant parsing (skip-not-crash). |
| Secret leakage | No secrets in code or VCS; `.env` gitignored; `.env.example` holds placeholders; service key used only server-side; only `VITE_`-prefixed vars reach the browser. |
| Stale/abandoned sessions | `401` triggers client sign-out + redirect to login; `last_login` recorded; all auth checks audited (`LOGIN`). |

---

## 2. RBAC + Supabase JWT verification

**Authentication is owned by Supabase Cloud.** The backend never issues tokens or stores
passwords — it only **verifies** the Supabase-issued access token.
(`backend/app/core/security.py`.)

- The SPA logs in via `@supabase/supabase-js` (`signInWithPassword`) and attaches the
  access token to every request as `Authorization: Bearer <jwt>`.
- `_decode_token` verifies the JWT using **HS256** with `SUPABASE_JWT_SECRET`, checks the
  audience (`SUPABASE_JWT_AUD`, default `authenticated`), and enforces the issuer
  (`<SUPABASE_URL>/auth/v1`) when a Supabase project is configured. Invalid/expired
  tokens raise an `AuthenticationError` (401).
- `get_current_user` reads the RBAC role from `app_metadata.role` (falling back to a
  top-level `role` claim, else `VIEWER`) and **JIT-provisions** a local mirror `User`
  row keyed on the `sub` claim, syncing role/email. The local row backs ownership FKs
  and audit.

**Roles** (`RoleName`): `ADMIN`, `OT_SECURITY_ENGINEER`, `SOC_ANALYST`,
`COMPLIANCE_OFFICER`, `VIEWER`. `require_role(*allowed)` enforces membership; **ADMIN is
always permitted**. Convenience groups:

| Group | Roles | Used by (write/mutating endpoints) |
|-------|-------|------------------------------------|
| `WRITE_OPERATIONS` | ADMIN, OT_SECURITY_ENGINEER | assets, vulnerabilities, config/change, reports, integrations, risk recompute, ingestion |
| `SOC_OPERATIONS` | ADMIN, OT_SECURITY_ENGINEER, SOC_ANALYST | detection status/evidence, incident create/update/timeline/AI |
| `COMPLIANCE_OPERATIONS` | ADMIN, COMPLIANCE_OFFICER | control status, evidence upload, AI gap, auto-link |

Read endpoints require a valid authenticated user (`get_current_user`) but no specific
role. The frontend uses `canWrite(role)` (ADMIN / OT_SECURITY_ENGINEER) to hide write
actions, but this is purely cosmetic — authorization is enforced server-side.

**`AUTH_DEV_BYPASS`** (development only): when `AUTH_DEV_BYPASS=true` **and**
`ENVIRONMENT=development`, the backend also accepts locally-minted HS256 tokens signed
with `SUPABASE_JWT_SECRET` (issuer not enforced). This is for tests/CI. It is **ignored
in production** and must never be enabled there.

---

## 3. Input / file-upload validation

- **Schema validation.** All request bodies are Pydantic models (e.g. `AIChatRequest`
  caps `question` at 2000 chars); unknown sources/enums are rejected with a clear
  `ValidationAppError`.
- **Ingestion payloads.** `POST /api/ingest/{source}` enforces an unknown-source check,
  an adapter-availability check, and a raw-body **size guard (~2 MB of JSON)**. Adapters
  parse **tolerantly** — a single malformed record is skipped, never aborts ingestion —
  and perform **no live capture/scanning**.
- **Uploads / imports.** CSV asset import and config import are parsed server-side; a
  global `MAX_UPLOAD_BYTES` (5 MB default) bounds upload size. Compliance evidence stores
  **metadata only** (`file_name` / `file_note`) — **no raw file bytes** are persisted in
  the MVP.
- **Untrusted free-text** (asset notes, `compliance_tags`, detection evidence `data`,
  config diffs, etc.) is treated as untrusted and **sanitized** before it can reach the
  AI (see `AI_DESIGN.md` §4).
- **Error normalization.** Exceptions are mapped to a consistent
  `{ "error": { "code", "message" } }` shape; a `401` causes the SPA to sign out.

---

## 4. Rate limiting

`POST /api/ai/chat` is rate-limited per user via the `ai_rate_limiter` dependency
(`core/rate_limit.py`): a **fixed-window** counter (default `AI_RATE_LIMIT=20/minute`)
backed by Redis (shared across replicas), with an **in-memory fallback** if Redis is
unavailable. Exceeding the limit returns **HTTP 429**.

---

## 5. No-secrets policy

- **No hardcoded secrets.** All configuration loads from the environment / `.env`
  (`core/config.py`, Pydantic Settings). Defaults present in code are non-production
  development placeholders (e.g. `SUPABASE_JWT_SECRET=dev-insecure-jwt-secret-change-me`).
- **`.env` is gitignored** (`.gitignore` ignores `.env`, `.env.*`, `*.pem`, `*.key`) and
  **`.env.example`** ships only **placeholders** (`YOUR-SUPABASE-…`, etc.) for operators
  to copy.
- **Service-role key** (`SUPABASE_SERVICE_KEY`) is used **only** by the backend seed
  script to provision demo auth users — never exposed to the browser.
- **Frontend exposure.** Only `VITE_`-prefixed variables are bundled into the SPA (the
  Supabase URL + anon key, which are browser-safe). The service key and JWT secret are
  never sent to the client.
- **Integration config** stores **non-secret** values only (endpoints/labels); the model
  comment explicitly forbids storing credentials, and all connectors are mock
  (`is_mock = true`).
- **Audit trail** captures actor, action, entity, and summary for sensitive operations
  (login, asset/vuln/detection/incident/compliance changes, AI prompt/response, report
  generation, integration import/export, ingestion, risk recompute).

---

## 6. Safety boundaries — NOT implemented by design

The following capabilities are **deliberately absent**. This is a product-safety
decision, not a gap to be "completed":

- **No malware, exploit, or payload generation.** The system prompt and persona forbid
  offensive content (exploits, malware, evasion, persistence, credential theft, bypass);
  the AI declines such requests.
- **No real-network scanning or active probing.** Discovery is *passive/simulated*:
  adapters parse already-supplied metadata only. No packet capture, port scanning, or
  active reconnaissance is performed.
- **No PLC / controller writes.** The platform never downloads logic, changes firmware,
  or writes to PLCs/RTUs/SIS. Configuration "changes" are *detected* from snapshots, not
  applied.
- **No automated containment.** The system never quarantines files, kills processes, or
  isolates hosts. Containment guidance is advisory and references *pre-approved* manual
  controls.
- **No automated firewall / network changes.** It never pushes firewall rules or alters
  segmentation; it only recommends going through the human change-management process.
- **AI is advisory-only.** The AI cannot execute any action. Every answer carries a
  forced disclaimer and cites only internal records; recommendations are passive and
  operationally conservative.
- **All risky operations are simulated and labeled demo.** Integrations are mock/read-
  only; records are flagged `is_demo`; the API description, `/health` (`demo_data: true`),
  and UI banners all make the simulated nature explicit.

These boundaries mean ForgeShield OT can be safely demonstrated against representative OT
scenarios without any possibility of impacting a live industrial process.
