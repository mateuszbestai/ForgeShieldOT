# ForgeShield OT

**A defensive OT / ICS cybersecurity & industrial‑defender console with an AI analyst layer.**

ForgeShield OT helps industrial, manufacturing, automotive, energy, utilities, critical‑infrastructure and
process‑automation teams **see, assess and govern** the cyber risk of their operational technology — SCADA,
PLCs, RTUs, HMIs, historians, engineering workstations, OT servers, network appliances, remote‑access
gateways and industrial IoT.

It is **not** a traditional IT antivirus product. PLCs and SCADA environments are safety‑critical and often
cannot run intrusive endpoint agents, so ForgeShield OT is **passive‑first, safety‑first, and read‑only by
default**. Host antimalware data is *ingested and displayed* only for supported Windows/Linux OT endpoints
(engineering workstations, HMIs, historians, jump servers, OT servers). For controllers it focuses on asset
fingerprinting, network‑anomaly detection, firmware/config integrity, unauthorized‑change detection,
vulnerability mapping, policy compliance and early warning.

---

## ⚠️ Demo / simulated data & safety

> **This MVP ships with clearly‑labeled simulated/demo data and mock connectors.** Every risky operation is
> simulated. ForgeShield OT **never** writes to PLCs, changes firewall rules, quarantines files, performs
> active/intrusive scanning, or takes automatic containment actions. The **AI analyst is advisory‑only** — it
> drafts grounded, cited recommendations and playbooks but cannot execute anything. A persistent *"Demonstration
> environment"* banner and `is_demo` flags make simulated data unmistakable throughout the UI and API.

---

## Architecture

```
                          ┌──────────────────────────────────────────────┐
   Browser (SPA)          │  React 18 + Vite + Tailwind + shadcn-style    │
   http://localhost:5173  │  TanStack Query · React Flow · Recharts       │
                          │  @supabase/supabase-js  ──login──┐            │
                          └──────────────────────────────────┼───────────┘
                                       │  Bearer JWT          │
                                       ▼                      ▼
                          ┌──────────────────────┐   ┌──────────────────┐
   API (FastAPI)          │  /api/* (72 routes)   │   │  Supabase Cloud  │
   http://localhost:8000  │  verifies Supabase JWT│◄──┤  (GoTrue auth)   │
                          │  RBAC · rate limit    │   └──────────────────┘
                          │  risk engine · audit  │
                          │  AI analyst (RAG)─────┼──► OpenAI-compatible endpoint
                          └──────┬─────────┬──────┘     (Foundation-Sec-8B / mock)
                                 │         │
                        ┌────────▼──┐  ┌───▼────────┐   ┌──────────────────────┐
                        │ PostgreSQL│  │   Redis     │   │ Celery worker + beat │
                        │  (SQLModel│  │ cache·rate  │◄──┤ daily brief · risk   │
                        │  + Alembic│  │ ·broker     │   │ recompute            │
                        └───────────┘  └─────────────┘   └──────────────────────┘
```

**Backend** — Python 3.12 · FastAPI · SQLModel/SQLAlchemy · PostgreSQL · Redis · Celery (+beat) · Alembic ·
pydantic‑settings · python‑jose (JWT) · httpx.
**Frontend** — TypeScript · React 18 · Vite · Tailwind CSS · shadcn‑style components (Radix) · TanStack Query ·
React Flow (`@xyflow/react`) · Recharts · Zustand · react‑hook‑form + zod.
**Auth** — Supabase Cloud. **AI** — provider abstraction (Cisco **Foundation‑Sec‑8B‑Reasoning** by default, with a
deterministic offline mock). **Deploy** — Docker Compose.

## Repository layout

```
ForgeShieldOT/
├── docker-compose.yml      # postgres · redis · backend · worker · frontend (+adminer profile)
├── .env.example            # all configuration (copy to .env)
├── Makefile                # up · down · seed · migrate · test · lint · fmt
├── backend/
│   ├── app/
│   │   ├── core/           # config, db, security (Supabase JWT + RBAC), enums, rate_limit, exceptions
│   │   ├── models/         # ~25 SQLModel tables
│   │   ├── schemas/        # Pydantic request/response DTOs
│   │   ├── api/routers/    # assets, detections, vulnerabilities, compliance, incidents, reports,
│   │   │                   #   integrations, risk, ai, audit, ingestion, sites, network_map, config, auth
│   │   ├── services/       # risk_engine, asset/vuln/config/compliance/incident/report/integration,
│   │   │                   #   audit, csv_io, discovery/ (simulated ingestion pipeline + adapters)
│   │   ├── ai/             # providers/{base,openai_compatible,local_foundation_sec,mock}, retrieval (RAG),
│   │   │                   #   schema (AIAnswer), system_prompt, sanitize, prompts, service
│   │   ├── workers/        # celery_app + tasks
│   │   └── seed/           # idempotent demo seed + Supabase user provisioning
│   ├── alembic/            # migrations (initial schema generated)
│   └── tests/              # 73 pytest tests
├── frontend/src/
│   ├── lib/                # api client, supabase, auth, theme, query client, endpoints, formatters
│   ├── components/         # ui/ (shadcn) · layout/ · common/ · charts/ · network/ · ai/
│   ├── pages/              # 18 pages
│   └── router.tsx
├── infra/                  # postgres init, scripts
└── docs/                   # ARCHITECTURE · DATA_MODEL · RISK_SCORING · AI_DESIGN · SECURITY · SEED_SCENARIO · API
```

---

## Quick start

**Prerequisites:** Docker + Docker Compose. (Optional, for the real demo: a Supabase project and an
OpenAI‑compatible endpoint serving Foundation‑Sec‑8B.)

```bash
cp .env.example .env          # then edit .env (see Configuration below)
docker compose up --build     # builds & starts the full stack
```

The backend entrypoint runs database migrations (`alembic upgrade head`) and idempotently seeds the demo data
on first start. Then open:

| Service       | URL                              |
|---------------|----------------------------------|
| Frontend SPA  | http://localhost:5173            |
| API + Swagger | http://localhost:8000/docs       |
| Health        | http://localhost:8000/health     |
| Adminer (opt) | `docker compose --profile tools up adminer` → http://localhost:8080 |

Handy `make` targets: `make up`, `make down`, `make reset` (wipe DB + restart), `make seed`, `make migrate`,
`make test`, `make lint`, `make fmt`, `make logs`.

### Try it without external services
You can run the **entire stack offline** for evaluation by setting `AI_PROVIDER=mock` (AI works deterministically
and offline) and `AUTH_DEV_BYPASS=true` with `ENVIRONMENT=development` (the backend then also accepts
locally‑minted HS256 tokens signed with `SUPABASE_JWT_SECRET`, for tests/CI). The committed `.env.example`
documents both the real (Supabase Cloud + Foundation‑Sec) and offline paths.

---

## Configuration

All configuration is via environment variables (`.env`). **No secrets are committed** — `.env` is gitignored;
only `.env.example` (placeholders) is in the repo.

| Group | Variables |
|------|-----------|
| **General** | `ENVIRONMENT`, `LOG_LEVEL`, `BACKEND_CORS_ORIGINS` |
| **Database** | `POSTGRES_USER/PASSWORD/DB/HOST/PORT`, or `DATABASE_URL` override |
| **Redis** | `REDIS_URL` |
| **Auth (Supabase)** | `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_KEY` (seed only), `SUPABASE_JWT_SECRET`, `SUPABASE_JWT_AUD`, `AUTH_DEV_BYPASS` (dev/tests only), `DEMO_USER_PASSWORD` |
| **AI** | `AI_PROVIDER` (`local_foundation_sec` \| `openai_compatible` \| `mock`), `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL_NAME`, `AI_TEMPERATURE`, `AI_MAX_TOKENS`, `AI_TIMEOUT_SECONDS`, `AI_JSON_MODE`, `AI_CAPTURE_REASONING`, `AI_RATE_LIMIT`, `AI_VECTOR_ENABLED` |
| **llama.cpp** | `LLAMA_THREADS`, `LLAMA_MODEL_FILE`, `LLAMA_N_GPU_LAYERS` (GPU override) |
| **Reports** | `REPORTS_PDF_ENABLED` (PDF optional; Markdown + HTML always available) |
| **Seeding** | `SEED_ON_START` |
| **Frontend (browser)** | `VITE_API_BASE_URL`, `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` |

### AI model configuration

ForgeShield OT runs **Foundation‑Sec‑8B‑Reasoning** (a cybersecurity‑specialized, reasoning LLM) locally via
**llama.cpp**, which the default stack ships as the `llama` compose service. Fetch the GGUF once and start the
GPU stack:

```bash
make llama-pull        # download the ~4.9GB Q4_K_M GGUF into the llama-models volume (public, no token)
make up-gpu            # NVIDIA GPU stack: docker compose + docker-compose.gpu.yml
# or `make up` for the CPU-only fallback (portable, slower)
```

Key settings (full list + run modes in **`docs/RUNBOOK_LLAMACPP.md`**):

```bash
AI_PROVIDER=local_foundation_sec
AI_BASE_URL=http://llama:8080/v1          # in-compose; host-run: http://host.docker.internal:8080/v1
AI_MODEL_NAME=Foundation-Sec-8B-Reasoning # must match the llama-server --alias
AI_JSON_MODE=off                          # reasoning model: think first, then JSON (recommended)
AI_CAPTURE_REASONING=true                 # persist + surface the model's reasoning trace
```

Because it talks plain **OpenAI‑compatible** HTTP, any other server (vLLM / TGI / Ollama) also works — point
`AI_BASE_URL` at its `/v1`. If no endpoint is available, set `AI_PROVIDER=mock` for a deterministic, grounded,
offline analyst. **Every provider** is forced through the same safety contract: retrieval‑grounded answers,
citations restricted to an allow‑list of internal record IDs, a confidence level (High/Medium/Low), an
assumptions section, a **"safe OT actions only"** section, and a non‑removable disclaimer. See
`docs/AI_DESIGN.md`.


How to check your pulled models (your question)

  The GGUFs live in the llama-models Docker volume, not on disk — so:

  # list files + sizes in the volume
  docker run --rm -v forgeshield-ot_llama-models:/models alpine ls -lh /models

  # what the running server is serving (only works while llama is up)
  curl -s localhost:8080/v1/models

  When I ran that, your volume contains one file: foundation-sec-8b-reasoning-q4_k_m.gguf at 3.0 GB.

  Problem 1 — that model is incomplete

  Hugging Face reports the true size as 4.92 GB; yours is 3.0 GB, so the download was cut off (and the old make llama-pull restarted from zero each
  time). This truncated file is almost certainly why you saw garbled output earlier. I just made make llama-pull resumable, so:
                                                                                                                                                       make llama-pull      # resumes from 3.0 GB → finishes at ~4.9 GB; it prints the size at the end
  Re-run it until the printed size is ~4.9 GB. Do this before starting llama — otherwise the server tries to load a truncated model and crashes.

  Problem 2 — make up-gpu failed on a Docker credential error
                                                                                                                                                       This line is the real failure (the getcwd line is just a harmless WSL warning):
  error getting credentials - err: exit status 1
  load metadata for docker.io/library/python:3.12-slim ... ERROR
  make up-gpu runs docker compose ... up --build, and the --build step needs to look up the python/node base images on Docker Hub — which invokes
  your Docker credential helper, and that helper is failing (a common Docker Desktop ↔ WSL integration hiccup).
                                                                                                                                                       You don't need to rebuild — the backend/frontend images are already built. Start the stack without --build, which skips the credential lookup        entirely:                                                                                                                                          
  docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d

  If you do want make up-gpu/--build working again, fix the credential helper one of these ways:
  - Make sure Docker Desktop is running with WSL integration enabled for this distro (Settings → Resources → WSL integration), then retry; or
  - docker logout, then retry; or
  - Edit ~/.docker/config.json and remove the "credsStore": "desktop" line (base images are public, so no creds are needed).

  Do this, in order

  cd "/mnt/c/Users/mstef/code repo/ForgeShieldOT"
  make llama-pull                                                     # 1. finish the model (re-run until ~4.9 GB)
  docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d # 2. start everything (no rebuild)                                              curl -s localhost:8080/health                                       # 3. {"status":"ok"} = model loaded                                                                                                                                                                                                   Then open http://localhost:5173 and try the AI tab. And keep the GPU power fix from before in mind (AC power + performance mode) so it runs fast
  rather than at the 15 W / 180 MHz throttle.
  
### Authentication (Supabase Cloud)

> **No Supabase tables or SQL are required.** Supabase is used **only for authentication** (GoTrue) — it
> manages its own `auth.users` internally. All ~25 application tables live in the app's **own PostgreSQL**
> container and are created automatically by the Alembic migration on boot. The only objects ForgeShield
> needs in your Supabase project are the **auth users**, created for you by the seed (Admin API) — not by SQL.

1. Create a project at <https://supabase.com>.
2. From **Project Settings → API**, copy the project URL, the `anon` key and the `service_role` key; from
   **API → JWT Settings**, copy the JWT secret. Put them in `.env` (`SUPABASE_URL`, `SUPABASE_ANON_KEY`,
   `SUPABASE_SERVICE_KEY`, `SUPABASE_JWT_SECRET`) and the browser‑safe `VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY`.
   The `VITE_*` values are read by Vite at startup, so after editing `.env` **recreate the frontend** so the
   browser bundle picks them up: `docker compose up -d` (or `docker compose restart frontend`).
3. Run the seed (`make seed`, or it runs on first boot). When `SUPABASE_SERVICE_KEY` is set, the seed provisions
   five demo users in your Supabase project via the Admin API, each with a role in `app_metadata`:

   | Email | Role |
   |-------|------|
   | `admin@forgeshield.local` | Administrator |
   | `engineer@forgeshield.local` | OT Security Engineer |
   | `analyst@forgeshield.local` | SOC Analyst |
   | `compliance@forgeshield.local` | Compliance Officer |
   | `viewer@forgeshield.local` | Viewer |

   Password = `DEMO_USER_PASSWORD` (default `Demo!ForgeShield123`). The frontend logs in via
   `@supabase/supabase-js`; the backend **verifies** the resulting JWT and maps RBAC from `app_metadata.role`.
   It accepts **both** token‑signing schemes a Supabase project may use: legacy **HS256** (shared
   `SUPABASE_JWT_SECRET`, also used for dev‑bypass/test tokens) **and** the newer asymmetric **ES256/RS256**
   tokens that modern projects issue — verified against the project's published JWKS
   (`{SUPABASE_URL}/auth/v1/.well-known/jwks.json`). The backend never issues tokens or stores passwords.

---

## Core modules

- **Dashboard** — KPIs (total/critical/unknown assets, vulns by severity, exploited‑in‑the‑wild, unauthorized
  changes, compliance score, open incidents) + widgets: risk‑score trend, asset‑criticality heatmap,
  vulnerability exposure, recent detections & config changes, compliance readiness by framework, MITRE ATT&CK
  for ICS coverage, and an **AI daily risk brief**.
- **OT Asset Inventory** — rich asset model (Purdue level, zone/conduit, protocols, criticality, safety/business
  impact, support/patch status, backup/owner, risk score …) with CRUD, filters, search, CSV import/export.
- **Passive Discovery & Protocol Intelligence** — *simulated* ingestion of PCAP‑metadata JSON, network
  observations, syslog, EDR/AV and firewall events → assets, observed protocols (Modbus TCP, S7comm,
  EtherNet/IP‑CIP, OPC UA, DNP3, Profinet, BACnet, IEC‑60870‑5‑104, MQTT, HTTP/S, SMB, RDP, SSH),
  communication relationships and detections. Parsers are safe mock adapters with a seam for real ones.
- **Network Map / Purdue model** — sites, zones, Purdue 0–5, assets, conduits; unknown links, remote‑access and
  internet‑exposed paths flagged as critical.
- **Configuration & Change Management** — snapshots, baselines, diff/compare, authorized/unauthorized
  disposition, change tickets, evidence reports, alerts on unauthorized changes to critical assets, AI change
  explanations.
- **Detections / Antimalware (defensive‑only)** — endpoint protection status, malware/YARA/hash/USB/persistence
  events, OT‑specific rules (new EW↔PLC, out‑of‑window PLC change, new L1/L2 device, malware on HMI, RDP from
  unapproved source, KEV on OT‑reachable asset …), each with severity/confidence, ATT&CK‑for‑ICS mapping,
  evidence, triage steps and **safe** containment suggestions. Simulated connectors (Defender/ClamAV/YARA/Sysmon/EDR).
- **Vulnerability Management** — CVE/CVSS/EPSS/KEV, vendor advisories, asset matching, OT‑aware prioritization,
  patch‑now/mitigate/monitor/accept‑risk workflows, remediation plans, AI explanations.
- **Policy Compliance & Audit** — control libraries for **IEC 62443, NERC CIP, TSA directives, NIS2, Saudi NCA
  OTCC, CISA CPGs, ISO 27001\*, NIST SP 800‑82\*, MITRE ATT&CK for ICS**; evidence (with auto‑linking from other
  modules), gap reports, readiness scoring, audit‑ready report export (`*` = placeholder library).
- **Incidents & Case Management** — create from detection, timeline, links, containment/recovery, AI incident &
  executive summaries, a **safe OT response checklist**.
- **AI Analyst** — grounded chat over your data (see below).
- **Integrations** — mock, read‑only connectors: SIEM webhook, Splunk/Sentinel export, ServiceNow/Jira tickets,
  Defender, Claroty/Nozomi/Dragos & Tenable/Qualys/Rapid7 import placeholders, OEM import placeholders.
- **Risk Scoring** — explainable (see `docs/RISK_SCORING.md`).
- **Reports** — Executive risk summary, asset inventory, vuln remediation plan, unauthorized change, compliance
  gap, IEC 62443 / NERC CIP evidence packs, NIS2 / Saudi OTCC readiness, incident report, AI daily brief
  (Markdown + HTML; PDF optional).
- **Audit logging** — logins, asset/baseline/detection/vuln/evidence/incident changes, **AI prompts & responses**,
  report generation and integration exports.

## API

REST under `/api`, documented at `/docs` (OpenAPI). Main groups: `/auth`, `/assets`, `/sites`, `/network-map`,
`/detections`, `/vulnerabilities`, `/config`, `/compliance`, `/incidents`, `/reports`, `/integrations`, `/risk`,
`/ai/chat`, `/audit-log`, `/ingest`. See `docs/API.md`.

## RBAC roles

| Role | Capabilities |
|------|--------------|
| **Admin** | Full access |
| **OT Security Engineer** | Manage assets, ingestion, vulnerabilities, config/change; read everything |
| **SOC Analyst** | Triage detections, manage incidents, use AI; read assets/vulns |
| **Compliance Officer** | Manage controls & evidence, generate reports; read everything |
| **Viewer** | Read‑only |

## Risk scoring (explainable)

Each asset's score (0–100) is the clamped sum of weighted, transparent factors — criticality, safety/business
impact, known‑exploited & high‑CVSS vulnerabilities, network exposure, Purdue‑level inversion, unsupported/EOL
platform, unauthorized change, active threat detections, missing backup/owner and linked compliance gaps — and
maps to a band (LOW < 35, MEDIUM 35–59, HIGH 60–79, CRITICAL ≥ 80). The API returns the **full factor breakdown,
top contributors and a single safe recommended next action**. Full table & worked examples in
`docs/RISK_SCORING.md`.

## The AI analyst (grounded, cited, advisory‑only)

- **RAG over your own records** — deterministic, structured retrieval assembles a typed evidence bundle per use
  case (asset risk, daily brief, vuln impact, remediation plan, compliance gap, config‑change explanation,
  incident/executive summary, alert translation, next‑best action, evidence mapping, free‑form chat).
- **Defensive attack‑path simulation** — for a target asset, the security model walks the relationship graph
  (internet paths, EW→PLC, remote access, unknown conduits), KEV/high‑CVSS vulnerabilities and open detections to
  produce a **blue‑team** ATT&CK‑for‑ICS attack path: entry → lateral movement → impact, each step mapped to a
  technique with its detection‑coverage gap and a safe, passive mitigation. No exploit code, payloads or active
  steps — strictly planning. Surfaced on the asset's *Ask AI* tab.
- **Reasoning trace** — the model's `<think>` reasoning (via llama.cpp `reasoning_content`) is captured, audited
  and shown as an expandable "analyst reasoning" panel.
- **Citations are allow‑listed** — the model may only cite internal record IDs present in the retrieved evidence;
  any fabricated citation is dropped server‑side.
- **Structured, safe output** — summary, findings, citations, confidence, assumptions, **safe OT actions only**,
  an optional defensive `attack_path`, and a forced disclaimer.
- **Prompt‑injection resistant** — untrusted data is delimited and sanitized, declared as *data, never
  instructions*; combined with citation allow‑listing and JSON validation.
- **Fully audited** — every prompt and response is written to the audit log.

---

## Security & limitations

ForgeShield OT enforces RBAC + Supabase JWT verification, Pydantic input validation, file‑upload validation,
AI‑endpoint rate limiting, no command execution / `eval` from user input, confirmation on destructive UI actions,
and a strict no‑secrets‑in‑repo policy. See `docs/SECURITY.md`.

**Explicitly NOT implemented — by design / for safety:** malware, exploit or payload generation; credential
theft; evasion or persistence techniques; security‑control bypass guidance; unauthorized/active scanning of real
networks; PLC write operations; automatic containment; automatic firewall changes; any function that could
disrupt an industrial process. All such operations are **simulated** and clearly labeled demo data. The AI is
**advisory‑only** and cannot execute actions. Real integrations can be added later through safe, read‑only
connectors via the provided seams.

## Testing

```bash
make test            # backend pytest (73 tests) inside the container
# or locally (Python 3.12): cd backend && pytest -q
cd frontend && npm run test    # vitest (component/unit tests)
npm run build                  # type-check + production build
```

The backend suite covers auth/RBAC, the risk engine (factors, bands, action priority, clamp), AI grounding &
citation allow‑listing, prompt‑injection defense, discovery ingestion, vuln matching/prioritization, report
generation, compliance auto‑linking, CSV round‑trip and idempotent seeding.

## Acceptance criteria

- [x] `docker compose up` runs the full app locally
- [x] Log in with demo users (Supabase) — RBAC mapped from `app_metadata.role`
- [x] Realistic OT security dashboard (KPIs + widgets + AI daily brief)
- [x] Browse OT assets with explainable risk scores
- [x] Asset detail shows protocols, vulnerabilities, detections, changes and compliance links
- [x] Purdue/zone network map (unknown / remote‑access / internet‑exposed paths flagged)
- [x] Review detections and create incidents from them
- [x] Review vulnerabilities and generate a remediation plan
- [x] Baseline and compare configuration snapshots
- [x] View compliance controls and evidence mapping
- [x] Generate ≥ 5 reports (11 report types available)
- [x] Ask the AI grounded, cited, defensive questions about the demo environment
- [x] The app never provides offensive cyber instructions
- [x] Simulated/demo data is clearly labeled
- [x] README explains setup, architecture, AI model configuration and security limitations

## Troubleshooting

| Symptom | Fix |
|--------|-----|
| AI endpoint returns 503 / "provider unavailable" | Point `AI_BASE_URL`/`AI_API_KEY`/`AI_MODEL_NAME` at a running model, or set `AI_PROVIDER=mock`. |
| Login fails / blank | Set the Supabase env vars (`SUPABASE_*` and `VITE_SUPABASE_*`) and seed demo users (`make seed`). For offline eval use `AUTH_DEV_BYPASS=true` + minted tokens (tests). |
| **Sign in does nothing — no error, stays on login** | The Supabase login succeeded but the backend rejected the session token. Most common causes: (a) `SUPABASE_JWT_SECRET` doesn't match the project (legacy HS256 projects); (b) the backend wasn't restarted after editing `.env`. The backend accepts modern **ES256/JWKS** tokens too, so a fresh project works out of the box — just ensure `SUPABASE_URL` is set and reachable. Verify end‑to‑end: log in with `admin@forgeshield.local` and confirm `GET /api/auth/me` returns `200`. |
| Supabase has "no tables" | Expected — Supabase is auth‑only; app tables live in the app's own Postgres. No Supabase SQL is needed. |
| Port already in use (5432/6379/8000/5173) | Stop the conflicting service (e.g. a local Postgres) or remap ports in `docker-compose.yml`. |
| DB schema out of date | `make migrate` (or `make reset` to wipe and re‑seed). |

---

*ForgeShield OT is a demonstration MVP. Validate all AI recommendations with a qualified OT engineer before
acting on safety‑critical systems.*
