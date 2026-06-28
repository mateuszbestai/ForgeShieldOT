# ForgeShield OT — API Reference

The backend exposes a REST API under the **`/api`** prefix (set by `API_PREFIX`).
Interactive **OpenAPI / Swagger** docs are served at **http://localhost:8000/docs**, and
the raw schema at **http://localhost:8000/openapi.json**. There are ~70 routes across
the domains below.

This catalog is derived from `backend/app/api/routers/*` (aggregated by
`backend/app/api/router.py`). All paths are shown **with** the `/api` prefix.

## Conventions

- **Auth.** Every endpoint except `GET /api/auth/config` requires a valid Supabase
  Bearer JWT (`get_current_user`). See `SECURITY.md`.
- **Roles.** Write/mutating endpoints add `require_role(...)` with one of these groups
  (ADMIN is always allowed):
  - **WRITE** = `WRITE_OPERATIONS` (ADMIN, OT_SECURITY_ENGINEER)
  - **SOC** = `SOC_OPERATIONS` (ADMIN, OT_SECURITY_ENGINEER, SOC_ANALYST)
  - **COMPL** = `COMPLIANCE_OPERATIONS` (ADMIN, COMPLIANCE_OFFICER)
  - **(auth)** = any authenticated user (read).
- **Non-`/api` endpoints:** `GET /` and `GET /health` (health/info; unauthenticated).

---

## Auth (`/api/auth`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/auth/config` | public | Non-secret Supabase config for the SPA (URL + anon key + `configured`). |
| `GET /api/auth/me` | (auth) | Current user profile; records `LOGIN` audit and updates `last_login`. |

## Assets (`/api/assets`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/assets` | (auth) | List/filter assets (paginated). |
| `GET /api/assets/filters` | (auth) | Available filter facets. |
| `GET /api/assets/export` | (auth) | Export assets as CSV (plain text). |
| `POST /api/assets/import` | WRITE | CSV import of assets. |
| `POST /api/assets` | WRITE | Create an asset. |
| `GET /api/assets/{asset_id}` | (auth) | Asset detail. |
| `PATCH /api/assets/{asset_id}` | WRITE | Update an asset. |
| `DELETE /api/assets/{asset_id}` | WRITE | Delete an asset (`204`). |

## Sites & Zones (`/api/sites`, `/api/zones`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/sites` | (auth) | List sites. |
| `GET /api/sites/{site_id}/zones` | (auth) | Zones for a site. |
| `GET /api/zones` | (auth) | List all zones. |

## Network Map (`/api/network-map`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/network-map` | (auth) | Purdue-level graph of assets, relationships and conduits (feeds the React Flow map). |

## Detections (`/api/detections`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/detections` | (auth) | List/filter detections (paginated). |
| `GET /api/detections/stats` | (auth) | Detection stats/aggregates. |
| `POST /api/detections` | WRITE | Create a detection. |
| `GET /api/detections/{detection_id}` | (auth) | Detection detail. |
| `PATCH /api/detections/{detection_id}` | SOC | Update detection status/fields. |
| `POST /api/detections/{detection_id}/evidence` | SOC | Add evidence to a detection. |

## Vulnerabilities (`/api/vulnerabilities`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/vulnerabilities` | (auth) | List/filter vulnerabilities. |
| `GET /api/vulnerabilities/stats` | (auth) | Vulnerability stats (KEV/CVSS aggregates). |
| `POST /api/vulnerabilities` | WRITE | Create a vulnerability. |
| `GET /api/vulnerabilities/{vuln_id}` | (auth) | Vulnerability detail. |
| `PATCH /api/vulnerabilities/{vuln_id}` | WRITE | Update a vulnerability. |
| `POST /api/vulnerabilities/{vuln_id}/match` | WRITE | Match the vuln to affected assets. |
| `GET /api/vulnerabilities/{vuln_id}/assets` | (auth) | Affected assets for a vuln. |
| `POST /api/vulnerabilities/asset-links/{link_id}/status` | WRITE | Update an asset-vuln link's remediation status. |
| `POST /api/vulnerabilities/{vuln_id}/remediation-plan` | WRITE | Save a remediation plan. |
| `POST /api/vulnerabilities/{vuln_id}/ai-explain` | WRITE | AI vuln-impact explanation (advisory). |
| `POST /api/vulnerabilities/{vuln_id}/ai-remediation` | WRITE | AI staged remediation plan (advisory). |

## Config & Change Management (`/api/config`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/config/snapshots` | (auth) | List config snapshots. |
| `POST /api/config/snapshots` | WRITE | Create a snapshot. |
| `POST /api/config/snapshots/{snapshot_id}/baseline` | WRITE | Mark a snapshot as the approved baseline. |
| `POST /api/config/compare` | WRITE | Diff two snapshots / detect a change. |
| `POST /api/config/import` | WRITE | Import config snapshot data. |
| `GET /api/config/changes` | (auth) | List config changes. |
| `GET /api/config/changes/{change_id}` | (auth) | Change detail. |
| `POST /api/config/changes/{change_id}/disposition` | WRITE | Set disposition (authorized/unauthorized). |
| `GET /api/config/changes/{change_id}/evidence-report` | (auth) | Render a change evidence report (plain text). |
| `POST /api/config/changes/{change_id}/ai-explain` | WRITE | AI explanation of a change (advisory). |

## Compliance (`/api/compliance`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/compliance/frameworks` | (auth) | List frameworks + readiness. |
| `GET /api/compliance/frameworks/mapping` | (auth) | Cross-framework / control mapping. |
| `GET /api/compliance/controls` | (auth) | List/filter controls. |
| `GET /api/compliance/controls/{control_id}` | (auth) | Control detail. |
| `PATCH /api/compliance/controls/{control_id}` | COMPL | Update a control's status/owner. |
| `POST /api/compliance/controls/{control_id}/ai-gap` | COMPL | AI gap summary for a control (advisory). |
| `POST /api/compliance/evidence` | COMPL | Attach evidence to a control (`201`). |
| `POST /api/compliance/auto-link` | COMPL | Auto-link evidence from other modules. |
| `GET /api/compliance/gap-report` | (auth) | Compliance gap report. |

## Incidents (`/api/incidents`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/incidents` | (auth) | List/filter incidents. |
| `GET /api/incidents/stats` | (auth) | Incident stats. |
| `GET /api/incidents/checklist` | (auth) | Safe OT incident-response checklist. |
| `GET /api/incidents/{incident_id}` | (auth) | Incident detail (timeline + links). |
| `POST /api/incidents` | SOC | Create an incident (`201`). |
| `POST /api/incidents/from-detection` | SOC | Create an incident from a detection (`201`). |
| `PATCH /api/incidents/{incident_id}` | SOC | Update an incident. |
| `POST /api/incidents/{incident_id}/timeline` | SOC | Add a timeline event (`201`). |
| `POST /api/incidents/{incident_id}/links` | SOC | Link a detection/asset/vuln/change (`201`). |
| `POST /api/incidents/{incident_id}/ai-summary` | SOC | AI incident summary (advisory). |
| `POST /api/incidents/{incident_id}/ai-exec-summary` | SOC | AI executive summary (advisory). |

## Reports (`/api/reports`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/reports/types` | (auth) | Available report types. |
| `GET /api/reports` | (auth) | List generated reports (paginated). |
| `POST /api/reports/generate` | WRITE | Generate a report (`201`). |
| `GET /api/reports/{report_id}` | (auth) | Report detail. |
| `GET /api/reports/{report_id}/download` | (auth) | Download as Markdown/HTML/PDF. |

## Integrations (`/api/integrations`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/integrations` | (auth) | List integrations (all mock/read-only). |
| `GET /api/integrations/{integration_id}` | (auth) | Integration detail. |
| `POST /api/integrations/{integration_id}/toggle` | WRITE | Enable/disable an integration. |
| `POST /api/integrations/{integration_id}/export` | WRITE | Simulated export run. |
| `POST /api/integrations/{integration_id}/import` | WRITE | Simulated import run. |

## Risk (`/api/risk`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/risk/asset/{asset_id}` | (auth) | Explainable per-asset risk (score, band, factors, recommended action). |
| `GET /api/risk/rollup?site_id=` | (auth) | Aggregate rollup (global or per-site). |
| `POST /api/risk/recompute` | WRITE | Recompute & persist scores for all assets; audited. |

See `RISK_SCORING.md` for the model.

## AI Analyst (`/api/ai`)

| Method · Path | Role | Description |
|---|---|---|
| `POST /api/ai/chat` | (auth) · **rate-limited** | Grounded, cited, advisory answer for a `use_case` (+ optional `entity_id`). Default 20/min per user. |
| `GET /api/ai/health` | (auth) | Active provider/model + reachability. |
| `GET /api/ai/conversations` | (auth) | The caller's recent conversations. |
| `GET /api/ai/conversations/{conversation_id}/messages` | (auth) | Messages in a conversation. |

See `AI_DESIGN.md` for the provider abstraction, RAG, and the `AIAnswer` contract.

## Audit Log (`/api/audit-log`)

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/audit-log` | (auth) | Query the immutable audit trail (paginated/filterable). |

## Ingestion (`/api/ingest`)

Simulated **passive** discovery — parses already-supplied metadata only (no live capture
or scanning). See `ARCHITECTURE.md` §6.

| Method · Path | Role | Description |
|---|---|---|
| `GET /api/ingest/sources` | (auth) | Supported sources + sample payloads. |
| `POST /api/ingest/{source}` | WRITE | Ingest a metadata payload for a source (`pcap_meta` · `network_obs` · `syslog` · `edr` · `firewall` · `manual`); body size-guarded (~2 MB). |

---

## Health / info (no prefix)

| Method · Path | Description |
|---|---|
| `GET /` | App name, docs link, demo notice. |
| `GET /health` | Status, environment, Redis health, active AI provider, `demo_data: true`. |
