# ForgeShield OT — Risk Scoring

ForgeShield OT scores each asset with an **explainable, additive, weighted-factor**
model. The result is a 0–100 score, a band, an ordered factor breakdown (each with its
own points/max and the records that justify it), and a single recommended next action
phrased for safe/passive OT operations.

Implementation: `backend/app/services/risk_engine.py`. The core function
`compute_risk(RiskInput) -> RiskResult` is **pure and deterministic** (fully
unit-testable); `build_risk_input(session, asset)` assembles the input from the
database; `score_asset(...)` persists the denormalized `risk_score` / `risk_band` onto
the asset; `recompute_all(session)` rescores every asset (run hourly by Celery beat).

The score is **not** capped per-asset before summation — factors are summed, rounded,
and then clamped to a maximum of 100.

---

## 1. Factor table

Each factor only contributes when its condition holds (zero-point factors are omitted
from the breakdown). Points are summed, rounded to the nearest integer, then clamped to
`[0, 100]`.

| # | Factor key | Label | Max pts | Points awarded · how computed (from `Asset` + linked records) |
|---|-----------|-------|--------:|----------------------------------------------------------------|
| 1 | `criticality` | Asset criticality | 18 | `LOW`→2, `MEDIUM`→8, `HIGH`→14, `SAFETY_CRITICAL`→18 (always present). |
| 2 | `safety_impact` | Safety impact | 16 | `NONE`→0, `LOW`→5, `MEDIUM`→10, `HIGH`→16. |
| 3 | `business_impact` | Business impact | 8 | `NONE`→0, `LOW`→2, `MEDIUM`→5, `HIGH`→8. |
| 4 | `known_exploited_vuln` | Known-exploited / critical-severity vuln | 16 | **16** if any open vuln is CISA-KEV (`known_exploited`); **else 6** if the highest open CVSS ≥ 9.0; otherwise absent. |
| 5 | `cvss_exposure` | Vulnerability severity exposure | 10 | `min(10.0, max_open_cvss)` when any open vuln exists (CVSS > 0). |
| 6 | `network_exposure` | Network exposure | 12 | **12** if `internet_reachable`; **else 8** if `it_reachable`; **else 6** if `remote_access_enabled`. (Highest applicable only.) |
| 7 | `purdue_inversion` | Purdue-level inversion | 6 | Only for low-level assets (`purdue_level ≤ L2`): **6** if also internet-reachable; **else 3** if IT-reachable. |
| 8 | `unsupported_platform` | Unsupported / outdated platform | 8 | **8** if `support_status == UNSUPPORTED` **or** `patch_status == EOL`; **else 4** if `support_status == EXTENDED` **or** `patch_status == OUTDATED`. |
| 9 | `unauthorized_change` | Unauthorized configuration change | 10 | If an `UNAUTHORIZED` `ConfigChange` is open: **10**, reduced to **8** if the change is older than 30 days. |
| 10 | `malware_detection` | Active threat detection | 12 | Highest open malware/endpoint detection severity → `CRITICAL`→12, `HIGH`→9, `MEDIUM`→5, `LOW`→2, `INFO`→1. |
| 11 | `missing_backup` | Missing backup/config | 4 | **4** when `backup_available` is false. |
| 12 | `missing_owner` | Missing asset owner | 3 | **3** when no owner **and** criticality ∈ {`HIGH`, `SAFETY_CRITICAL`}. |
| 13 | `compliance_gap` | Linked compliance gaps | 5 | `min(5.0, gap_controls × 1.5)` — counts distinct linked controls in `NOT_STARTED`/`PARTIAL`. |

**Maximum possible (sum of maxes):** 18+16+8+16+10+12+6+8+10+12+4+3+5 = **128**, so a
fully-stacked worst-case asset clamps to **100**.

### How linked records are gathered (`build_risk_input`)

- **Vulnerabilities** — open `AssetVulnerability` rows (`status` ∈ `OPEN`, `PATCH_NOW`,
  `MITIGATE`, `MONITOR`). Sets `has_kev_open` (any `known_exploited`), `max_open_cvss`,
  and citation refs (`vuln:<cve_id>`).
- **Detections** — open detections (`status` ∈ `NEW`, `TRIAGING`, `CONFIRMED`) whose
  `detection_type` is in the malware set (`MALWARE`, `QUARANTINED_FILE`, `YARA_MATCH`,
  `HASH_REPUTATION`, `SUSPICIOUS_PROCESS`, `AUTORUN_PERSISTENCE`, `UNSIGNED_BINARY`,
  `ENG_TOOL_ABUSE`); takes the highest severity (refs `detection:<id>`).
- **Config changes** — `ConfigChange` rows with `disposition == UNAUTHORIZED`; computes
  age from `detected_at`/`created_at` (refs `config_change:<id>`).
- **Compliance gaps** — `ComplianceEvidence` rows whose `source_id` is the asset and
  whose linked control is in a gap status; counts distinct controls (refs
  `control:<control_ref>`).

Each emitted factor carries `record_refs` (e.g. `asset:<id>`, `vuln:CVE-…`) so the UI
can show *why* the score is what it is.

---

## 2. Band thresholds

```
score   0 ─────────────── 35 ─────────────── 60 ─────────────── 80 ──────────── 100
band    │      LOW         │     MEDIUM        │      HIGH         │   CRITICAL    │
        └──────────────────┴───────────────────┴──────────────────┴───────────────┘
```

| Band       | Condition       |
|------------|-----------------|
| `LOW`      | `score < 35`    |
| `MEDIUM`   | `35 ≤ score < 60` |
| `HIGH`     | `60 ≤ score < 80` |
| `CRITICAL` | `score ≥ 80`    |

(From `_band()`; verified by parametrized tests at boundaries 34/35, 59/60, 79/80.)
The frontend mirrors these thresholds in `frontend/src/lib/riskBands.ts`.

---

## 3. Recommended-action decision tree

`_recommended_action(...)` selects exactly **one** action from the active factor keys,
in this strict priority order (first match wins):

```
if  malware_detection present
        → "Isolate the affected endpoint using existing, pre-approved network
           controls (do not alter PLC logic). Preserve forensic evidence and open
           an incident."
elif known_exploited_vuln present AND has_kev_open
        → "Prioritize remediation of the known-exploited vulnerability. If patching
           is not feasible, apply OT compensating controls (segmentation, monitoring,
           access restriction)."
elif unauthorized_change present
        → "Investigate the unauthorized configuration change. Compare against the
           approved baseline and confirm the associated change ticket before taking
           any action."
elif network_exposure present AND (internet_reachable OR it_reachable)
        → "Review network segmentation. Remove internet/IT reachability and restrict
           remote access to this OT asset via the firewall change process."
elif unsupported_platform present
        → "Plan migration or apply compensating controls for the unsupported/EOL
           platform; increase monitoring in the interim."
elif total points ≥ 35   (score_is_elevated)
        → "Schedule a risk review, assign an owner, and ensure a current backup exists."
else
        → "Maintain passive monitoring; no elevated risk indicators."
```

Note the priority order is **malware → KEV → unauthorized-change → exposure →
unsupported platform → elevated → none**, and the KEV branch additionally requires the
real KEV flag (the `known_exploited_vuln` factor can also fire for a CVSS ≥ 9 vuln that
is *not* KEV, which does not, on its own, trigger the KEV action). Every recommended
action is passive/safe; none instructs the system or operator to write to a controller.

---

## 4. Worked examples

### Example A — `AUTO-WINSRV-01` (unsupported Windows line-data server with KEV)

Seed inputs: criticality `HIGH`, safety_impact `LOW`, business_impact `HIGH`, Purdue
`L3`, `it_reachable = true` (not internet), `support_status = UNSUPPORTED`,
`patch_status = EOL`, `backup_available = false`, owner = "Manufacturing IT". Linked
open vuln `CVE-2024-50004` (KEV, CVSS 9.8). Its open detections (`KEV_EXPOSURE`,
`UNSUPPORTED_OS`) are **not** in the malware set, so factor #10 does not fire.

| Factor | Points |
|--------|-------:|
| `known_exploited_vuln` (KEV) | 16.0 |
| `criticality` (HIGH) | 14.0 |
| `cvss_exposure` (min(10, 9.8)) | 9.8 |
| `network_exposure` (IT-reachable) | 8.0 |
| `unsupported_platform` (UNSUPPORTED/EOL) | 8.0 |
| `business_impact` (HIGH) | 8.0 |
| `safety_impact` (LOW) | 5.0 |
| `missing_backup` | 4.0 |
| **Raw sum** | **72.8** |

`purdue_inversion` does **not** apply (asset is L3, not ≤ L2); `missing_owner` does not
apply (owner present). Raw 72.8 → **score 73 → band HIGH**.

Recommended action: no malware factor, but `known_exploited_vuln` is present with
`has_kev_open` → **"Prioritize remediation of the known-exploited vulnerability… apply
OT compensating controls (segmentation, monitoring, access restriction)."**

### Example B — Worst-case stacked asset (clamps to CRITICAL 100)

When every adverse condition holds — `SAFETY_CRITICAL`, safety/business `HIGH`, Purdue
`L1`, internet- + IT-reachable + remote access, `UNSUPPORTED`/`EOL`, no backup, no
owner, open KEV, CVSS 10.0, `CRITICAL` malware detection, open unauthorized change, 5+
linked gap controls — the raw sum exceeds 128 worth of triggered maxes and is clamped:

```
score = 100   →   band = CRITICAL
```

(This is asserted directly by `test_fully_stacked_input_clamps_to_critical_100`.) With
a malware detection present, the recommended action is the highest-priority one:
**"Isolate the affected endpoint…"**

### Example C — Benign isolated asset (LOW)

A `LOW`-criticality, isolated, supported, backed-up asset with an owner and no vulns/
detections/changes contributes only the criticality factor (2 points) → **score 2 →
band LOW**, recommended action **"Maintain passive monitoring; no elevated risk
indicators."**

---

## 5. API surface

| Method · path | Purpose |
|---|---|
| `GET /api/risk/asset/{asset_id}` | Full explainable result for one asset (score, band, ordered factors, `top_factors`, `recommended_action`). |
| `GET /api/risk/rollup?site_id=` | Aggregate rollup (`asset_count`, `average_score`, `max_score`, per-band counts) for the global or per-site scope. |
| `POST /api/risk/recompute` | Recompute and persist scores for all assets (write roles). Also runs hourly via Celery beat. |

`RiskResult` / `RiskFactor` DTOs are defined in `backend/app/schemas/risk.py`.
