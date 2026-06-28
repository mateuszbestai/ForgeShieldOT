# ForgeShield OT — Data Model

The persistence layer is **SQLModel** (SQLAlchemy + Pydantic). There are **25 tables**,
all registered on `SQLModel.metadata` via `backend/app/models/__init__.py`. Most tables
carry three mixins from `models/base.py`:

- `UUIDMixin` — `id: UUID` primary key (`uuid4`, indexed).
- `TimestampMixin` — `created_at`, `updated_at` (auto-`onupdate`).
- `DemoMixin` — `is_demo: bool` (indexed) so the UI/AI can label simulated data.

JSON columns use a cross-database helper (`json_column()`) that works on both
PostgreSQL and the SQLite test database. Models use **explicit foreign-key columns**
and explicit `select()` queries in services (no ORM `Relationship()` objects).

---

## 1. Tables by domain

### People / access

| Table       | Class      | Key fields | Notes |
|-------------|------------|------------|-------|
| `role`      | `Role`     | `name` (RoleName, unique), `description` | Normalized role catalog (one per RoleName). |
| `app_user`  | `User`     | `supabase_id` (unique), `email`, `full_name`, `role` (RoleName), `is_active`, `last_login` | Local mirror of Supabase users; `User.role` is the runtime RBAC source. |
| `user_role` | `UserRole` | `user_id → app_user`, `role_id → role` | Normalized assignment (catalog completeness; runtime RBAC uses `User.role`). |

### Organization

| Table  | Class | Key fields | Notes |
|--------|-------|------------|-------|
| `site` | `Site` | `name`, `code`, `location`, `industry`, `description` | A plant/facility. |
| `zone` | `Zone` | `site_id → site`, `name`, `purdue_level` (PurdueLevel), `conduit`, `internet_exposed`, `it_reachable` | Purdue network zone / conduit. |

### Asset inventory

| Table                  | Class                 | Key fields | Notes |
|------------------------|-----------------------|------------|-------|
| `asset`                | `Asset`               | `asset_tag` (unique), `hostname/ip/mac`, `vendor/model/firmware_version/software_version`, `os_name`, `site_id`, `zone_id`, `purdue_level`, `asset_type`, `criticality`, `safety_impact`, `business_impact`, `owner`, `support_status`, `patch_status`, `backup_available`, `config_available`, `internet_reachable`, `it_reachable`, `remote_access_enabled`, `endpoint_protection_installed/healthy`, `discovery_source`, `last_seen`, `risk_score`, `risk_band`, `compliance_tags` (JSON), `notes` | The central inventory record; `risk_score`/`risk_band` are denormalized by the risk engine. |
| `asset_relationship`   | `AssetRelationship`   | `src_asset_id → asset`, `dst_asset_id → asset`, `protocol`, `relationship_type`, `is_unknown`, `is_internet_path`, `first_seen`, `last_seen`, `observation_count` | Observed communication path/conduit; unique on `(src, dst, protocol)`. |
| `protocol_observation` | `ProtocolObservation` | `asset_id → asset`, `protocol`, `port`, `direction`, `observation_count`, `first_seen`, `last_seen`, `source` | Passive protocol fingerprint; unique on `(asset, protocol)`. |

### Vulnerabilities

| Table                 | Class               | Key fields | Notes |
|-----------------------|---------------------|------------|-------|
| `vulnerability`       | `Vulnerability`     | `cve_id` (unique), `title`, `cvss_base`, `cvss_vector`, `epss`, `known_exploited` (CISA KEV), `vendor`, `product`, `affected_versions` (JSON), `remediation`, `workaround`, `patch_available`, `patch_risk`, `required_downtime`, `ot_compensating_controls` (JSON), `safety_impact` | Vulnerability catalog. |
| `asset_vulnerability` | `AssetVulnerability`| `asset_id → asset`, `vuln_id → vulnerability`, `status` (VulnRemediationStatus), `match_basis`, `priority_score`, `exploitability_in_context`, `asset_exposure_note`, `detected_at`, risk-acceptance fields, `remediation_plan` | Many-to-many association with OT-aware workflow state; unique on `(asset, vuln)`. |

### Detections (defensive-only)

| Table                | Class               | Key fields | Notes |
|----------------------|---------------------|------------|-------|
| `detection`          | `Detection`         | `title`, `detection_type`, `severity`, `confidence`, `status`, `asset_id → asset`, `site_id → site`, `description`, `attck_ics_technique`, `attck_ics_tactic`, `triage_steps` (JSON), `safe_containment_steps` (JSON), `ai_summary`, `source`, `detected_at` | An alert / anomaly; containment steps are *safe* and advisory. |
| `detection_evidence` | `DetectionEvidence` | `detection_id → detection`, `kind` (EvidenceKind), `label`, `data` (JSON, untrusted — sanitized before AI use) | Supporting evidence. |

### Configuration / change management

| Table             | Class            | Key fields | Notes |
|-------------------|------------------|------------|-------|
| `config_snapshot` | `ConfigSnapshot` | `asset_id → asset`, `label`, `kind` (SnapshotKind), `is_baseline`, `content` (JSON), `content_hash`, `captured_at`, `source` | Normalized key/value content used for diffing. |
| `config_change`   | `ConfigChange`   | `asset_id → asset`, `from_snapshot_id`, `to_snapshot_id` (→ `config_snapshot`), `summary`, `diff` (JSON `[{field,before,after}]`), `disposition` (ChangeDisposition), `change_ticket`, `within_approved_window`, `detected_at`, `reviewed_by`, `ai_explanation` | Detected change between snapshots; drives unauthorized-change risk. |

### Compliance

| Table                  | Class                 | Key fields | Notes |
|------------------------|-----------------------|------------|-------|
| `compliance_framework` | `ComplianceFramework` | `key` (FrameworkKey, unique), `name`, `version`, `description`, `is_placeholder` | A framework (IEC 62443, NERC CIP, …). |
| `compliance_control`   | `ComplianceControl`   | `framework_id → compliance_framework`, `control_ref`, `title`, `description`, `evidence_required`, `status` (ControlStatus), `owner`, `due_date`, `last_reviewed`, `ai_gap_summary` | A control within a framework. |
| `compliance_evidence`  | `ComplianceEvidence`  | `control_id → compliance_control`, `source_type` (EvidenceSourceType), `source_id` (linked asset/detection/…), `description`, `file_name`, `file_note`, `auto_linked`, `uploaded_by` | Evidence; may be auto-linked from other modules. No raw file bytes are stored (metadata only). |

### Incidents

| Table                     | Class                   | Key fields | Notes |
|---------------------------|-------------------------|------------|-------|
| `incident`                | `Incident`              | `reference` (e.g. `INC-2026-0001`, unique), `title`, `severity`, `status` (IncidentStatus), `site_id → site`, `summary`, `attck_ics_technique`, `lead_owner`, `containment_actions` (JSON), `recovery_actions` (JSON), `lessons_learned`, `compliance_impact`, `ai_summary`, `executive_summary`, `opened_at`, `closed_at` | A case. |
| `incident_timeline_event` | `IncidentTimelineEvent` | `incident_id → incident`, `kind` (TimelineEventKind), `description`, `author`, `occurred_at`, `ref` | Chronological case events. |
| `incident_link`           | `IncidentLink`          | `incident_id → incident`, `link_type` (IncidentLinkType), `entity_id` | Polymorphic link to a detection/asset/vuln/change. |

### Reports / integrations / audit / AI

| Table             | Class           | Key fields | Notes |
|-------------------|-----------------|------------|-------|
| `report`          | `Report`        | `report_type` (ReportType), `title`, `fmt` (ReportFormat), `content` (rendered Markdown/HTML), `params` (JSON), `generated_by → app_user`, `summary` | Generated report. |
| `integration`     | `Integration`   | `kind` (IntegrationKind), `name`, `direction` (IntegrationDirection), `enabled`, `is_mock` (always true in MVP), `config` (JSON, non-secret only), `description`, `last_sync_summary` | Mock/read-only connector. |
| `audit_log`       | `AuditLog`      | `actor_user_id → app_user`, `actor_email`, `action` (AuditAction), `entity_type`, `entity_id`, `summary`, `meta` (JSON), `ip_address` | Immutable audit trail. |
| `ai_conversation` | `AIConversation`| `user_id → app_user`, `title`, `use_case` (AIUseCase) | A chat thread. |
| `ai_message`      | `AIMessage`     | `conversation_id → ai_conversation`, `role` (MessageRole), `content`, `citations` (JSON), `confidence`, `assumptions` (JSON), `safe_ot_actions` (JSON), `provider_name`, `model_name`, `latency_ms`, `use_case` | A message; assistant messages retain the full structured `AIAnswer` for audit. |

**Table count:** 25 (`role`, `app_user`, `user_role`, `site`, `zone`, `asset`,
`asset_relationship`, `protocol_observation`, `vulnerability`, `asset_vulnerability`,
`detection`, `detection_evidence`, `config_snapshot`, `config_change`,
`compliance_framework`, `compliance_control`, `compliance_evidence`, `incident`,
`incident_timeline_event`, `incident_link`, `report`, `integration`, `audit_log`,
`ai_conversation`, `ai_message`).

---

## 2. ASCII ER overview

```
        site ────────────────┐
         │ 1                  │ 1
         │ *                  │ *
        zone               asset ───────────────────────────────────────────┐
                            │  ▲ │ ▲                                          │
        ┌───────────────────┘  │ │ │                                         │
        │ src/dst (M:N self)   │ │ └── 1:* ── protocol_observation           │
        │                      │ │                                           │
  asset_relationship           │ └──── 1:* ── config_snapshot                │
                               │                  │  ▲                        │
                               │                  │  │ from/to                │
                               │                  └──┴── config_change ──┐    │
                               │                                         │    │
        vulnerability ── M:N ──┴── asset_vulnerability                   │    │
                                                                         │    │
        detection ── 1:* ── detection_evidence                          │    │
            │  (asset_id, site_id → asset/site)                          │    │
            │                                                            │    │
  compliance_framework ─ 1:* ─ compliance_control ─ 1:* ─ compliance_evidence │
                                                                              │
  incident ─ 1:* ─ incident_timeline_event                                    │
     │                                                                        │
     └─ 1:* ─ incident_link ──(entity_id, polymorphic)──► detection/asset/vuln/change

  app_user ─ 1:* ─ ai_conversation ─ 1:* ─ ai_message
  app_user ─ 1:* ─ audit_log              report ─(generated_by)─► app_user
  role ─ M:N(user_role) ─ app_user        integration  (standalone)
```

`ComplianceEvidence.source_id` and `IncidentLink.entity_id` are **soft (polymorphic)
references** — plain UUID columns interpreted by `source_type` / `link_type`, not
enforced FKs.

---

## 3. Key enums

All enums live in `backend/app/core/enums.py` (`value == name`, uppercase) and are
mirrored in `frontend/src/types/enums.ts`.

**RoleName** (RBAC): `ADMIN`, `OT_SECURITY_ENGINEER`, `SOC_ANALYST`,
`COMPLIANCE_OFFICER`, `VIEWER`.

**Criticality:** `LOW`, `MEDIUM`, `HIGH`, `SAFETY_CRITICAL`.

**ImpactLevel** (safety/business): `NONE`, `LOW`, `MEDIUM`, `HIGH`.

**PurdueLevel** (IntEnum 0–5): `L0` physical process, `L1` basic control (PLC/RTU),
`L2` area supervisory (HMI/SCADA), `L3` site operations, `L4` site business/IT,
`L5` enterprise/internet.

**AssetType:** `PLC`, `RTU`, `HMI`, `SCADA_SERVER`, `HISTORIAN`, `ENG_WORKSTATION`,
`SAFETY_SIS`, `NETWORK_DEVICE`, `REMOTE_ACCESS_GATEWAY`, `IIOT_EDGE`,
`OEM_VENDOR_SYSTEM`.

**SupportStatus:** `SUPPORTED`, `EXTENDED`, `UNSUPPORTED`, `UNKNOWN`.
**PatchStatus:** `CURRENT`, `OUTDATED`, `EOL`, `UNKNOWN`.

**DiscoverySource:** `PASSIVE_NETWORK`, `MANUAL`, `CSV_IMPORT`, `EDR`, `FIREWALL`,
`OEM_IMPORT`, `SEED`.

**RelationshipType:** `COMM`, `EW_TO_PLC`, `REMOTE_ACCESS`, `MANAGEMENT`.
**ProtocolDirection:** `INBOUND`, `OUTBOUND`, `BIDIRECTIONAL`.

**NormalizedProtocol:** `MODBUS_TCP`, `S7COMM`, `ETHERNET_IP_CIP`, `OPC_UA`, `DNP3`,
`PROFINET`, `BACNET`, `IEC_60870_5_104`, `MQTT`, `HTTP`, `HTTPS`, `SMB`, `RDP`, `SSH`.
(OT control protocols and remote-access protocols are defined as subsets used by the
EW→PLC and remote-access heuristics.)

**Severity:** `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
**Confidence:** `LOW`, `MEDIUM`, `HIGH`.
**RiskBand:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

**DetectionType:** `MALWARE`, `QUARANTINED_FILE`, `YARA_MATCH`, `HASH_REPUTATION`,
`SUSPICIOUS_PROCESS`, `USB_INSERTION`, `AUTORUN_PERSISTENCE`, `UNSIGNED_BINARY`,
`ENG_TOOL_ABUSE`, `UNKNOWN_ASSET`, `UNKNOWN_COMM_PATH`, `NEW_DEVICE_IN_ZONE`,
`EW_TO_PLC`, `REMOTE_ACCESS`, `RDP_FROM_UNAPPROVED`, `OUT_OF_WINDOW_CHANGE`,
`UNUSUAL_OUTBOUND`, `FIREWALL_EXPOSURE`, `UNSUPPORTED_OS`, `KEV_EXPOSURE`,
`ENDPOINT_PROTECTION_STATUS`.
**DetectionStatus:** `NEW`, `TRIAGING`, `CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`.
**EvidenceKind:** `HASH`, `PROCESS`, `FILE_META`, `YARA`, `USB`, `LOG`, `NETWORK`,
`CONFIG`.

**VulnRemediationStatus:** `OPEN`, `PATCH_NOW`, `MITIGATE`, `MONITOR`, `RISK_ACCEPTED`,
`REMEDIATED`.
**PatchRisk:** `LOW`, `MEDIUM`, `HIGH`, `REQUIRES_OUTAGE`.
**MatchBasis:** `VENDOR_MODEL_VERSION`, `VENDOR_PRODUCT`, `MANUAL`.

**SnapshotKind:** `PLC_PROGRAM`, `FIRMWARE`, `LOGIC`, `NETWORK_CONFIG`,
`FIREWALL_RULES`, `SOFTWARE_INVENTORY`, `ACCOUNT_CONFIG`, `BACKUP_STATUS`.
**ChangeDisposition:** `UNREVIEWED`, `AUTHORIZED`, `UNAUTHORIZED`.

**FrameworkKey:** `IEC_62443`, `NERC_CIP`, `TSA`, `NIS2`, `NCA_OTCC`, `CISA_CPG`,
`ISO_27001`, `NIST_800_82`, `MITRE_ATTCK_ICS`.
**ControlStatus:** `NOT_STARTED`, `PARTIAL`, `IMPLEMENTED`, `NOT_APPLICABLE`
(`NOT_STARTED` + `PARTIAL` count as open gaps for readiness).
**EvidenceSourceType:** `ASSET`, `DETECTION`, `CONFIG_CHANGE`, `VULN`, `INCIDENT`,
`REPORT`, `MANUAL`.

**IncidentStatus:** `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`.
**TimelineEventKind:** `NOTE`, `EVIDENCE`, `STATUS_CHANGE`, `CONTAINMENT`, `RECOVERY`,
`LINK`.
**IncidentLinkType:** `DETECTION`, `ASSET`, `VULN`, `CONFIG_CHANGE`.

**ReportType:** `EXEC_RISK_SUMMARY`, `ASSET_INVENTORY`, `VULN_REMEDIATION_PLAN`,
`UNAUTHORIZED_CHANGE`, `COMPLIANCE_GAP`, `IEC62443_EVIDENCE`, `NERC_CIP_EVIDENCE`,
`NIS2_READINESS`, `OTCC_READINESS`, `INCIDENT_REPORT`, `AI_DAILY_BRIEF`.
**ReportFormat:** `MARKDOWN`, `HTML`, `PDF`.

**IntegrationKind:** `SIEM_WEBHOOK`, `SPLUNK`, `SENTINEL`, `SERVICENOW`, `JIRA`,
`DEFENDER`, `OT_PLATFORM_IMPORT` (Claroty/Nozomi/Dragos), `VULN_SCANNER_IMPORT`
(Tenable/Qualys/Rapid7), `OEM_IMPORT`.
**IntegrationDirection:** `EXPORT`, `IMPORT`.

**AuditAction:** `LOGIN`, `USER_PROVISION`, `ASSET_CREATE/UPDATE/DELETE/IMPORT/EXPORT`,
`CONFIG_BASELINE`, `CONFIG_SNAPSHOT`, `CHANGE_DISPOSITION`, `DETECTION_STATUS_CHANGE`,
`VULN_RISK_ACCEPTANCE`, `VULN_STATUS_CHANGE`, `COMPLIANCE_EVIDENCE_UPLOAD`,
`CONTROL_STATUS_CHANGE`, `INCIDENT_CREATE/UPDATE`, `AI_PROMPT`, `AI_RESPONSE`,
`REPORT_GENERATE`, `INTEGRATION_EXPORT/IMPORT`, `INGEST`, `RISK_RECOMPUTE`.

**SourceType** (ingestion): `PCAP_META`, `NETWORK_OBS`, `SYSLOG`, `EDR`, `FIREWALL`,
`MANUAL`, `SEED`.
**EventKind:** `ASSET_OBSERVED`, `COMM_OBSERVED`, `REMOTE_ACCESS`, `EDR_ALERT`,
`FIREWALL_EVENT`, `CONFIG_HINT`, `USB_EVENT`.

**AIProviderKind:** `local_foundation_sec`, `openai_compatible`, `mock`.
**AIUseCase:** `CHAT`, `ASSET_RISK`, `DAILY_BRIEF`, `VULN_IMPACT`, `REMEDIATION_PLAN`,
`COMPLIANCE_GAP`, `CONFIG_CHANGE`, `INCIDENT_SUMMARY`, `EXEC_SUMMARY`,
`ALERT_TRANSLATE`, `NEXT_ACTION`, `EVIDENCE_MAP`.
**MessageRole:** `system`, `user`, `assistant`.
