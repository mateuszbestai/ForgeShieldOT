# ForgeShield OT — Seed Scenario

The demo seed creates a realistic, fully-linked OT environment so every feature has
meaningful data on first run. **Everything is simulated** and flagged `is_demo=True`.
The loader is **fully idempotent** — re-running it never duplicates rows.

Code: `backend/app/seed/loaders.py` (`seed_all`), `backend/app/seed/cli.py`
(entrypoint), `backend/app/seed/supabase_users.py` (auth-user provisioning).

Idempotency is achieved with a `get_or_create` helper keyed on each model's natural key
(e.g. `site.code`, `asset.asset_tag`, `vuln.cve_id`, `framework.key`,
`(framework_id, control_ref)`, `incident.title` / `reference`, `user.supabase_id`).

---

## 1. Two demo sites

| Code | Name | Industry | Location | Notes |
|------|------|----------|----------|-------|
| `ENERGY` | **Helios Solar & Battery Plant** | Energy | Arizona, US | Utility-scale solar + battery energy storage facility. |
| `AUTO` | **Apex Automotive Assembly** | Automotive manufacturing | Michigan, US | Body-in-white and final-assembly automotive line. |

Each site has 4 Purdue zones (L1 control, L2 supervisory, L3 site-ops, L3.5 DMZ); the
L3.5 DMZ zones are internet-exposed and IT-reachable.

---

## 2. Assets (17)

### Site 1 — ENERGY (9 assets)

| Asset tag | Type | Vendor / model | Purdue | Criticality | Notable posture |
|-----------|------|----------------|:------:|-------------|-----------------|
| `ENERGY-SCADA-01` | SCADA_SERVER | GE iFIX / Win Server 2019 | L2 | HIGH | IT-reachable; outdated patch. Target of RDP-from-unapproved detection. |
| `ENERGY-HIST-01` | HISTORIAN | OSIsoft PI Server / Win Server 2016 | L3 | MEDIUM | IT-reachable. |
| `ENERGY-EWS-01` | ENG_WORKSTATION | TIA Portal / Win 10 LTSC | L3 | HIGH | EW→PLC links to S7 + Modicon; USB-insertion detection. |
| `ENERGY-PLC-S7-01` | PLC | Siemens S7-1500 | L1 | SAFETY_CRITICAL | **No owner** (intentional demo gap); open KEV-adjacent S7 RCE; unauthorized logic change. |
| `ENERGY-PLC-MOD-01` | PLC | Schneider Modicon M580 | L1 | HIGH | Modbus auth flaw. |
| `ENERGY-OPCUA-01` | OEM_VENDOR_SYSTEM | Kepware KEPServerEX | L2 | MEDIUM | OPC UA cert-validation flaw. |
| `ENERGY-FW-01` | NETWORK_DEVICE | Fortinet FortiGate 100F | L3 | HIGH | Internet- + IT-reachable; **KEV** FortiGate SSL-VPN RCE; firewall-exposure detection. |
| `ENERGY-RAGW-01` | REMOTE_ACCESS_GATEWAY | Cisco ASA | L3 | HIGH | Internet-reachable, remote access enabled; **KEV** FortiGate vuln linked. |
| `ENERGY-HMI-01` | HMI | Siemens WinCC / Win 10 IoT | L2 | HIGH | Endpoint protection **unhealthy**; malware detection. |

### Site 2 — AUTO (8 assets)

| Asset tag | Type | Vendor / model | Purdue | Criticality | Notable posture |
|-----------|------|----------------|:------:|-------------|-----------------|
| `AUTO-PLC-CL-01` | PLC | Rockwell ControlLogix 1756-L85E | L1 | HIGH | EtherNet/IP DoS vuln; EW→PLC link. |
| `AUTO-HMI-01` | HMI | Rockwell PanelView Plus 7 | L2 | MEDIUM | New-device-in-zone detection target. |
| `AUTO-MES-01` | OEM_VENDOR_SYSTEM | Siemens Opcenter MES / Win Server 2019 | L3 | MEDIUM | IT-reachable; current patch. |
| `AUTO-ROBOT-01` | OEM_VENDOR_SYSTEM | FANUC R-30iB Plus | L1 | HIGH | EtherNet/IP cell comms. |
| `AUTO-EWS-01` | ENG_WORKSTATION | Studio 5000 / Win 10 | L3 | HIGH | EW→PLC link to ControlLogix. |
| `AUTO-WINSRV-01` | SCADA_SERVER | HPE / **Windows Server 2012 (EOL)** | L3 | HIGH | **Unsupported/EOL**, no backup, **KEV** SMBv1 RCE; unsupported-OS + KEV-exposure detections. |
| `AUTO-SW-01` | NETWORK_DEVICE | Cisco IE-4000 | L2 | MEDIUM | Outdated firmware. |
| `AUTO-SIS-01` | SAFETY_SIS | Rockwell GuardLogix 1756-L84ES | L1 | SAFETY_CRITICAL | Safety PLC; current patch. |

The seed also creates **12 protocol observations** (Modbus, S7comm, OPC UA, EtherNet/IP,
PROFINET, RDP, HTTPS, SMB) and **9 asset relationships**, including EW→PLC links, a
remote-access path, an internet-exposed firewall→gateway path, and one **unknown** comm
path into the L2 automotive zone (driving the new-device scenario).

---

## 3. Vulnerabilities (7 demo CVEs; 2 are CISA KEV)

| CVE (DEMO) | Title | CVSS | KEV | Affects |
|------------|-------|:----:|:---:|---------|
| `CVE-2024-50001` | Siemens SIMATIC S7-1500 RCE | 9.8 | — | `ENERGY-PLC-S7-01` |
| `CVE-2024-50002` | Rockwell ControlLogix DoS | 8.6 | — | `AUTO-PLC-CL-01`, `AUTO-SIS-01` |
| `CVE-2024-50003` | Schneider Modicon M580 improper auth | 9.1 | — | `ENERGY-PLC-MOD-01` |
| `CVE-2024-50004` | Windows Server SMBv1 RCE | 9.8 | **KEV** | `AUTO-WINSRV-01` |
| `CVE-2024-50005` | OPC UA cert-validation bypass | 7.4 | — | `ENERGY-OPCUA-01` |
| `CVE-2024-50006` | FortiGate SSL-VPN pre-auth RCE | 9.8 | **KEV** | `ENERGY-FW-01`, `ENERGY-RAGW-01` |
| `CVE-2024-50007` | OSIsoft PI Server info disclosure | 6.5 | — | `ENERGY-HIST-01` |

Each carries vendor/product, affected versions, remediation, workaround, patch risk
(incl. `REQUIRES_OUTAGE`), required downtime, OT compensating controls, and safety
impact. Asset links are created as `OPEN` `AssetVulnerability` rows.

---

## 4. Detections (8)

`OUT_OF_WINDOW_CHANGE` (S7-1500), `MALWARE` (WinCC HMI), `UNSUPPORTED_OS`
(`AUTO-WINSRV-01`), `KEV_EXPOSURE` (`AUTO-WINSRV-01`), `NEW_DEVICE_IN_ZONE`
(`AUTO-HMI-01`), `RDP_FROM_UNAPPROVED` (`ENERGY-SCADA-01`), `USB_INSERTION`
(`ENERGY-EWS-01`), and `FIREWALL_EXPOSURE` (`ENERGY-FW-01`). Each has typed evidence
records (hash, network, config, USB, log).

---

## 5. Incidents (5 — one per headline scenario)

References are auto-numbered `INC-<year>-NNNN`. Each gets a 3-event timeline plus links
to its driving detection and asset, and a MITRE ATT&CK for ICS technique mapping.

| Title | Severity | Status | Site | ATT&CK ICS |
|-------|----------|--------|------|:----------:|
| Unauthorized PLC logic change on Siemens S7-1500 | HIGH | INVESTIGATING | ENERGY | T0889 |
| Malware detected on Siemens WinCC HMI | CRITICAL | OPEN | ENERGY | T0863 |
| Unsupported Windows Server with known-exploited vulnerability | CRITICAL | OPEN | AUTO | T0866 |
| New unknown device in Level-2 automotive zone | MEDIUM | INVESTIGATING | AUTO | T0846 |
| Remote access from unapproved source to SCADA server | HIGH | INVESTIGATING | ENERGY | T0822 |

A config-change pair is also seeded for the S7-1500: an **approved baseline** snapshot
and an **observed** snapshot, yielding one `UNAUTHORIZED` `ConfigChange` (extra program
block downloaded outside any approved window).

---

## 6. Compliance (9 frameworks, 34 controls, 5 demo gaps)

| FrameworkKey | Name | Version | Placeholder? |
|--------------|------|---------|:------------:|
| `IEC_62443` | IEC 62443 | 2018 | — |
| `NERC_CIP` | NERC CIP | v7 | — |
| `TSA` | TSA Security Directive Pipeline | 2022 | — |
| `NIS2` | EU NIS2 Directive | 2022/2555 | — |
| `NCA_OTCC` | NCA OT Cybersecurity Controls (Saudi) | 1.0 | — |
| `CISA_CPG` | CISA Cross-Sector CPGs | 2023 | — |
| `ISO_27001` | ISO/IEC 27001 | 2022 | **placeholder** |
| `NIST_800_82` | NIST SP 800-82 | Rev 3 | **placeholder** |
| `MITRE_ATTCK_ICS` | MITRE ATT&CK for ICS | v14 | — |

Controls are seeded for 7 of the frameworks (the two placeholder frameworks ship with no
controls), totalling **34 controls** across a mix of `IMPLEMENTED`, `PARTIAL`, and
`NOT_STARTED` statuses. The **5 demo gaps** (`NOT_STARTED`/`PARTIAL` controls with
supporting evidence) cover: configuration change management, OT/IT network segmentation,
vulnerability-remediation procedure, incident-response test evidence, and OT asset
ownership (tied to the ownerless S7-1500). Two evidence rows are **auto-linked** to
assets (the ownerless S7-1500 → NCA `OTCC-1-1`; the EOL Windows server → CISA `CPG 2.E`),
plus positive manual evidence (e.g. an IEC 62443 backup-test report).

The seed also provisions a demo AI conversation (with audit logs), default mock
integrations, then runs `risk_engine.recompute_all` so every asset has a populated
score/band.

---

## 7. Demo user accounts

The local mirror `User` rows are always seeded. The matching **Supabase auth users** are
provisioned (idempotently) **only when** `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` are
configured; otherwise provisioning is a logged no-op (local rows are still created). The
shared password comes from `DEMO_USER_PASSWORD` (default `Demo!ForgeShield123`), and the
RBAC role is written into Supabase `app_metadata.role`.

| Email | Role |
|-------|------|
| `admin@forgeshield.local` | `ADMIN` |
| `engineer@forgeshield.local` | `OT_SECURITY_ENGINEER` |
| `analyst@forgeshield.local` | `SOC_ANALYST` |
| `compliance@forgeshield.local` | `COMPLIANCE_OFFICER` |
| `viewer@forgeshield.local` | `VIEWER` |

---

## 8. (Re)seeding

Seeding is **idempotent** — safe to run repeatedly.

- **Make target:** `make seed` → runs `python -m app.seed.cli` inside the backend
  container.
- **Direct:** `python -m app.seed.cli` (from the backend). Phase 1 seeds the local DB;
  Phase 2 provisions Supabase auth users (self-guards on missing config). Phase 1
  failures do not block by Supabase issues, and a Supabase failure never fails the run.
- **On startup:** with `SEED_ON_START=true`, the backend entrypoint loads the demo data
  automatically on boot.
- **Fresh start:** `make reset` tears down the stack, deletes the Postgres volume, and
  rebuilds — yielding a clean reseed.

The CLI prints a JSON summary of created counts (sites, zones, assets, vulns,
detections, incidents, compliance frameworks/controls/evidence, integrations, AI
records, and assets recomputed).
