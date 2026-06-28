"""Idempotent demo seed data for ForgeShield OT.

Everything created here is flagged ``is_demo=True`` (where the model supports it)
so the UI and AI layer can clearly label simulated data. The loader is fully
idempotent: re-running it does NOT duplicate rows. Idempotency is achieved with a
``get_or_create`` helper keyed on each model's natural key:

    site.code, zone(site_id,name), asset.asset_tag, vuln.cve_id,
    framework.key, control(framework_id, control_ref), incident.reference,
    integration(kind,name), user.supabase_id, role.name.

Data is built directly through the SQLModel models, plus two helper services
(``detection_service.create_from_template`` and
``integration_service.ensure_default_integrations``). Risk scores are populated at
the end via ``risk_engine.recompute_all``.
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, TypeVar

from sqlmodel import Session, SQLModel, select

from app.core.enums import (
    AIUseCase,
    AssetType,
    AuditAction,
    ChangeDisposition,
    Confidence,
    ControlStatus,
    Criticality,
    DetectionType,
    DiscoverySource,
    EvidenceKind,
    EvidenceSourceType,
    FrameworkKey,
    ImpactLevel,
    IncidentLinkType,
    IncidentStatus,
    MatchBasis,
    MessageRole,
    NormalizedProtocol,
    PatchRisk,
    PatchStatus,
    ProtocolDirection,
    PurdueLevel,
    RelationshipType,
    RoleName,
    Severity,
    SnapshotKind,
    SourceType,
    SupportStatus,
    TimelineEventKind,
    VulnRemediationStatus,
)
from app.models.ai import AIConversation, AIMessage
from app.models.asset import Asset, AssetRelationship, ProtocolObservation
from app.models.audit import AuditLog
from app.models.base import utcnow
from app.models.compliance import (
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)
from app.models.config_mgmt import ConfigChange, ConfigSnapshot
from app.models.incident import Incident, IncidentLink, IncidentTimelineEvent
from app.models.org import Site, Zone
from app.models.user import Role, User
from app.models.vuln import AssetVulnerability, Vulnerability
from app.schemas.detection import EvidenceCreate
from app.services import detection_service, integration_service
from app.services.risk_engine import recompute_all

ModelT = TypeVar("ModelT", bound=SQLModel)


# --------------------------------------------------------------------------- #
# get-or-create helper (the heart of idempotency)
# --------------------------------------------------------------------------- #
def get_or_create(
    session: Session,
    model: type[ModelT],
    defaults: dict[str, Any] | None = None,
    **natural_key: Any,
) -> tuple[ModelT, bool]:
    """Fetch a row by its natural key or create it.

    Returns ``(obj, created)``. The natural key columns identify an existing row;
    ``defaults`` supplies the remaining columns only on creation (an existing row
    is never mutated, keeping re-runs side-effect free).
    """
    stmt = select(model)
    for field, value in natural_key.items():
        stmt = stmt.where(getattr(model, field) == value)
    existing = session.exec(stmt).first()
    if existing is not None:
        return existing, False

    params: dict[str, Any] = {**natural_key, **(defaults or {})}
    obj = model(**params)
    session.add(obj)
    session.flush()  # assign PK / FK without ending the transaction
    return obj, True


# --------------------------------------------------------------------------- #
# Users / roles
# --------------------------------------------------------------------------- #
_DEMO_USERS: list[tuple[str, str, RoleName, str]] = [
    ("demo-admin", "admin@forgeshield.local", RoleName.ADMIN, "Demo Admin"),
    (
        "demo-engineer",
        "engineer@forgeshield.local",
        RoleName.OT_SECURITY_ENGINEER,
        "Demo OT Security Engineer",
    ),
    ("demo-analyst", "analyst@forgeshield.local", RoleName.SOC_ANALYST, "Demo SOC Analyst"),
    (
        "demo-compliance",
        "compliance@forgeshield.local",
        RoleName.COMPLIANCE_OFFICER,
        "Demo Compliance Officer",
    ),
    ("demo-viewer", "viewer@forgeshield.local", RoleName.VIEWER, "Demo Viewer"),
]


def _seed_users_roles(session: Session) -> dict[str, int]:
    counts = {"roles": 0, "users": 0}
    # Role catalog (one per RoleName).
    for role_name in RoleName:
        _, created = get_or_create(
            session,
            Role,
            defaults={"description": f"{role_name.value} role"},
            name=role_name,
        )
        counts["roles"] += int(created)

    # Local mirror User rows (real auth users are provisioned via supabase_users.py).
    for supabase_id, email, role, full_name in _DEMO_USERS:
        _, created = get_or_create(
            session,
            User,
            defaults={"email": email, "role": role, "full_name": full_name, "is_active": True},
            supabase_id=supabase_id,
        )
        counts["users"] += int(created)
    session.commit()
    return counts


def _admin_user(session: Session) -> User | None:
    return session.exec(select(User).where(User.supabase_id == "demo-admin")).first()


# --------------------------------------------------------------------------- #
# Sites / zones
# --------------------------------------------------------------------------- #
def _seed_sites(session: Session) -> dict[str, Site]:
    energy, _ = get_or_create(
        session,
        Site,
        defaults={
            "name": "Helios Solar & Battery Plant",
            "location": "Arizona, US",
            "industry": "Energy",
            "description": "Utility-scale solar + battery energy storage facility (DEMO).",
            "is_demo": True,
        },
        code="ENERGY",
    )
    auto, _ = get_or_create(
        session,
        Site,
        defaults={
            "name": "Apex Automotive Assembly",
            "location": "Michigan, US",
            "industry": "Automotive manufacturing",
            "description": "Body-in-white and final-assembly automotive line (DEMO).",
            "is_demo": True,
        },
        code="AUTO",
    )
    session.commit()
    return {"ENERGY": energy, "AUTO": auto}


def _seed_zones(session: Session, sites: dict[str, Site]) -> dict[str, Zone]:
    energy = sites["ENERGY"]
    auto = sites["AUTO"]
    specs: list[tuple[str, str, PurdueLevel, bool, bool, str]] = [
        # site_code, name, purdue, internet_exposed, it_reachable, conduit
        ("ENERGY", "ENERGY-L1-Control", PurdueLevel.L1, False, False, "ENERGY-L1<->L2"),
        ("ENERGY", "ENERGY-L2-Supervisory", PurdueLevel.L2, False, False, "ENERGY-L2<->L3"),
        ("ENERGY", "ENERGY-L3-SiteOps", PurdueLevel.L3, False, True, "ENERGY-L3<->L3.5"),
        ("ENERGY", "ENERGY-L3.5-DMZ", PurdueLevel.L3, True, True, "ENERGY-L3.5<->IT"),
        ("AUTO", "AUTO-L1-Control", PurdueLevel.L1, False, False, "AUTO-L1<->L2"),
        ("AUTO", "AUTO-L2-Supervisory", PurdueLevel.L2, False, False, "AUTO-L2<->L3"),
        ("AUTO", "AUTO-L3-SiteOps", PurdueLevel.L3, False, True, "AUTO-L3<->L3.5"),
        ("AUTO", "AUTO-L3.5-DMZ", PurdueLevel.L3, True, True, "AUTO-L3.5<->IT"),
    ]
    site_by_code = {"ENERGY": energy, "AUTO": auto}
    zones: dict[str, Zone] = {}
    for site_code, name, purdue, exposed, it_reach, conduit in specs:
        site = site_by_code[site_code]
        zone, _ = get_or_create(
            session,
            Zone,
            defaults={
                "purdue_level": purdue,
                "internet_exposed": exposed,
                "it_reachable": it_reach,
                "conduit": conduit,
                "description": f"{name} zone (DEMO).",
                "is_demo": True,
            },
            site_id=site.id,
            name=name,
        )
        zones[name] = zone
    session.commit()
    return zones


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #
def _seed_assets(
    session: Session, sites: dict[str, Site], zones: dict[str, Zone]
) -> dict[str, Asset]:
    energy = sites["ENERGY"]
    auto = sites["AUTO"]

    # asset_tag -> field dict. zone_name resolved to zone_id below.
    specs: dict[str, dict[str, Any]] = {
        # ----------------------- Site 1: ENERGY -----------------------
        "ENERGY-SCADA-01": dict(
            site=energy, zone="ENERGY-L2-Supervisory", hostname="scada01",
            ip_address="10.20.2.10", mac_address="00:1B:1B:00:20:10",
            vendor="Microsoft", model="GE iFIX SCADA", software_version="iFIX 6.5",
            os_name="Windows Server 2019", asset_type=AssetType.SCADA_SERVER,
            purdue_level=PurdueLevel.L2, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.MEDIUM, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True, it_reachable=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=True,
            owner="OT Operations",
        ),
        "ENERGY-HIST-01": dict(
            site=energy, zone="ENERGY-L3-SiteOps", hostname="hist01",
            ip_address="10.20.3.20", mac_address="00:1B:1B:00:20:20",
            vendor="OSIsoft", model="PI Server", software_version="PI Server 2018 SP3",
            os_name="Windows Server 2016", asset_type=AssetType.HISTORIAN,
            purdue_level=PurdueLevel.L3, criticality=Criticality.MEDIUM,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True, it_reachable=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=True,
            owner="OT Operations",
        ),
        "ENERGY-EWS-01": dict(
            site=energy, zone="ENERGY-L3-SiteOps", hostname="ews01",
            ip_address="10.20.3.30", mac_address="00:1B:1B:00:20:30",
            vendor="Microsoft", model="Dell Precision", software_version="TIA Portal V17",
            os_name="Windows 10 Enterprise LTSC", asset_type=AssetType.ENG_WORKSTATION,
            purdue_level=PurdueLevel.L3, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.MEDIUM, business_impact=ImpactLevel.MEDIUM,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.CURRENT,
            backup_available=True, config_available=True, it_reachable=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=True,
            owner="OT Security Engineering",
        ),
        "ENERGY-PLC-S7-01": dict(
            site=energy, zone="ENERGY-L1-Control", hostname="plc-s7-01",
            ip_address="10.20.1.40", mac_address="00:1B:1B:00:20:40",
            vendor="Siemens", model="SIMATIC S7-1500 CPU 1518-4 PN/DP",
            firmware_version="V2.8", asset_type=AssetType.PLC,
            purdue_level=PurdueLevel.L1, criticality=Criticality.SAFETY_CRITICAL,
            safety_impact=ImpactLevel.HIGH, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            owner=None,  # intentional demo gap: critical PLC with no owner
        ),
        "ENERGY-PLC-MOD-01": dict(
            site=energy, zone="ENERGY-L1-Control", hostname="plc-mod-01",
            ip_address="10.20.1.41", mac_address="00:1B:1B:00:20:41",
            vendor="Schneider Electric", model="Modicon M580 BMEP584040",
            firmware_version="SV3.20", asset_type=AssetType.PLC,
            purdue_level=PurdueLevel.L1, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.HIGH, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            owner="OT Operations",
        ),
        "ENERGY-OPCUA-01": dict(
            site=energy, zone="ENERGY-L2-Supervisory", hostname="opcua01",
            ip_address="10.20.2.50", mac_address="00:1B:1B:00:20:50",
            vendor="Kepware", model="KEPServerEX OPC UA", software_version="6.11",
            os_name="Windows Server 2019", asset_type=AssetType.OEM_VENDOR_SYSTEM,
            purdue_level=PurdueLevel.L2, criticality=Criticality.MEDIUM,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.MEDIUM,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True, it_reachable=True,
            owner="OT Operations",
        ),
        "ENERGY-FW-01": dict(
            site=energy, zone="ENERGY-L3.5-DMZ", hostname="fw01",
            ip_address="10.20.35.1", mac_address="00:1B:1B:00:20:F1",
            vendor="Fortinet", model="FortiGate 100F", firmware_version="FortiOS 7.0.5",
            asset_type=AssetType.NETWORK_DEVICE,
            purdue_level=PurdueLevel.L3, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            internet_reachable=True, it_reachable=True,
            owner="Network Engineering",
        ),
        "ENERGY-RAGW-01": dict(
            site=energy, zone="ENERGY-L3.5-DMZ", hostname="ragw01",
            ip_address="10.20.35.5", mac_address="00:1B:1B:00:20:F5",
            vendor="Cisco", model="Secure Remote Access Gateway",
            software_version="ASA 9.16", asset_type=AssetType.REMOTE_ACCESS_GATEWAY,
            purdue_level=PurdueLevel.L3, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            internet_reachable=True, it_reachable=True, remote_access_enabled=True,
            owner="OT Security Engineering",
        ),
        "ENERGY-HMI-01": dict(
            site=energy, zone="ENERGY-L2-Supervisory", hostname="hmi01",
            ip_address="10.20.2.60", mac_address="00:1B:1B:00:20:60",
            vendor="Siemens", model="SIMATIC WinCC HMI", software_version="WinCC V7.5",
            os_name="Windows 10 IoT Enterprise", asset_type=AssetType.HMI,
            purdue_level=PurdueLevel.L2, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.MEDIUM, business_impact=ImpactLevel.MEDIUM,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=False,
            owner="OT Operations",
        ),
        # ----------------------- Site 2: AUTO -----------------------
        "AUTO-PLC-CL-01": dict(
            site=auto, zone="AUTO-L1-Control", hostname="plc-cl-01",
            ip_address="10.30.1.40", mac_address="00:1B:1B:00:30:40",
            vendor="Rockwell Automation", model="ControlLogix 1756-L85E",
            firmware_version="V32.011", asset_type=AssetType.PLC,
            purdue_level=PurdueLevel.L1, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.HIGH, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            owner="Plant Controls",
        ),
        "AUTO-HMI-01": dict(
            site=auto, zone="AUTO-L2-Supervisory", hostname="auto-hmi01",
            ip_address="10.30.2.60", mac_address="00:1B:1B:00:30:60",
            vendor="Rockwell Automation", model="PanelView Plus 7",
            software_version="FactoryTalk View ME 12",
            os_name="Windows 10 IoT Enterprise", asset_type=AssetType.HMI,
            purdue_level=PurdueLevel.L2, criticality=Criticality.MEDIUM,
            safety_impact=ImpactLevel.MEDIUM, business_impact=ImpactLevel.MEDIUM,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=True,
            owner="Plant Controls",
        ),
        "AUTO-MES-01": dict(
            site=auto, zone="AUTO-L3-SiteOps", hostname="mes01",
            ip_address="10.30.3.70", mac_address="00:1B:1B:00:30:70",
            vendor="Siemens", model="Opcenter MES Connector", software_version="2022",
            os_name="Windows Server 2019", asset_type=AssetType.OEM_VENDOR_SYSTEM,
            purdue_level=PurdueLevel.L3, criticality=Criticality.MEDIUM,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.CURRENT,
            backup_available=True, config_available=True, it_reachable=True,
            owner="Manufacturing IT",
        ),
        "AUTO-ROBOT-01": dict(
            site=auto, zone="AUTO-L1-Control", hostname="robot-ctrl-01",
            ip_address="10.30.1.45", mac_address="00:1B:1B:00:30:45",
            vendor="FANUC", model="R-30iB Plus Robot Controller",
            firmware_version="V9.30", asset_type=AssetType.OEM_VENDOR_SYSTEM,
            purdue_level=PurdueLevel.L1, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.HIGH, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            owner="Plant Controls",
        ),
        "AUTO-EWS-01": dict(
            site=auto, zone="AUTO-L3-SiteOps", hostname="auto-ews01",
            ip_address="10.30.3.30", mac_address="00:1B:1B:00:30:30",
            vendor="Microsoft", model="Dell Precision",
            software_version="Studio 5000 v32", os_name="Windows 10 Enterprise",
            asset_type=AssetType.ENG_WORKSTATION,
            purdue_level=PurdueLevel.L3, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.MEDIUM, business_impact=ImpactLevel.MEDIUM,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.CURRENT,
            backup_available=True, config_available=True, it_reachable=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=True,
            owner="Plant Controls",
        ),
        "AUTO-WINSRV-01": dict(
            site=auto, zone="AUTO-L3-SiteOps", hostname="auto-winsrv01",
            ip_address="10.30.3.80", mac_address="00:1B:1B:00:30:80",
            vendor="Microsoft", model="HPE ProLiant DL360",
            software_version="Line data server",
            os_name="Windows Server 2012",  # UNSUPPORTED / EOL endpoint
            asset_type=AssetType.SCADA_SERVER,
            purdue_level=PurdueLevel.L3, criticality=Criticality.HIGH,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.UNSUPPORTED, patch_status=PatchStatus.EOL,
            backup_available=False, config_available=False, it_reachable=True,
            endpoint_protection_installed=True, endpoint_protection_healthy=False,
            owner="Manufacturing IT",
        ),
        "AUTO-SW-01": dict(
            site=auto, zone="AUTO-L2-Supervisory", hostname="auto-sw01",
            ip_address="10.30.2.1", mac_address="00:1B:1B:00:30:01",
            vendor="Cisco", model="IE-4000 Industrial Switch",
            firmware_version="IOS 15.2(7)E", asset_type=AssetType.NETWORK_DEVICE,
            purdue_level=PurdueLevel.L2, criticality=Criticality.MEDIUM,
            safety_impact=ImpactLevel.LOW, business_impact=ImpactLevel.MEDIUM,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.OUTDATED,
            backup_available=True, config_available=True,
            owner="Network Engineering",
        ),
        "AUTO-SIS-01": dict(
            site=auto, zone="AUTO-L1-Control", hostname="auto-sis01",
            ip_address="10.30.1.50", mac_address="00:1B:1B:00:30:50",
            vendor="Rockwell Automation", model="GuardLogix 1756-L84ES Safety PLC",
            firmware_version="V32.011", asset_type=AssetType.SAFETY_SIS,
            purdue_level=PurdueLevel.L1, criticality=Criticality.SAFETY_CRITICAL,
            safety_impact=ImpactLevel.HIGH, business_impact=ImpactLevel.HIGH,
            support_status=SupportStatus.SUPPORTED, patch_status=PatchStatus.CURRENT,
            backup_available=True, config_available=True,
            owner="Functional Safety",
        ),
    }

    assets: dict[str, Asset] = {}
    for tag, fields in specs.items():
        fields = dict(fields)
        site = fields.pop("site")
        zone_name = fields.pop("zone")
        zone = zones.get(zone_name)
        defaults: dict[str, Any] = {
            "site_id": site.id,
            "zone_id": zone.id if zone is not None else None,
            "discovery_source": DiscoverySource.SEED,
            "last_seen": utcnow(),
            "is_demo": True,
            **fields,
        }
        asset, _ = get_or_create(session, Asset, defaults=defaults, asset_tag=tag)
        assets[tag] = asset
    session.commit()
    return assets


# --------------------------------------------------------------------------- #
# Protocol observations + relationships
# --------------------------------------------------------------------------- #
def _seed_protocols(session: Session, assets: dict[str, Asset]) -> int:
    specs: list[tuple[str, NormalizedProtocol, int]] = [
        ("ENERGY-PLC-MOD-01", NormalizedProtocol.MODBUS_TCP, 502),
        ("ENERGY-PLC-S7-01", NormalizedProtocol.S7COMM, 102),
        ("ENERGY-OPCUA-01", NormalizedProtocol.OPC_UA, 4840),
        ("ENERGY-SCADA-01", NormalizedProtocol.OPC_UA, 4840),
        ("ENERGY-HMI-01", NormalizedProtocol.PROFINET, None),
        ("ENERGY-RAGW-01", NormalizedProtocol.RDP, 3389),
        ("ENERGY-HIST-01", NormalizedProtocol.HTTPS, 443),
        ("AUTO-PLC-CL-01", NormalizedProtocol.ETHERNET_IP_CIP, 44818),
        ("AUTO-SIS-01", NormalizedProtocol.ETHERNET_IP_CIP, 44818),
        ("AUTO-ROBOT-01", NormalizedProtocol.ETHERNET_IP_CIP, 44818),
        ("AUTO-MES-01", NormalizedProtocol.OPC_UA, 4840),
        ("AUTO-WINSRV-01", NormalizedProtocol.SMB, 445),
    ]
    created = 0
    for tag, proto, port in specs:
        asset = assets.get(tag)
        if asset is None:
            continue
        _, was_created = get_or_create(
            session,
            ProtocolObservation,
            defaults={
                "port": port,
                "direction": ProtocolDirection.BIDIRECTIONAL,
                "observation_count": 42,
                "first_seen": utcnow() - timedelta(days=30),
                "last_seen": utcnow(),
                "source": SourceType.SEED,
                "is_demo": True,
            },
            asset_id=asset.id,
            protocol=proto,
        )
        created += int(was_created)
    session.commit()
    return created


def _seed_relationships(session: Session, assets: dict[str, Asset]) -> int:
    # (src_tag, dst_tag, protocol, type, is_internet_path, is_unknown)
    specs: list[tuple[str, str, NormalizedProtocol, RelationshipType, bool, bool]] = [
        # Engineering workstation -> Siemens PLC over S7comm (EW_TO_PLC).
        ("ENERGY-EWS-01", "ENERGY-PLC-S7-01", NormalizedProtocol.S7COMM,
         RelationshipType.EW_TO_PLC, False, False),
        # Engineering workstation -> Modicon over Modbus (EW_TO_PLC).
        ("ENERGY-EWS-01", "ENERGY-PLC-MOD-01", NormalizedProtocol.MODBUS_TCP,
         RelationshipType.EW_TO_PLC, False, False),
        # Remote access gateway -> SCADA server over RDP (REMOTE_ACCESS).
        ("ENERGY-RAGW-01", "ENERGY-SCADA-01", NormalizedProtocol.RDP,
         RelationshipType.REMOTE_ACCESS, False, False),
        # Firewall internet-exposed path to the remote access gateway.
        ("ENERGY-FW-01", "ENERGY-RAGW-01", NormalizedProtocol.HTTPS,
         RelationshipType.MANAGEMENT, True, False),
        # SCADA -> Modicon comm (Modbus).
        ("ENERGY-SCADA-01", "ENERGY-PLC-MOD-01", NormalizedProtocol.MODBUS_TCP,
         RelationshipType.COMM, False, False),
        # OPC UA server <- SCADA.
        ("ENERGY-SCADA-01", "ENERGY-OPCUA-01", NormalizedProtocol.OPC_UA,
         RelationshipType.COMM, False, False),
        # AUTO: engineering workstation -> ControlLogix over EtherNet/IP (EW_TO_PLC).
        ("AUTO-EWS-01", "AUTO-PLC-CL-01", NormalizedProtocol.ETHERNET_IP_CIP,
         RelationshipType.EW_TO_PLC, False, False),
        # AUTO: ControlLogix <-> robot controller.
        ("AUTO-PLC-CL-01", "AUTO-ROBOT-01", NormalizedProtocol.ETHERNET_IP_CIP,
         RelationshipType.COMM, False, False),
        # AUTO: unknown comm path into Level-2 HMI (drives NEW_DEVICE/unknown scenario).
        ("AUTO-WINSRV-01", "AUTO-HMI-01", NormalizedProtocol.SMB,
         RelationshipType.COMM, False, True),
    ]
    created = 0
    for src_tag, dst_tag, proto, rel_type, internet_path, unknown in specs:
        src = assets.get(src_tag)
        dst = assets.get(dst_tag)
        if src is None or dst is None:
            continue
        _, was_created = get_or_create(
            session,
            AssetRelationship,
            defaults={
                "relationship_type": rel_type,
                "is_internet_path": internet_path,
                "is_unknown": unknown,
                "first_seen": utcnow() - timedelta(days=20),
                "last_seen": utcnow(),
                "observation_count": 17,
                "is_demo": True,
            },
            src_asset_id=src.id,
            dst_asset_id=dst.id,
            protocol=proto,
        )
        created += int(was_created)
    session.commit()
    return created


# --------------------------------------------------------------------------- #
# Vulnerabilities + asset links
# --------------------------------------------------------------------------- #
def _seed_vulns(session: Session, assets: dict[str, Asset]) -> dict[str, int]:
    # cve_id -> (vuln fields, list of asset_tags to link)
    specs: list[tuple[str, dict[str, Any], list[str]]] = [
        (
            "CVE-2024-50001",
            dict(
                title="(DEMO) Siemens SIMATIC S7-1500 remote code execution",
                description="A flaw in the web server of affected SIMATIC S7-1500 CPUs "
                "could allow remote code execution (DEMO).",
                cvss_base=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss=0.42, known_exploited=False, vendor="Siemens",
                product="SIMATIC S7-1500", affected_versions=["< V3.0"],
                remediation="Update CPU firmware to V3.0 or later.",
                workaround="Disable the integrated web server; restrict TCP/102 access.",
                patch_available=True, patch_risk=PatchRisk.REQUIRES_OUTAGE,
                required_downtime="Process outage required for CPU firmware update.",
                ot_compensating_controls=[
                    "Restrict S7comm to engineering hosts via ACL",
                    "Passive monitoring of controller programming",
                ],
                safety_impact=ImpactLevel.HIGH,
            ),
            ["ENERGY-PLC-S7-01"],
        ),
        (
            "CVE-2024-50002",
            dict(
                title="(DEMO) Rockwell ControlLogix denial of service",
                description="Malformed CIP packets can cause affected Logix controllers "
                "to fault into a major non-recoverable state (DEMO).",
                cvss_base=8.6, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                epss=0.18, known_exploited=False, vendor="Rockwell Automation",
                product="ControlLogix 1756", affected_versions=["V32.011", "< V33"],
                remediation="Upgrade controller firmware to V33 or later.",
                workaround="Restrict EtherNet/IP (TCP/UDP 44818) to trusted hosts.",
                patch_available=True, patch_risk=PatchRisk.REQUIRES_OUTAGE,
                required_downtime="Controlled line stop required for firmware upgrade.",
                ot_compensating_controls=["CIP allowlist on the cell switch"],
                safety_impact=ImpactLevel.HIGH,
            ),
            ["AUTO-PLC-CL-01", "AUTO-SIS-01"],
        ),
        (
            "CVE-2024-50003",
            dict(
                title="(DEMO) Schneider Modicon M580 improper authentication",
                description="Improper authentication on the Modbus service of affected "
                "Modicon M580 controllers permits unauthenticated writes (DEMO).",
                cvss_base=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                epss=0.30, known_exploited=False, vendor="Schneider Electric",
                product="Modicon M580", affected_versions=["< SV4.10"],
                remediation="Upgrade firmware to SV4.10 and enable Modbus application password.",
                workaround="Enforce Modbus write protection; restrict TCP/502 by ACL.",
                patch_available=True, patch_risk=PatchRisk.HIGH,
                required_downtime="Brief controller restart during upgrade.",
                ot_compensating_controls=["Modbus deep-packet monitoring"],
                safety_impact=ImpactLevel.HIGH,
            ),
            ["ENERGY-PLC-MOD-01"],
        ),
        (
            "CVE-2024-50004",
            dict(
                title="(DEMO) Windows Server SMBv1 remote code execution (KEV)",
                description="A remote code execution vulnerability in the SMBv1 service of "
                "unsupported Windows Server; listed in the CISA KEV catalog (DEMO).",
                cvss_base=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss=0.94, known_exploited=True, vendor="Microsoft",
                product="Windows Server", affected_versions=["Windows Server 2012"],
                remediation="Disable SMBv1 and migrate off the unsupported OS.",
                workaround="Block TCP/445 inbound at the OT firewall; segment the host.",
                patch_available=False, patch_risk=PatchRisk.REQUIRES_OUTAGE,
                required_downtime="OS migration required (no vendor patch for EOL OS).",
                ot_compensating_controls=[
                    "Network segmentation of the line data server",
                    "Disable SMBv1",
                    "Increased endpoint monitoring",
                ],
                safety_impact=ImpactLevel.LOW,
            ),
            ["AUTO-WINSRV-01"],
        ),
        (
            "CVE-2024-50005",
            dict(
                title="(DEMO) OPC UA server certificate validation bypass",
                description="Improper certificate validation in the OPC UA server allows "
                "man-in-the-middle interception of OT telemetry (DEMO).",
                cvss_base=7.4, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                epss=0.12, known_exploited=False, vendor="Kepware",
                product="KEPServerEX OPC UA", affected_versions=["< 6.13"],
                remediation="Upgrade to KEPServerEX 6.13 and enforce certificate trust lists.",
                workaround="Pin server certificates; restrict TCP/4840 to known clients.",
                patch_available=True, patch_risk=PatchRisk.MEDIUM,
                required_downtime="Service restart during upgrade.",
                ot_compensating_controls=["TLS enforcement for OPC UA sessions"],
                safety_impact=ImpactLevel.LOW,
            ),
            ["ENERGY-OPCUA-01"],
        ),
        (
            "CVE-2024-50006",
            dict(
                title="(DEMO) FortiGate SSL-VPN pre-auth RCE (KEV)",
                description="A pre-authentication remote code execution vulnerability in the "
                "SSL-VPN of affected FortiGate firewalls; listed in CISA KEV (DEMO).",
                cvss_base=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss=0.97, known_exploited=True, vendor="Fortinet",
                product="FortiGate", affected_versions=["FortiOS 7.0.0 - 7.0.6"],
                remediation="Upgrade FortiOS to 7.0.7 or later.",
                workaround="Disable SSL-VPN until patched; restrict management to trusted IPs.",
                patch_available=True, patch_risk=PatchRisk.MEDIUM,
                required_downtime="Brief VPN outage during firmware upgrade.",
                ot_compensating_controls=[
                    "Restrict remote access source IPs",
                    "MFA on the VPN gateway",
                ],
                safety_impact=ImpactLevel.LOW,
            ),
            ["ENERGY-FW-01", "ENERGY-RAGW-01"],
        ),
        (
            "CVE-2024-50007",
            dict(
                title="(DEMO) OSIsoft PI Server information disclosure",
                description="An authenticated information-disclosure vulnerability in the "
                "PI Server data archive (historian) (DEMO).",
                cvss_base=6.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                epss=0.08, known_exploited=False, vendor="OSIsoft",
                product="PI Server", affected_versions=["< 2018 SP3 Patch 3"],
                remediation="Apply the latest PI Server patch and restrict archive access.",
                workaround="Tighten PI mappings and least-privilege archive permissions.",
                patch_available=True, patch_risk=PatchRisk.LOW,
                required_downtime="No outage required (rolling patch).",
                ot_compensating_controls=["Least-privilege PI access mappings"],
                safety_impact=ImpactLevel.NONE,
            ),
            ["ENERGY-HIST-01"],
        ),
    ]

    counts = {"vulns": 0, "links": 0}
    for cve_id, fields, asset_tags in specs:
        vuln, created = get_or_create(
            session,
            Vulnerability,
            defaults={**fields, "is_demo": True, "advisory_url": f"https://example.test/{cve_id}"},
            cve_id=cve_id,
        )
        counts["vulns"] += int(created)
        for tag in asset_tags:
            asset = assets.get(tag)
            if asset is None:
                continue
            exploit_note = (
                "Known-exploited; asset is OT-reachable."
                if fields.get("known_exploited")
                else "Reachable from adjacent OT/IT network."
            )
            _, link_created = get_or_create(
                session,
                AssetVulnerability,
                defaults={
                    "status": VulnRemediationStatus.OPEN,
                    "match_basis": MatchBasis.VENDOR_MODEL_VERSION,
                    "priority_score": int(round(fields.get("cvss_base", 0.0) * 10)),
                    "exploitability_in_context": exploit_note,
                    "asset_exposure_note": exploit_note,
                    "detected_at": utcnow() - timedelta(days=5),
                    "is_demo": True,
                },
                asset_id=asset.id,
                vuln_id=vuln.id,
            )
            counts["links"] += int(link_created)
    session.commit()
    return counts


# --------------------------------------------------------------------------- #
# Config snapshots + change (unauthorized PLC logic change)
# --------------------------------------------------------------------------- #
def _seed_config_change(session: Session, assets: dict[str, Asset]) -> dict[str, int]:
    plc = assets.get("ENERGY-PLC-S7-01")
    counts = {"snapshots": 0, "changes": 0}
    if plc is None:
        return counts

    baseline, c1 = get_or_create(
        session,
        ConfigSnapshot,
        defaults={
            "kind": SnapshotKind.PLC_PROGRAM,
            "is_baseline": True,
            "content": {
                "firmware": "V2.8",
                "logic_hash": "sha256:baseline-aaaa1111",
                "ob1_blocks": 12,
                "safety_program": "locked",
                "last_download_by": "engineer@forgeshield.local",
            },
            "content_hash": "sha256:baseline-aaaa1111",
            "captured_at": utcnow() - timedelta(days=14),
            "source": SourceType.SEED,
            "is_demo": True,
        },
        asset_id=plc.id,
        label="Approved baseline 2026-06-13",
    )
    counts["snapshots"] += int(c1)

    current, c2 = get_or_create(
        session,
        ConfigSnapshot,
        defaults={
            "kind": SnapshotKind.PLC_PROGRAM,
            "is_baseline": False,
            "content": {
                "firmware": "V2.8",
                "logic_hash": "sha256:changed-bbbb2222",
                "ob1_blocks": 13,
                "safety_program": "locked",
                "last_download_by": "unknown",
            },
            "content_hash": "sha256:changed-bbbb2222",
            "captured_at": utcnow() - timedelta(hours=6),
            "source": SourceType.SEED,
            "is_demo": True,
        },
        asset_id=plc.id,
        label="Observed snapshot 2026-06-27",
    )
    counts["snapshots"] += int(c2)

    _, c3 = get_or_create(
        session,
        ConfigChange,
        defaults={
            "from_snapshot_id": baseline.id,
            "to_snapshot_id": current.id,
            "summary": "Unauthorized PLC logic change detected on Siemens S7-1500: "
            "an additional program block was downloaded outside any approved window.",
            "diff": [
                {"field": "logic_hash", "before": "sha256:baseline-aaaa1111",
                 "after": "sha256:changed-bbbb2222"},
                {"field": "ob1_blocks", "before": 12, "after": 13},
                {"field": "last_download_by", "before": "engineer@forgeshield.local",
                 "after": "unknown"},
            ],
            "disposition": ChangeDisposition.UNAUTHORIZED,
            "within_approved_window": False,
            "detected_at": utcnow() - timedelta(hours=6),
            "is_demo": True,
        },
        asset_id=plc.id,
        change_ticket=None,
        from_snapshot_id=baseline.id,
        to_snapshot_id=current.id,
    )
    counts["changes"] += int(c3)
    session.commit()
    return counts


# --------------------------------------------------------------------------- #
# Detections (5 demo scenarios + extras)
# --------------------------------------------------------------------------- #
def _get_detection(session: Session, det_type: DetectionType, asset_id: uuid.UUID | None):
    from app.models.detection import Detection

    stmt = select(Detection).where(Detection.detection_type == det_type)
    if asset_id is not None:
        stmt = stmt.where(Detection.asset_id == asset_id)
    return session.exec(stmt).first()


def _seed_detections(session: Session, assets: dict[str, Asset]) -> dict[str, Any]:
    # (detection_type, asset_tag, evidence)
    specs: list[tuple[DetectionType, str, list[EvidenceCreate]]] = [
        (
            DetectionType.OUT_OF_WINDOW_CHANGE,
            "ENERGY-PLC-S7-01",
            [EvidenceCreate(kind=EvidenceKind.CONFIG, label="Logic hash mismatch",
                            data={"before": "sha256:baseline-aaaa1111",
                                  "after": "sha256:changed-bbbb2222"})],
        ),
        (
            DetectionType.MALWARE,
            "ENERGY-HMI-01",
            [EvidenceCreate(kind=EvidenceKind.HASH, label="Malicious file hash",
                            data={"sha256": "deadbeef" * 8, "verdict": "trojan"})],
        ),
        (
            DetectionType.UNSUPPORTED_OS,
            "AUTO-WINSRV-01",
            [EvidenceCreate(kind=EvidenceKind.LOG, label="OS end-of-support",
                            data={"os_name": "Windows Server 2012", "status": "EOL"})],
        ),
        (
            DetectionType.KEV_EXPOSURE,
            "AUTO-WINSRV-01",
            [EvidenceCreate(kind=EvidenceKind.NETWORK, label="KEV SMB exposure",
                            data={"cve": "CVE-2024-50004", "port": 445})],
        ),
        (
            DetectionType.NEW_DEVICE_IN_ZONE,
            "AUTO-HMI-01",
            [EvidenceCreate(kind=EvidenceKind.NETWORK, label="New device first seen",
                            data={"ip": "10.30.2.199", "mac": "00:1B:1B:00:30:FF",
                                  "zone": "AUTO-L2-Supervisory"})],
        ),
        (
            DetectionType.RDP_FROM_UNAPPROVED,
            "ENERGY-SCADA-01",
            [EvidenceCreate(kind=EvidenceKind.NETWORK, label="RDP from unapproved source",
                            data={"src": "203.0.113.45", "dst": "10.20.2.10", "port": 3389})],
        ),
        (
            DetectionType.USB_INSERTION,
            "ENERGY-EWS-01",
            [EvidenceCreate(kind=EvidenceKind.USB, label="USB device inserted",
                            data={"vendor_id": "0x0781", "product_id": "0x5567"})],
        ),
        (
            DetectionType.FIREWALL_EXPOSURE,
            "ENERGY-FW-01",
            [EvidenceCreate(kind=EvidenceKind.NETWORK, label="Permissive firewall rule",
                            data={"rule": "any->10.20.2.10:3389", "scope": "internet"})],
        ),
    ]

    created = 0
    detection_by_type: dict[DetectionType, uuid.UUID] = {}
    for det_type, tag, evidence in specs:
        asset = assets.get(tag)
        asset_id = asset.id if asset is not None else None
        existing = _get_detection(session, det_type, asset_id)
        if existing is not None:
            detection_by_type[det_type] = existing.id
            continue
        detection = detection_service.create_from_template(
            session,
            det_type,
            asset,
            asset.site_id if asset is not None else None,
            evidence=evidence,
            source=SourceType.SEED,
        )
        detection_by_type[det_type] = detection.id
        created += 1
    return {"created": created, "by_type": detection_by_type}


# --------------------------------------------------------------------------- #
# Incidents (5, one per demo scenario)
# --------------------------------------------------------------------------- #
def _next_incident_reference(session: Session) -> str:
    existing = session.exec(select(Incident)).all()
    year = utcnow().year
    prefix = f"INC-{year}-"
    max_n = 0
    for inc in existing:
        if inc.reference.startswith(prefix):
            try:
                max_n = max(max_n, int(inc.reference.rsplit("-", 1)[-1]))
            except ValueError:
                continue
    return f"{prefix}{max_n + 1:04d}"


def _seed_incidents(
    session: Session,
    sites: dict[str, Site],
    assets: dict[str, Asset],
    detection_by_type: dict[DetectionType, uuid.UUID],
) -> int:
    energy = sites["ENERGY"]
    auto = sites["AUTO"]

    # (stable_key_title, severity, status, site, attck, summary, asset_tag, detection_type)
    specs: list[tuple[str, Severity, IncidentStatus, Site, str, str, str, DetectionType]] = [
        (
            "Unauthorized PLC logic change on Siemens S7-1500",
            Severity.HIGH, IncidentStatus.INVESTIGATING, energy, "T0889",
            "An unauthorized program download was detected on the Siemens S7-1500 outside "
            "any approved maintenance window.",
            "ENERGY-PLC-S7-01", DetectionType.OUT_OF_WINDOW_CHANGE,
        ),
        (
            "Malware detected on Siemens WinCC HMI",
            Severity.CRITICAL, IncidentStatus.OPEN, energy, "T0863",
            "Endpoint protection flagged a malicious file on the WinCC HMI; the agent is "
            "reporting an unhealthy state.",
            "ENERGY-HMI-01", DetectionType.MALWARE,
        ),
        (
            "Unsupported Windows Server with known-exploited vulnerability",
            Severity.CRITICAL, IncidentStatus.OPEN, auto, "T0866",
            "The line data server runs unsupported Windows Server 2012 and is affected by a "
            "CISA KEV-listed SMBv1 vulnerability.",
            "AUTO-WINSRV-01", DetectionType.KEV_EXPOSURE,
        ),
        (
            "New unknown device in Level-2 automotive zone",
            Severity.MEDIUM, IncidentStatus.INVESTIGATING, auto, "T0846",
            "A previously unseen device appeared in the Level-2 supervisory zone and is not "
            "in the approved asset inventory.",
            "AUTO-HMI-01", DetectionType.NEW_DEVICE_IN_ZONE,
        ),
        (
            "Remote access from unapproved source to SCADA server",
            Severity.HIGH, IncidentStatus.INVESTIGATING, energy, "T0822",
            "An RDP session to the SCADA server originated from a source outside the approved "
            "remote-access allowlist.",
            "ENERGY-SCADA-01", DetectionType.RDP_FROM_UNAPPROVED,
        ),
    ]

    created = 0
    for title, severity, status, site, attck, summary, asset_tag, det_type in specs:
        existing = session.exec(select(Incident).where(Incident.title == title)).first()
        if existing is not None:
            continue
        reference = _next_incident_reference(session)
        incident = Incident(
            reference=reference,
            title=title,
            severity=severity,
            status=status,
            site_id=site.id,
            summary=summary,
            attck_ics_technique=attck,
            lead_owner="OT Security Engineering",
            opened_at=utcnow() - timedelta(hours=8),
            is_demo=True,
        )
        session.add(incident)
        session.flush()
        created += 1

        # Timeline events.
        base = utcnow() - timedelta(hours=8)
        events = [
            (TimelineEventKind.NOTE, "Detection raised and incident opened.", base),
            (TimelineEventKind.STATUS_CHANGE,
             f"Status set to {status.value}.", base + timedelta(hours=1)),
            (TimelineEventKind.EVIDENCE,
             "Linked detection evidence attached for triage.", base + timedelta(hours=2)),
        ]
        for kind, desc, occurred in events:
            session.add(
                IncidentTimelineEvent(
                    incident_id=incident.id,
                    kind=kind,
                    description=desc,
                    author="analyst@forgeshield.local",
                    occurred_at=occurred,
                    is_demo=True,
                )
            )

        # Links: detection + asset.
        det_id = detection_by_type.get(det_type)
        if det_id is not None:
            session.add(
                IncidentLink(
                    incident_id=incident.id,
                    link_type=IncidentLinkType.DETECTION,
                    entity_id=det_id,
                )
            )
        asset = assets.get(asset_tag)
        if asset is not None:
            session.add(
                IncidentLink(
                    incident_id=incident.id,
                    link_type=IncidentLinkType.ASSET,
                    entity_id=asset.id,
                )
            )
    session.commit()
    return created


# --------------------------------------------------------------------------- #
# Compliance frameworks / controls / evidence
# --------------------------------------------------------------------------- #
_FRAMEWORK_META: dict[FrameworkKey, dict[str, Any]] = {
    FrameworkKey.IEC_62443: dict(name="IEC 62443", version="2018",
                                 description="Industrial automation and control systems security."),
    FrameworkKey.NERC_CIP: dict(name="NERC CIP", version="v7",
                                description="Critical infrastructure protection for the bulk electric system."),
    FrameworkKey.TSA: dict(name="TSA Security Directive Pipeline", version="2022",
                           description="TSA pipeline cybersecurity requirements."),
    FrameworkKey.NIS2: dict(name="EU NIS2 Directive", version="2022/2555",
                            description="EU network and information security directive."),
    FrameworkKey.NCA_OTCC: dict(name="NCA OT Cybersecurity Controls", version="1.0",
                                description="Saudi NCA operational-technology cybersecurity controls."),
    FrameworkKey.CISA_CPG: dict(name="CISA Cross-Sector Cybersecurity Performance Goals", version="2023",
                                description="CISA baseline cybersecurity performance goals."),
    FrameworkKey.ISO_27001: dict(name="ISO/IEC 27001", version="2022",
                                 description="Information security management systems (placeholder)."),
    FrameworkKey.NIST_800_82: dict(name="NIST SP 800-82", version="Rev 3",
                                   description="Guide to OT security (placeholder)."),
    FrameworkKey.MITRE_ATTCK_ICS: dict(name="MITRE ATT&CK for ICS", version="v14",
                                       description="Adversary technique coverage mapping for ICS."),
}

_PLACEHOLDER_FRAMEWORKS = {FrameworkKey.ISO_27001, FrameworkKey.NIST_800_82}

# framework_key -> list of (control_ref, title, status, evidence_required, gap_tag)
# gap_tag links the 5 demo compliance gaps to assets/changes/incidents where applicable.
_CONTROLS: dict[FrameworkKey, list[tuple[str, str, ControlStatus, str]]] = {
    FrameworkKey.IEC_62443: [
        ("SR 1.1", "Human user identification and authentication", ControlStatus.IMPLEMENTED,
         "Identity and access management records."),
        ("SR 2.1", "Authorization enforcement", ControlStatus.PARTIAL,
         "Access-control matrices and role assignments."),
        ("SR 3.4", "Software and information integrity", ControlStatus.NOT_STARTED,
         "Change-management evidence for controller configuration."),  # GAP: config change mgmt
        ("SR 5.1", "Network segmentation", ControlStatus.NOT_STARTED,
         "Zone/conduit diagrams and firewall rule evidence."),  # GAP: segmentation
        ("SR 7.6", "Network and security configuration settings", ControlStatus.PARTIAL,
         "Hardening baselines and configuration snapshots."),
        ("SR 7.3", "Control system backup", ControlStatus.IMPLEMENTED,
         "Backup logs and restore-test records."),
    ],
    FrameworkKey.NERC_CIP: [
        ("CIP-002-5.1a", "BES cyber system categorization", ControlStatus.IMPLEMENTED,
         "Asset categorization records."),
        ("CIP-005-7", "Electronic security perimeter", ControlStatus.PARTIAL,
         "ESP diagrams and access-point inventory."),
        ("CIP-007-6", "System security management / patching", ControlStatus.NOT_STARTED,
         "Documented vulnerability-remediation procedure."),  # GAP: vuln remediation procedure
        ("CIP-010-4", "Configuration change management", ControlStatus.NOT_STARTED,
         "Baseline configurations and change records."),  # GAP: config change mgmt (NERC)
        ("CIP-008-6", "Incident reporting and response planning", ControlStatus.PARTIAL,
         "IR plan and incident-response test evidence."),  # GAP: IR test evidence
    ],
    FrameworkKey.TSA: [
        ("TSA-1", "Critical cyber system identification", ControlStatus.IMPLEMENTED,
         "Critical system inventory."),
        ("TSA-2", "Network segmentation policies", ControlStatus.PARTIAL,
         "Segmentation policy and validation."),
        ("TSA-3", "Access control measures", ControlStatus.PARTIAL,
         "Access-control policy and reviews."),
        ("TSA-4", "Continuous monitoring and detection", ControlStatus.IMPLEMENTED,
         "Monitoring coverage evidence."),
    ],
    FrameworkKey.NIS2: [
        ("Art.21(2)(a)", "Risk analysis and information system security policies",
         ControlStatus.PARTIAL, "Risk assessment and security policy."),
        ("Art.21(2)(b)", "Incident handling", ControlStatus.PARTIAL,
         "Incident-handling procedures and test evidence."),  # GAP support: IR test
        ("Art.21(2)(d)", "Supply chain security", ControlStatus.NOT_STARTED,
         "Supplier security assessments."),
        ("Art.23", "Reporting obligations", ControlStatus.IMPLEMENTED,
         "Reporting workflow evidence."),
    ],
    FrameworkKey.NCA_OTCC: [
        ("OTCC-1-1", "OT asset management", ControlStatus.PARTIAL,
         "OT asset inventory with assigned owners."),  # GAP: asset owner for critical PLC
        ("OTCC-2-1", "OT network segmentation", ControlStatus.NOT_STARTED,
         "Network segmentation evidence."),  # GAP: segmentation
        ("OTCC-3-1", "OT vulnerability management", ControlStatus.PARTIAL,
         "Vulnerability-management procedure and records."),
        ("OTCC-4-1", "OT incident management", ControlStatus.PARTIAL,
         "Incident-management procedure and test evidence."),
        ("OTCC-5-1", "OT access control", ControlStatus.IMPLEMENTED,
         "Access-control policy and reviews."),
    ],
    FrameworkKey.CISA_CPG: [
        ("CPG 1.A", "Asset inventory", ControlStatus.IMPLEMENTED,
         "Maintained asset inventory."),
        ("CPG 2.E", "Separation of OT and IT networks", ControlStatus.NOT_STARTED,
         "Segmentation architecture evidence."),  # GAP: segmentation
        ("CPG 4.C", "Vulnerability management", ControlStatus.PARTIAL,
         "Vulnerability-remediation procedure."),
        ("CPG 5.A", "Incident response plan", ControlStatus.PARTIAL,
         "Tested incident-response plan."),  # GAP: IR test
        ("CPG 2.K", "Strong multi-factor authentication", ControlStatus.IMPLEMENTED,
         "MFA enforcement evidence."),
    ],
    FrameworkKey.MITRE_ATTCK_ICS: [
        ("T0889", "Coverage: Modify Program", ControlStatus.PARTIAL,
         "Detection coverage for controller program modification."),
        ("T0863", "Coverage: User Execution", ControlStatus.IMPLEMENTED,
         "Endpoint detection coverage for user execution."),
        ("T0822", "Coverage: External Remote Services", ControlStatus.PARTIAL,
         "Remote-access monitoring coverage."),
        ("T0846", "Coverage: Remote System Discovery", ControlStatus.PARTIAL,
         "New-device/discovery detection coverage."),
        ("T0866", "Coverage: Exploitation of Remote Services", ControlStatus.PARTIAL,
         "KEV exposure detection coverage."),
    ],
}


def _seed_compliance(
    session: Session,
    assets: dict[str, Asset],
    config_counts: dict[str, int],
) -> dict[str, int]:
    counts = {"frameworks": 0, "controls": 0, "evidence": 0}
    framework_by_key: dict[FrameworkKey, ComplianceFramework] = {}
    for key in FrameworkKey:
        meta = _FRAMEWORK_META[key]
        fw, created = get_or_create(
            session,
            ComplianceFramework,
            defaults={
                "name": meta["name"],
                "version": meta["version"],
                "description": meta["description"],
                "is_placeholder": key in _PLACEHOLDER_FRAMEWORKS,
                "is_demo": True,
            },
            key=key,
        )
        framework_by_key[key] = fw
        counts["frameworks"] += int(created)
    session.commit()

    control_index: dict[tuple[FrameworkKey, str], ComplianceControl] = {}
    for key, controls in _CONTROLS.items():
        fw = framework_by_key[key]
        for control_ref, title, status, evidence_required in controls:
            ctrl, created = get_or_create(
                session,
                ComplianceControl,
                defaults={
                    "title": title,
                    "status": status,
                    "evidence_required": evidence_required,
                    "description": f"{title} ({key.value}).",
                    "last_reviewed": utcnow() - timedelta(days=10),
                    "is_demo": True,
                },
                framework_id=fw.id,
                control_ref=control_ref,
            )
            control_index[(key, control_ref)] = ctrl
            counts["controls"] += int(created)
    session.commit()

    # Evidence rows: a mix of auto-linked (to assets) and manual.
    s7 = assets.get("ENERGY-PLC-S7-01")
    winsrv = assets.get("AUTO-WINSRV-01")

    def add_evidence(
        key: FrameworkKey,
        control_ref: str,
        source_type: EvidenceSourceType,
        source_id: uuid.UUID | None,
        description: str,
        auto_linked: bool,
        file_name: str | None = None,
    ) -> None:
        ctrl = control_index.get((key, control_ref))
        if ctrl is None:
            return
        # Natural key: (control_id, source_type, description) keeps it idempotent.
        _, created = get_or_create(
            session,
            ComplianceEvidence,
            defaults={
                "source_id": source_id,
                "auto_linked": auto_linked,
                "file_name": file_name,
                "uploaded_by": "compliance@forgeshield.local",
                "is_demo": True,
            },
            control_id=ctrl.id,
            source_type=source_type,
            description=description,
        )
        counts["evidence"] += int(created)

    # Auto-linked: critical S7 PLC has no owner -> evidence ties to the NCA asset-mgmt gap.
    if s7 is not None:
        add_evidence(
            FrameworkKey.NCA_OTCC, "OTCC-1-1", EvidenceSourceType.ASSET, s7.id,
            "Asset inventory entry for Siemens S7-1500 (missing assigned owner).",
            auto_linked=True,
        )
    # Auto-linked: unsupported Windows server -> CISA segmentation gap.
    if winsrv is not None:
        add_evidence(
            FrameworkKey.CISA_CPG, "CPG 2.E", EvidenceSourceType.ASSET, winsrv.id,
            "Line data server (Windows Server 2012) lacks documented segmentation.",
            auto_linked=True,
        )
    # Manual evidence (positive).
    add_evidence(
        FrameworkKey.IEC_62443, "SR 7.3", EvidenceSourceType.MANUAL, None,
        "Quarterly backup-and-restore test report for OT controllers.",
        auto_linked=False, file_name="backup_restore_test_q2_2026.pdf",
    )
    add_evidence(
        FrameworkKey.NERC_CIP, "CIP-002-5.1a", EvidenceSourceType.MANUAL, None,
        "BES cyber system categorization spreadsheet.",
        auto_linked=False, file_name="bes_categorization.xlsx",
    )
    session.commit()
    return counts


# --------------------------------------------------------------------------- #
# AI audit trail (one conversation + messages + audit logs)
# --------------------------------------------------------------------------- #
def _seed_ai_audit(session: Session, assets: dict[str, Asset]) -> dict[str, int]:
    counts = {"conversations": 0, "messages": 0, "audit_logs": 0}
    admin = _admin_user(session)
    title = "(DEMO) Siemens S7-1500 unauthorized change risk"

    existing = session.exec(
        select(AIConversation).where(AIConversation.title == title)
    ).first()
    if existing is not None:
        return counts

    conv = AIConversation(
        user_id=admin.id if admin else None,
        title=title,
        use_case=AIUseCase.CONFIG_CHANGE,
    )
    session.add(conv)
    session.flush()
    counts["conversations"] += 1

    plc = assets.get("ENERGY-PLC-S7-01")
    citation_ref = f"asset:{plc.id}" if plc is not None else "asset:unknown"

    user_msg = AIMessage(
        conversation_id=conv.id,
        role=MessageRole.USER,
        content="What is the risk of the unauthorized logic change on the Siemens S7-1500 PLC?",
        use_case=AIUseCase.CONFIG_CHANGE,
    )
    assistant_msg = AIMessage(
        conversation_id=conv.id,
        role=MessageRole.ASSISTANT,
        content="(DEMO) An unauthorized program block was downloaded to the safety-critical "
        "Siemens S7-1500 outside any approved window. Because this controller has no assigned "
        "owner and an open high-CVSS vulnerability, the change should be treated as high risk "
        "until disposition is confirmed.",
        citations=[
            {"ref": citation_ref, "label": "Siemens S7-1500 PLC"},
            {"ref": "config_change:s7-logic", "label": "Unauthorized config change"},
        ],
        confidence=Confidence.MEDIUM.value,
        assumptions=["Change-management calendar shows no approved window for the observed time."],
        safe_ot_actions=[
            "Compare the current program against the approved baseline (read-only).",
            "Confirm the change ticket with change management before any rollback.",
            "Do not alter PLC logic without authorization.",
        ],
        provider_name="mock",
        model_name="demo-seed",
        latency_ms=120,
        use_case=AIUseCase.CONFIG_CHANGE,
    )
    session.add(user_msg)
    session.add(assistant_msg)
    session.flush()
    counts["messages"] += 2

    session.add(
        AuditLog(
            actor_user_id=admin.id if admin else None,
            actor_email="admin@forgeshield.local",
            action=AuditAction.AI_PROMPT,
            entity_type="ai_conversation",
            entity_id=str(conv.id),
            summary="(DEMO) AI CONFIG_CHANGE query",
            meta={"use_case": AIUseCase.CONFIG_CHANGE.value, "demo": True},
        )
    )
    session.add(
        AuditLog(
            actor_user_id=admin.id if admin else None,
            actor_email="admin@forgeshield.local",
            action=AuditAction.AI_RESPONSE,
            entity_type="ai_message",
            entity_id=str(assistant_msg.id),
            summary="(DEMO) AI response (MEDIUM confidence, 2 citations)",
            meta={"provider": "mock", "model": "demo-seed", "demo": True},
        )
    )
    counts["audit_logs"] += 2
    session.commit()
    return counts


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def seed_all(session: Session) -> dict[str, Any]:
    """Seed all demo data idempotently and return a summary count dict."""
    summary: dict[str, Any] = {}

    user_counts = _seed_users_roles(session)
    summary.update(user_counts)

    sites = _seed_sites(session)
    summary["sites"] = len(sites)

    zones = _seed_zones(session, sites)
    summary["zones"] = len(zones)

    assets = _seed_assets(session, sites, zones)
    summary["assets"] = len(assets)

    summary["protocol_observations"] = _seed_protocols(session, assets)
    summary["relationships"] = _seed_relationships(session, assets)

    vuln_counts = _seed_vulns(session, assets)
    summary["vulnerabilities"] = vuln_counts["vulns"]
    summary["asset_vulnerabilities"] = vuln_counts["links"]

    config_counts = _seed_config_change(session, assets)
    summary["config_snapshots"] = config_counts["snapshots"]
    summary["config_changes"] = config_counts["changes"]

    det_result = _seed_detections(session, assets)
    summary["detections"] = det_result["created"]

    summary["incidents"] = _seed_incidents(session, sites, assets, det_result["by_type"])

    comp_counts = _seed_compliance(session, assets, config_counts)
    summary["compliance_frameworks"] = comp_counts["frameworks"]
    summary["compliance_controls"] = comp_counts["controls"]
    summary["compliance_evidence"] = comp_counts["evidence"]

    summary["integrations"] = integration_service.ensure_default_integrations(session)

    ai_counts = _seed_ai_audit(session, assets)
    summary["ai_conversations"] = ai_counts["conversations"]
    summary["ai_messages"] = ai_counts["messages"]
    summary["audit_logs"] = ai_counts["audit_logs"]

    # Populate denormalized asset risk scores/bands.
    summary["risk_recomputed_assets"] = recompute_all(session)

    return summary
