"""Discovery handlers: turn NormalizedEvents into inventory + detections.

These operate on a Session and are SIMULATED/PASSIVE: they only persist what was
observed and emit defensive detections. They never write to controllers or take
automated network actions.
"""
from __future__ import annotations

import uuid

from sqlmodel import Session, select

from app.core.enums import (
    OT_CONTROL_PROTOCOLS,
    REMOTE_ACCESS_PROTOCOLS,
    AssetType,
    DetectionType,
    DiscoverySource,
    EvidenceKind,
    NormalizedProtocol,
    ProtocolDirection,
    PurdueLevel,
    RelationshipType,
    SourceType,
)
from app.models.asset import Asset, AssetRelationship, ProtocolObservation
from app.models.base import utcnow
from app.models.detection import Detection
from app.models.org import Site
from app.schemas.detection import EvidenceCreate
from app.schemas.ingestion import NormalizedEvent
from app.services import detection_service

# Controller-style asset types that are sensitive EW->PLC interaction targets.
_CONTROLLER_TYPES: frozenset[AssetType] = frozenset(
    {AssetType.PLC, AssetType.RTU, AssetType.SAFETY_SIS}
)

# Source -> DiscoverySource mapping for newly created assets.
_DISCOVERY_SOURCE_MAP: dict[SourceType, DiscoverySource] = {
    SourceType.PCAP_META: DiscoverySource.PASSIVE_NETWORK,
    SourceType.NETWORK_OBS: DiscoverySource.PASSIVE_NETWORK,
    SourceType.SYSLOG: DiscoverySource.PASSIVE_NETWORK,
    SourceType.EDR: DiscoverySource.EDR,
    SourceType.FIREWALL: DiscoverySource.FIREWALL,
    SourceType.MANUAL: DiscoverySource.MANUAL,
    SourceType.SEED: DiscoverySource.SEED,
}


# --------------------------------------------------------------------------- #
# Asset matching / upsert
# --------------------------------------------------------------------------- #
def _find_asset(
    session: Session, *, ip: str | None, mac: str | None, hostname: str | None
) -> Asset | None:
    """Match an existing asset by IP, then MAC, then hostname (in that order)."""
    if ip:
        hit = session.exec(select(Asset).where(Asset.ip_address == ip)).first()
        if hit:
            return hit
    if mac:
        hit = session.exec(select(Asset).where(Asset.mac_address == mac)).first()
        if hit:
            return hit
    if hostname:
        hit = session.exec(select(Asset).where(Asset.hostname == hostname)).first()
        if hit:
            return hit
    return None


def _first_site_id(session: Session) -> uuid.UUID | None:
    site = session.exec(select(Site).order_by(Site.created_at)).first()  # type: ignore[attr-defined]
    return site.id if site else None


def _next_tag(session: Session) -> str:
    """Generate a unique asset tag for a discovered asset."""
    base = "DISC"
    count = len(
        session.exec(select(Asset).where(Asset.asset_tag.like(f"{base}-%"))).all()  # type: ignore[attr-defined]
    )
    candidate = f"{base}-{count + 1:04d}"
    # Guard against collisions (e.g. gaps from deletions).
    while session.exec(select(Asset).where(Asset.asset_tag == candidate)).first():
        count += 1
        candidate = f"{base}-{count + 1:04d}"
    return candidate


def upsert_asset(session: Session, event: NormalizedEvent) -> tuple[Asset | None, bool]:
    """Match-or-create an asset for the *source* endpoint of an event.

    Returns ``(asset, created)``. ``asset`` is ``None`` (with no creation) if there
    is no identifying info, or if there is no Site to attach a new asset to.
    A newly-created asset emits an UNKNOWN_ASSET (or NEW_DEVICE_IN_ZONE) detection.
    """
    ip = event.src_ip
    mac = event.src_mac
    hostname = event.hostname_hint

    if not (ip or mac or hostname):
        return None, False

    existing = _find_asset(session, ip=ip, mac=mac, hostname=hostname)
    if existing is not None:
        # Refresh observation metadata.
        existing.last_seen = event.observed_at or utcnow()
        if not existing.hostname and hostname:
            existing.hostname = hostname
        if not existing.mac_address and mac:
            existing.mac_address = mac
        if not existing.vendor and event.vendor_hint:
            existing.vendor = event.vendor_hint
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing, False

    site_id = _first_site_id(session)
    if site_id is None:
        return None, False

    asset = Asset(
        asset_tag=_next_tag(session),
        hostname=hostname,
        ip_address=ip,
        mac_address=mac,
        vendor=event.vendor_hint,
        site_id=site_id,
        asset_type=AssetType.NETWORK_DEVICE,
        purdue_level=PurdueLevel.L3,
        discovery_source=_DISCOVERY_SOURCE_MAP.get(event.source, DiscoverySource.PASSIVE_NETWORK),
        last_seen=event.observed_at or utcnow(),
        is_demo=True,
    )
    session.add(asset)
    session.commit()
    session.refresh(asset)

    # Emit a discovery detection for the newly-seen device.
    det_type = (
        DetectionType.NEW_DEVICE_IN_ZONE
        if int(asset.purdue_level) <= int(PurdueLevel.L2)
        else DetectionType.UNKNOWN_ASSET
    )
    evidence = [
        EvidenceCreate(
            kind=EvidenceKind.NETWORK,
            label="Discovery observation",
            data={
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "source": event.source.value,
            },
        )
    ]
    detection_service.create_from_template(
        session,
        det_type,
        asset,
        asset.site_id,
        evidence=evidence,
        source=event.source,
    )
    return asset, True


# --------------------------------------------------------------------------- #
# Protocol observations
# --------------------------------------------------------------------------- #
def record_protocol_observation(
    session: Session,
    asset: Asset,
    protocol: NormalizedProtocol | None,
    port: int | None,
    source: SourceType,
) -> ProtocolObservation | None:
    """Upsert a ProtocolObservation for an asset (increment count / last_seen)."""
    if protocol is None or asset.id is None:
        return None
    now = utcnow()
    obs = session.exec(
        select(ProtocolObservation)
        .where(ProtocolObservation.asset_id == asset.id)
        .where(ProtocolObservation.protocol == protocol)
    ).first()
    if obs is None:
        obs = ProtocolObservation(
            asset_id=asset.id,
            protocol=protocol,
            port=port,
            direction=ProtocolDirection.BIDIRECTIONAL,
            observation_count=1,
            first_seen=now,
            last_seen=now,
            source=source,
            is_demo=True,
        )
    else:
        obs.observation_count += 1
        obs.last_seen = now
        if obs.port is None and port is not None:
            obs.port = port
    session.add(obs)
    session.commit()
    session.refresh(obs)
    return obs


# --------------------------------------------------------------------------- #
# Relationships
# --------------------------------------------------------------------------- #
def _classify_relationship(
    src: Asset, dst: Asset, protocol: NormalizedProtocol | None
) -> RelationshipType:
    if (
        src.asset_type == AssetType.ENG_WORKSTATION
        and dst.asset_type in _CONTROLLER_TYPES
        and protocol in OT_CONTROL_PROTOCOLS
    ):
        return RelationshipType.EW_TO_PLC
    if protocol in REMOTE_ACCESS_PROTOCOLS:
        return RelationshipType.REMOTE_ACCESS
    return RelationshipType.COMM


def upsert_relationship(
    session: Session,
    src: Asset,
    dst: Asset,
    protocol: NormalizedProtocol | None,
    source: SourceType,
) -> tuple[AssetRelationship | None, bool]:
    """Upsert an AssetRelationship and emit a detection for newly-seen paths.

    Returns ``(relationship, created)``. Newly-seen paths are marked ``is_unknown``
    and raise an EW_TO_PLC / REMOTE_ACCESS / UNKNOWN_COMM_PATH detection.
    """
    if src.id is None or dst.id is None or src.id == dst.id:
        return None, False

    now = utcnow()
    rel = session.exec(
        select(AssetRelationship)
        .where(AssetRelationship.src_asset_id == src.id)
        .where(AssetRelationship.dst_asset_id == dst.id)
        .where(AssetRelationship.protocol == protocol)
    ).first()
    if rel is not None:
        rel.last_seen = now
        rel.observation_count += 1
        session.add(rel)
        session.commit()
        session.refresh(rel)
        return rel, False

    rel_type = _classify_relationship(src, dst, protocol)
    is_internet = bool(src.internet_reachable or dst.internet_reachable)
    rel = AssetRelationship(
        src_asset_id=src.id,
        dst_asset_id=dst.id,
        protocol=protocol,
        relationship_type=rel_type,
        is_unknown=True,
        is_internet_path=is_internet,
        first_seen=now,
        last_seen=now,
        observation_count=1,
        is_demo=True,
    )
    session.add(rel)
    session.commit()
    session.refresh(rel)

    # Emit a detection appropriate to the newly-seen path.
    if rel_type == RelationshipType.EW_TO_PLC:
        det_type = DetectionType.EW_TO_PLC
    elif rel_type == RelationshipType.REMOTE_ACCESS:
        det_type = DetectionType.REMOTE_ACCESS
    else:
        det_type = DetectionType.UNKNOWN_COMM_PATH

    evidence = [
        EvidenceCreate(
            kind=EvidenceKind.NETWORK,
            label="Observed communication path",
            data={
                "src": src.asset_tag,
                "dst": dst.asset_tag,
                "protocol": protocol.value if protocol else None,
                "relationship_type": rel_type.value,
                "source": source.value,
            },
        )
    ]
    detection_service.create_from_template(
        session,
        det_type,
        dst,
        dst.site_id,
        evidence=evidence,
        source=source,
    )
    return rel, True


# --------------------------------------------------------------------------- #
# Endpoint / firewall handlers
# --------------------------------------------------------------------------- #
def handle_edr_alert(
    session: Session, event: NormalizedEvent
) -> tuple[Detection | None, Asset | None, bool]:
    """Create the appropriate endpoint detection from an EDR alert event.

    Returns ``(detection, asset, asset_created)`` so the pipeline can account for
    any asset the alert introduced and recompute its risk.
    """
    asset, asset_created = upsert_asset(session, event)
    raw = event.raw_fields or {}
    category = str(raw.get("category") or raw.get("type") or "").strip().lower()

    if event.event_kind.value == "USB_EVENT" or "usb" in category:
        det_type = DetectionType.USB_INSERTION
    elif any(k in category for k in ("malware", "virus", "trojan", "ransom")):
        det_type = DetectionType.MALWARE
    elif "yara" in category:
        det_type = DetectionType.YARA_MATCH
    else:
        det_type = DetectionType.SUSPICIOUS_PROCESS

    label = str(raw.get("name") or raw.get("rule") or det_type.value)
    evidence = [
        EvidenceCreate(
            kind=EvidenceKind.PROCESS if det_type == DetectionType.SUSPICIOUS_PROCESS else EvidenceKind.LOG,
            label=label,
            data=raw,
        )
    ]
    detection = detection_service.create_from_template(
        session,
        det_type,
        asset,
        asset.site_id if asset else None,
        title=f"{detection_service.template_for(det_type)['title']}: {label}" if label else None,
        evidence=evidence,
        source=event.source,
    )
    return detection, asset, asset_created


def handle_firewall_event(session: Session, event: NormalizedEvent) -> Detection | None:
    """Create a FIREWALL_EXPOSURE detection when a rule exposes an OT asset.

    The destination of the rule (an OT asset) is matched if present; the detection
    is attached to it. Rules that don't plausibly expose anything are skipped.
    """
    raw = event.raw_fields or {}
    action = str(raw.get("action") or "ALLOW").strip().upper()
    if action not in ("ALLOW", "PERMIT", "ACCEPT"):
        return None

    exposes_internet = bool(raw.get("exposes_internet"))
    src_zone = str(raw.get("src_zone") or "").strip().upper()
    from_untrusted = exposes_internet or src_zone in ("WAN", "INTERNET", "IT", "ENTERPRISE")

    # Match the destination OT asset, if any.
    dst = _find_asset(
        session, ip=event.dst_ip, mac=None, hostname=event.hostname_hint
    )

    # Only raise when the rule plausibly exposes an OT asset from a less-trusted zone.
    if not (from_untrusted or dst is not None):
        return None

    label = str(raw.get("name") or raw.get("rule") or "firewall rule")
    evidence = [
        EvidenceCreate(
            kind=EvidenceKind.CONFIG,
            label=label,
            data=raw,
        )
    ]
    return detection_service.create_from_template(
        session,
        DetectionType.FIREWALL_EXPOSURE,
        dst,
        dst.site_id if dst else _first_site_id(session),
        title=f"Firewall rule exposes OT asset: {label}",
        evidence=evidence,
        source=event.source,
    )
