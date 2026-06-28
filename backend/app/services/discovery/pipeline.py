"""Simulated passive-discovery ingestion pipeline.

``ingest`` picks the adapter for a SourceType, parses the supplied metadata payload
into NormalizedEvents, runs the handlers (asset/protocol/relationship upserts and
defensive detection emission), recomputes risk for affected assets, and writes an
INGEST audit entry. Everything is read-only with respect to the network — it only
processes already-supplied metadata.
"""
from __future__ import annotations

import uuid

from sqlmodel import Session

from app.core.enums import AuditAction, EventKind, SourceType
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.schemas.ingestion import IngestSummary, NormalizedEvent
from app.services.audit_service import record_audit
from app.services.discovery import handlers
from app.services.discovery.adapters.base import SourceAdapter
from app.services.discovery.adapters.edr import EdrAdapter
from app.services.discovery.adapters.firewall import FirewallAdapter
from app.services.discovery.adapters.manual import ManualAdapter
from app.services.discovery.adapters.network_obs import NetworkObsAdapter
from app.services.discovery.adapters.pcap_meta import PcapMetaAdapter
from app.services.discovery.adapters.syslog import SyslogAdapter
from app.services.risk_engine import score_asset

# Registry of available source adapters. SEED has no live adapter (it is produced by
# the seed routine directly), so it is intentionally absent here.
_ADAPTERS: dict[SourceType, SourceAdapter] = {
    SourceType.PCAP_META: PcapMetaAdapter(),
    SourceType.NETWORK_OBS: NetworkObsAdapter(),
    SourceType.SYSLOG: SyslogAdapter(),
    SourceType.EDR: EdrAdapter(),
    SourceType.FIREWALL: FirewallAdapter(),
    SourceType.MANUAL: ManualAdapter(),
}


def get_adapter(source: SourceType) -> SourceAdapter | None:
    return _ADAPTERS.get(source)


def supported_sources() -> list[SourceType]:
    return list(_ADAPTERS.keys())


def _process_event(
    session: Session, event: NormalizedEvent, summary: IngestSummary, affected: set[uuid.UUID]
) -> None:
    """Dispatch a single normalized event to the right handler(s)."""
    if event.event_kind == EventKind.EDR_ALERT or event.event_kind == EventKind.USB_EVENT:
        det, asset, asset_created = handlers.handle_edr_alert(session, event)
        if asset is not None:
            affected.add(asset.id)  # type: ignore[arg-type]
            if asset_created:
                summary.assets_created += 1
                summary.detections_created += 1  # discovery detection emitted in upsert_asset
            else:
                summary.assets_updated += 1
        if det is not None:
            summary.detections_created += 1
            if det.asset_id:
                affected.add(det.asset_id)
        return

    if event.event_kind == EventKind.FIREWALL_EVENT:
        det = handlers.handle_firewall_event(session, event)
        if det is not None:
            summary.detections_created += 1
            if det.asset_id:
                affected.add(det.asset_id)
        return

    # Asset / comm / remote-access observations -> inventory upserts.
    src_asset, src_created = handlers.upsert_asset(session, event)
    if src_asset is None:
        summary.notes.append(
            "Skipped an observation with no identifying info or no Site to attach to."
        )
        return
    if src_created:
        summary.assets_created += 1
        summary.detections_created += 1  # discovery detection emitted in upsert_asset
    else:
        summary.assets_updated += 1
    affected.add(src_asset.id)  # type: ignore[arg-type]

    # Record protocol fingerprint on the source asset.
    obs = handlers.record_protocol_observation(
        session, src_asset, event.protocol, event.transport_port, event.source
    )
    if obs is not None:
        summary.protocols_recorded += 1

    if event.event_kind in (EventKind.COMM_OBSERVED, EventKind.REMOTE_ACCESS) and (
        event.dst_ip or event.dst_mac
    ):
        dst_event = NormalizedEvent(
            source=event.source,
            event_kind=EventKind.ASSET_OBSERVED,
            observed_at=event.observed_at,
            src_ip=event.dst_ip,
            src_mac=event.dst_mac,
            protocol=event.protocol,
            transport_port=event.transport_port,
            raw_fields=event.raw_fields,
        )
        dst_asset, dst_created = handlers.upsert_asset(session, dst_event)
        if dst_asset is not None:
            if dst_created:
                summary.assets_created += 1
                summary.detections_created += 1
            else:
                summary.assets_updated += 1
            affected.add(dst_asset.id)  # type: ignore[arg-type]
            handlers.record_protocol_observation(
                session, dst_asset, event.protocol, event.transport_port, event.source
            )
            rel, rel_created = handlers.upsert_relationship(
                session, src_asset, dst_asset, event.protocol, event.source
            )
            if rel is not None:
                summary.relationships_recorded += 1
                if rel_created:
                    summary.detections_created += 1  # path detection emitted on creation


def ingest(
    session: Session,
    *,
    source: SourceType,
    payload: dict,
    user: AuthenticatedUser | None,
) -> IngestSummary:
    """Run the full ingestion pipeline for one source + payload."""
    summary = IngestSummary(source=source)

    adapter = get_adapter(source)
    if adapter is None:
        summary.notes.append(f"No adapter available for source '{source.value}'.")
        return summary

    events = adapter.parse(payload or {})
    summary.events_processed = len(events)
    if not events:
        summary.notes.append("No usable records were found in the supplied payload.")

    affected: set[uuid.UUID] = set()
    for event in events:
        _process_event(session, event, summary, affected)

    # Recompute risk for every asset touched (creation/detection emission changes risk).
    for asset_id in affected:
        asset = session.get(Asset, asset_id)
        if asset is not None:
            score_asset(session, asset, persist=True)

    record_audit(
        session,
        action=AuditAction.INGEST,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="ingest",
        entity_id=None,
        summary=(
            f"Ingested {source.value}: {summary.events_processed} events, "
            f"{summary.assets_created} new assets, {summary.detections_created} detections"
        ),
        meta=summary.model_dump(),
    )
    return summary
