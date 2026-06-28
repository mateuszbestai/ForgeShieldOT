"""SAFE MOCK adapter for manually-supplied asset/observation metadata.

This adapter lets an operator hand-feed assets to the discovery pipeline (e.g.
from a spreadsheet) without going through the full inventory CRUD. It reads::

    {"assets": [
        {"ip": "10.1.2.30", "mac": "...", "hostname": "HIST-1",
         "vendor": "OSIsoft", "protocol": "https", "port": 443}
    ]}

Each entry becomes a bare ASSET_OBSERVED event (plus a COMM_OBSERVED event if a
``peer_ip`` is supplied).
"""
from __future__ import annotations

from datetime import datetime

from app.core.enums import REMOTE_ACCESS_PROTOCOLS, EventKind, SourceType
from app.schemas.ingestion import NormalizedEvent
from app.services.discovery.adapters.base import SourceAdapter, _as_list, _to_int
from app.services.discovery.protocol_registry import normalize_protocol


def _parse_dt(value: object) -> datetime | None:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


class ManualAdapter(SourceAdapter):
    source = SourceType.MANUAL

    def parse(self, payload: dict) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        # Tolerate either "assets" or "observations" as the section name.
        entries = _as_list(payload.get("assets")) or _as_list(payload.get("observations"))
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            port = _to_int(entry.get("port") or entry.get("dst_port"))
            protocol = normalize_protocol(entry.get("protocol"), port)
            observed_at = _parse_dt(entry.get("observed_at") or entry.get("last_seen"))
            events.append(
                NormalizedEvent(
                    source=self.source,
                    event_kind=EventKind.ASSET_OBSERVED,
                    observed_at=observed_at,
                    src_ip=entry.get("ip") or entry.get("src_ip"),
                    src_mac=entry.get("mac") or entry.get("src_mac"),
                    protocol=protocol,
                    transport_port=port,
                    hostname_hint=entry.get("hostname"),
                    vendor_hint=entry.get("vendor"),
                    raw_fields=entry,
                )
            )
            peer_ip = entry.get("peer_ip") or entry.get("dst_ip")
            if peer_ip:
                kind = (
                    EventKind.REMOTE_ACCESS
                    if protocol in REMOTE_ACCESS_PROTOCOLS
                    else EventKind.COMM_OBSERVED
                )
                events.append(
                    NormalizedEvent(
                        source=self.source,
                        event_kind=kind,
                        observed_at=observed_at,
                        src_ip=entry.get("ip") or entry.get("src_ip"),
                        dst_ip=peer_ip,
                        src_mac=entry.get("mac") or entry.get("src_mac"),
                        dst_mac=entry.get("peer_mac") or entry.get("dst_mac"),
                        protocol=protocol,
                        transport_port=port,
                        hostname_hint=entry.get("hostname"),
                        vendor_hint=entry.get("vendor"),
                        raw_fields=entry,
                    )
                )
        return events
