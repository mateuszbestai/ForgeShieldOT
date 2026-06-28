"""SAFE MOCK adapter over syslog-style event metadata.

A real syslog/SIEM collector would plug in here. This adapter reads already-parsed
events::

    {"events": [
        {"src_ip": "10.4.0.5", "dst_ip": "10.1.2.10", "protocol": "rdp",
         "port": 3389, "kind": "remote_access", "message": "..."}
    ]}

The optional ``kind`` hint maps to an EventKind; otherwise it is inferred from the
protocol (remote-access protocols -> REMOTE_ACCESS, else COMM_OBSERVED).
"""
from __future__ import annotations

from datetime import datetime

from app.core.enums import REMOTE_ACCESS_PROTOCOLS, EventKind, SourceType
from app.schemas.ingestion import NormalizedEvent
from app.services.discovery.adapters.base import SourceAdapter, _as_list, _to_int
from app.services.discovery.protocol_registry import normalize_protocol

_KIND_HINTS: dict[str, EventKind] = {
    "asset": EventKind.ASSET_OBSERVED,
    "asset_observed": EventKind.ASSET_OBSERVED,
    "comm": EventKind.COMM_OBSERVED,
    "comm_observed": EventKind.COMM_OBSERVED,
    "remote_access": EventKind.REMOTE_ACCESS,
    "rdp": EventKind.REMOTE_ACCESS,
    "ssh": EventKind.REMOTE_ACCESS,
    "usb": EventKind.USB_EVENT,
    "usb_event": EventKind.USB_EVENT,
    "config": EventKind.CONFIG_HINT,
    "config_hint": EventKind.CONFIG_HINT,
}


def _parse_dt(value: object) -> datetime | None:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


class SyslogAdapter(SourceAdapter):
    source = SourceType.SYSLOG

    def parse(self, payload: dict) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for entry in _as_list(payload.get("events")):
            if not isinstance(entry, dict):
                continue
            port = _to_int(entry.get("port") or entry.get("dst_port"))
            protocol = normalize_protocol(entry.get("protocol"), port)
            hint = str(entry.get("kind") or "").strip().lower()
            kind = _KIND_HINTS.get(hint)
            if kind is None:
                kind = (
                    EventKind.REMOTE_ACCESS
                    if protocol in REMOTE_ACCESS_PROTOCOLS
                    else EventKind.COMM_OBSERVED
                )
            events.append(
                NormalizedEvent(
                    source=self.source,
                    event_kind=kind,
                    observed_at=_parse_dt(entry.get("observed_at") or entry.get("timestamp")),
                    src_ip=entry.get("src_ip"),
                    dst_ip=entry.get("dst_ip"),
                    src_mac=entry.get("src_mac"),
                    dst_mac=entry.get("dst_mac"),
                    protocol=protocol,
                    transport_port=port,
                    hostname_hint=entry.get("hostname"),
                    vendor_hint=entry.get("vendor"),
                    raw_fields=entry,
                )
            )
        return events
