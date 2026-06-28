"""SAFE MOCK adapter over firewall rule / event metadata.

A real firewall API/config client would plug in here. This adapter reads
already-supplied rules or events::

    {"rules": [
        {"name": "ALLOW-WAN-PLC", "dst_ip": "10.1.2.10", "port": 502,
         "protocol": "modbus", "src_zone": "WAN", "action": "ALLOW",
         "exposes_internet": true}
    ]}

Each rule/event becomes a FIREWALL_EVENT; the handler decides whether it exposes an
OT asset and raises a FIREWALL_EXPOSURE detection.
"""
from __future__ import annotations

from datetime import datetime

from app.core.enums import EventKind, SourceType
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


class FirewallAdapter(SourceAdapter):
    source = SourceType.FIREWALL

    def parse(self, payload: dict) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        # Accept either "rules" or "events" as the section name.
        entries = _as_list(payload.get("rules")) or _as_list(payload.get("events"))
        for rule in entries:
            if not isinstance(rule, dict):
                continue
            port = _to_int(rule.get("port") or rule.get("dst_port"))
            protocol = normalize_protocol(rule.get("protocol"), port)
            events.append(
                NormalizedEvent(
                    source=self.source,
                    event_kind=EventKind.FIREWALL_EVENT,
                    observed_at=_parse_dt(rule.get("observed_at") or rule.get("timestamp")),
                    src_ip=rule.get("src_ip"),
                    dst_ip=rule.get("dst_ip"),
                    protocol=protocol,
                    transport_port=port,
                    hostname_hint=rule.get("hostname"),
                    raw_fields=rule,
                )
            )
        return events
