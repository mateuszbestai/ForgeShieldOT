"""SAFE MOCK adapter over PCAP *metadata* (not packets).

Real PCAP parsing (pyshark/scapy/tshark) would plug in here. This adapter only
reads already-extracted flow metadata of the form::

    {"flows": [
        {"src_ip": "10.1.2.3", "dst_ip": "10.1.2.10", "protocol": "modbus",
         "port": 502, "src_mac": "...", "dst_mac": "...", "observed_at": "..."}
    ]}
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


class PcapMetaAdapter(SourceAdapter):
    source = SourceType.PCAP_META

    def parse(self, payload: dict) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for flow in _as_list(payload.get("flows")):
            if not isinstance(flow, dict):
                continue
            port = _to_int(flow.get("port") or flow.get("dst_port"))
            protocol = normalize_protocol(flow.get("protocol"), port)
            kind = (
                EventKind.REMOTE_ACCESS
                if protocol in REMOTE_ACCESS_PROTOCOLS
                else EventKind.COMM_OBSERVED
            )
            events.append(
                NormalizedEvent(
                    source=self.source,
                    event_kind=kind,
                    observed_at=_parse_dt(flow.get("observed_at")),
                    src_ip=flow.get("src_ip"),
                    dst_ip=flow.get("dst_ip"),
                    src_mac=flow.get("src_mac"),
                    dst_mac=flow.get("dst_mac"),
                    protocol=protocol,
                    transport_port=port,
                    hostname_hint=flow.get("hostname"),
                    vendor_hint=flow.get("vendor"),
                    raw_fields=flow,
                )
            )
        return events
