"""SAFE MOCK adapter over passive network observations.

Real passive-discovery sensors (Claroty/Nozomi/Dragos exports, ARP/DHCP/mDNS
observers) would plug in here. This adapter reads already-supplied observations::

    {"observations": [
        {"ip": "10.1.2.3", "mac": "00:11:...", "hostname": "ENG-WS-1",
         "vendor": "Siemens", "protocol": "s7comm", "port": 102,
         "peer_ip": "10.1.2.10"}
    ]}

An observation with a ``peer_ip``/``peer_mac`` is treated as a communication
event; otherwise it is a bare asset observation.
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


class NetworkObsAdapter(SourceAdapter):
    source = SourceType.NETWORK_OBS

    def parse(self, payload: dict) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for obs in _as_list(payload.get("observations")):
            if not isinstance(obs, dict):
                continue
            port = _to_int(obs.get("port") or obs.get("dst_port"))
            protocol = normalize_protocol(obs.get("protocol"), port)
            peer_ip = obs.get("peer_ip") or obs.get("dst_ip")
            peer_mac = obs.get("peer_mac") or obs.get("dst_mac")
            observed_at = _parse_dt(obs.get("observed_at") or obs.get("last_seen"))

            if peer_ip or peer_mac:
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
                        src_ip=obs.get("ip") or obs.get("src_ip"),
                        dst_ip=peer_ip,
                        src_mac=obs.get("mac") or obs.get("src_mac"),
                        dst_mac=peer_mac,
                        protocol=protocol,
                        transport_port=port,
                        hostname_hint=obs.get("hostname"),
                        vendor_hint=obs.get("vendor"),
                        raw_fields=obs,
                    )
                )
            else:
                events.append(
                    NormalizedEvent(
                        source=self.source,
                        event_kind=EventKind.ASSET_OBSERVED,
                        observed_at=observed_at,
                        src_ip=obs.get("ip") or obs.get("src_ip"),
                        src_mac=obs.get("mac") or obs.get("src_mac"),
                        protocol=protocol,
                        transport_port=port,
                        hostname_hint=obs.get("hostname"),
                        vendor_hint=obs.get("vendor"),
                        raw_fields=obs,
                    )
                )
        return events
