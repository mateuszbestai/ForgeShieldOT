"""SAFE MOCK adapter over EDR alert metadata.

A real EDR API client (Defender/CrowdStrike/etc.) would plug in here. This adapter
reads already-supplied alerts::

    {"alerts": [
        {"host_ip": "10.1.2.20", "hostname": "HMI-1", "category": "malware",
         "name": "Trojan.X", "sha256": "...", "process": "...", "severity": "HIGH"}
    ]}

All alerts map to EventKind.EDR_ALERT (USB alerts to USB_EVENT); the handler turns
them into the appropriate detection (MALWARE / SUSPICIOUS_PROCESS / USB_INSERTION).
"""
from __future__ import annotations

from datetime import datetime

from app.core.enums import EventKind, SourceType
from app.schemas.ingestion import NormalizedEvent
from app.services.discovery.adapters.base import SourceAdapter, _as_list


def _parse_dt(value: object) -> datetime | None:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


class EdrAdapter(SourceAdapter):
    source = SourceType.EDR

    def parse(self, payload: dict) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for alert in _as_list(payload.get("alerts")):
            if not isinstance(alert, dict):
                continue
            category = str(alert.get("category") or alert.get("type") or "").strip().lower()
            kind = EventKind.USB_EVENT if "usb" in category else EventKind.EDR_ALERT
            events.append(
                NormalizedEvent(
                    source=self.source,
                    event_kind=kind,
                    observed_at=_parse_dt(alert.get("observed_at") or alert.get("timestamp")),
                    src_ip=alert.get("host_ip") or alert.get("ip"),
                    src_mac=alert.get("host_mac") or alert.get("mac"),
                    hostname_hint=alert.get("hostname") or alert.get("host"),
                    raw_fields=alert,
                )
            )
        return events
