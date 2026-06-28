"""Simulated passive-discovery ingestion API.

All ingestion is READ-ONLY with respect to the network: adapters parse
already-supplied metadata payloads. No live capture, scanning, or active probing.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends
from sqlmodel import Session

from app.api.deps import WRITE_OPERATIONS, AuthenticatedUser, get_current_user, require_role
from app.core.db import get_session
from app.core.enums import SourceType
from app.core.exceptions import ValidationAppError
from app.services.discovery import pipeline

router = APIRouter(prefix="/ingest", tags=["ingestion"])

# Guard against oversized JSON bodies (this is a demo ingestion endpoint, not a
# bulk loader). Roughly 2 MB of serialized JSON.
_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024

# Tiny illustrative sample payloads for each supported source.
_SAMPLE_PAYLOADS: dict[SourceType, dict] = {
    SourceType.PCAP_META: {
        "flows": [
            {
                "src_ip": "10.20.1.50",
                "dst_ip": "10.20.1.10",
                "protocol": "modbus",
                "port": 502,
            }
        ]
    },
    SourceType.NETWORK_OBS: {
        "observations": [
            {
                "ip": "10.20.1.60",
                "mac": "00:1b:1b:aa:bb:cc",
                "hostname": "ENG-WS-2",
                "vendor": "Siemens",
                "protocol": "s7comm",
                "port": 102,
                "peer_ip": "10.20.1.11",
            }
        ]
    },
    SourceType.SYSLOG: {
        "events": [
            {
                "src_ip": "10.40.0.5",
                "dst_ip": "10.20.1.12",
                "protocol": "rdp",
                "port": 3389,
                "kind": "remote_access",
                "message": "RDP session established",
            }
        ]
    },
    SourceType.EDR: {
        "alerts": [
            {
                "host_ip": "10.20.1.20",
                "hostname": "HMI-1",
                "category": "malware",
                "name": "Trojan.Generic",
                "sha256": "0" * 64,
                "severity": "HIGH",
            }
        ]
    },
    SourceType.FIREWALL: {
        "rules": [
            {
                "name": "ALLOW-WAN-HMI",
                "dst_ip": "10.20.1.20",
                "port": 443,
                "protocol": "https",
                "src_zone": "WAN",
                "action": "ALLOW",
                "exposes_internet": True,
            }
        ]
    },
    SourceType.MANUAL: {
        "assets": [
            {
                "ip": "10.20.1.30",
                "hostname": "HIST-1",
                "vendor": "OSIsoft",
                "protocol": "https",
                "port": 443,
            }
        ]
    },
}


@router.get("/sources")
def list_sources(
    _user: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    return {
        "sources": [
            {"source": src.value, "sample_payload": sample}
            for src, sample in _SAMPLE_PAYLOADS.items()
        ],
        "is_demo_environment": True,
    }


@router.post("/{source}")
def ingest_source(
    source: str,
    payload: dict = Body(...),
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    try:
        source_type = SourceType(source.upper())
    except ValueError as exc:
        raise ValidationAppError(
            f"Unknown ingestion source '{source}'. "
            f"Valid sources: {', '.join(s.value for s in SourceType)}"
        ) from exc

    if pipeline.get_adapter(source_type) is None:
        raise ValidationAppError(
            f"Source '{source_type.value}' is not ingestible via this endpoint."
        )

    # Size guard on the raw JSON body.
    if len(json.dumps(payload).encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ValidationAppError("Ingestion payload exceeds the maximum allowed size.")

    return pipeline.ingest(session, source=source_type, payload=payload, user=user).model_dump()
