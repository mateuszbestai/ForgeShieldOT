"""Schemas for the simulated passive-discovery ingestion pipeline.

A ``NormalizedEvent`` is the common, source-agnostic shape that every source
adapter produces. The pipeline's handlers consume only ``NormalizedEvent`` so the
underlying source (PCAP metadata, network observations, syslog, EDR, firewall,
manual) is irrelevant downstream.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.enums import EventKind, NormalizedProtocol, SourceType


class NormalizedEvent(BaseModel):
    source: SourceType
    event_kind: EventKind
    observed_at: datetime | None = None

    # Network identity (any may be missing depending on the source)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    protocol: NormalizedProtocol | None = None
    transport_port: int | None = None

    # Enrichment hints
    hostname_hint: str | None = None
    vendor_hint: str | None = None

    # Original (untrusted) fields, retained for evidence/audit. Sanitized before AI use.
    raw_fields: dict = Field(default_factory=dict)

    is_demo: bool = True


class IngestSummary(BaseModel):
    source: SourceType
    events_processed: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    protocols_recorded: int = 0
    relationships_recorded: int = 0
    detections_created: int = 0
    notes: list[str] = Field(default_factory=list)
    is_demo_environment: bool = True
