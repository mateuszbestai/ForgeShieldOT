"""Source-adapter abstraction for the simulated passive-discovery pipeline.

A ``SourceAdapter`` turns a lenient, already-supplied JSON metadata payload into a
list of ``NormalizedEvent`` objects. These are SAFE MOCK adapters: they perform NO
live packet capture, NO scanning, and NO network access. They only parse metadata
that has been handed to the API.

NOTE: real PCAP parsers (e.g. pyshark/scapy), syslog/SIEM collectors, EDR/firewall
API clients, etc. would plug in here later by implementing ``parse``. The rest of
the pipeline (handlers, risk recompute) is unchanged regardless of source.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from app.core.enums import SourceType
from app.schemas.ingestion import NormalizedEvent


class SourceAdapter(ABC):
    """Base class: subclasses declare a ``source`` and implement ``parse``."""

    source: SourceType

    @abstractmethod
    def parse(self, payload: dict) -> list[NormalizedEvent]:
        """Parse a lenient JSON payload into normalized events.

        Implementations MUST tolerate missing keys and malformed entries (skip
        rather than raise) so that a single bad record does not abort ingestion.
        """
        raise NotImplementedError


def _as_list(value: object) -> list:
    """Coerce a payload section into a list (tolerating None / single dicts)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _to_int(value: object) -> int | None:
    """Best-effort int coercion for ports (tolerating strings / None)."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
