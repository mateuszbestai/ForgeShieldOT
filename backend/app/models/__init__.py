"""Importing this package registers every table on SQLModel.metadata."""
from __future__ import annotations

from app.models.ai import AIConversation, AIMessage
from app.models.asset import Asset, AssetRelationship, ProtocolObservation
from app.models.audit import AuditLog
from app.models.compliance import (
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)
from app.models.config_mgmt import ConfigChange, ConfigSnapshot
from app.models.detection import Detection, DetectionEvidence
from app.models.incident import Incident, IncidentLink, IncidentTimelineEvent
from app.models.integration import Integration
from app.models.org import Site, Zone
from app.models.report import Report
from app.models.user import Role, User, UserRole
from app.models.vuln import AssetVulnerability, Vulnerability

__all__ = [
    "AIConversation",
    "AIMessage",
    "Asset",
    "AssetRelationship",
    "AssetVulnerability",
    "AuditLog",
    "ComplianceControl",
    "ComplianceEvidence",
    "ComplianceFramework",
    "ConfigChange",
    "ConfigSnapshot",
    "Detection",
    "DetectionEvidence",
    "Incident",
    "IncidentLink",
    "IncidentTimelineEvent",
    "Integration",
    "ProtocolObservation",
    "Report",
    "Role",
    "Site",
    "User",
    "UserRole",
    "Vulnerability",
    "Zone",
]
