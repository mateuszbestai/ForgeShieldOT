"""Single source of truth for ForgeShield OT enumerations.

Convention: every string enum has ``value == name`` (uppercase identifiers).
This keeps the value stable regardless of whether SQLAlchemy persists by enum
name or value, and keeps API payloads predictable. The frontend mirrors these
in ``frontend/src/types/enums.ts``.
"""
from __future__ import annotations

from enum import Enum, IntEnum


class StrEnum(str, Enum):
    """str-mixin enum; members compare equal to their string value."""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


# --------------------------------------------------------------------------- #
# People / access
# --------------------------------------------------------------------------- #
class RoleName(StrEnum):
    ADMIN = "ADMIN"
    OT_SECURITY_ENGINEER = "OT_SECURITY_ENGINEER"
    SOC_ANALYST = "SOC_ANALYST"
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    VIEWER = "VIEWER"


# --------------------------------------------------------------------------- #
# Assets / organization
# --------------------------------------------------------------------------- #
class Criticality(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    SAFETY_CRITICAL = "SAFETY_CRITICAL"


class ImpactLevel(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class PurdueLevel(IntEnum):
    """Purdue Enterprise Reference Architecture levels 0–5."""

    L0 = 0  # Physical process (sensors/actuators)
    L1 = 1  # Basic control (PLC/RTU)
    L2 = 2  # Area supervisory control (HMI/SCADA)
    L3 = 3  # Site operations (historian, eng workstation)
    L4 = 4  # Site business / IT
    L5 = 5  # Enterprise / internet


class AssetType(StrEnum):
    PLC = "PLC"
    RTU = "RTU"
    HMI = "HMI"
    SCADA_SERVER = "SCADA_SERVER"
    HISTORIAN = "HISTORIAN"
    ENG_WORKSTATION = "ENG_WORKSTATION"
    SAFETY_SIS = "SAFETY_SIS"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    REMOTE_ACCESS_GATEWAY = "REMOTE_ACCESS_GATEWAY"
    IIOT_EDGE = "IIOT_EDGE"
    OEM_VENDOR_SYSTEM = "OEM_VENDOR_SYSTEM"


# Asset types that can host a supported antimalware/EDR agent (Windows/Linux endpoints).
HOST_AGENT_CAPABLE_TYPES: frozenset[AssetType] = frozenset(
    {
        AssetType.ENG_WORKSTATION,
        AssetType.HMI,
        AssetType.HISTORIAN,
        AssetType.SCADA_SERVER,
    }
)


class SupportStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    EXTENDED = "EXTENDED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class PatchStatus(StrEnum):
    CURRENT = "CURRENT"
    OUTDATED = "OUTDATED"
    EOL = "EOL"
    UNKNOWN = "UNKNOWN"


class DiscoverySource(StrEnum):
    PASSIVE_NETWORK = "PASSIVE_NETWORK"
    MANUAL = "MANUAL"
    CSV_IMPORT = "CSV_IMPORT"
    EDR = "EDR"
    FIREWALL = "FIREWALL"
    OEM_IMPORT = "OEM_IMPORT"
    SEED = "SEED"


class RelationshipType(StrEnum):
    COMM = "COMM"
    EW_TO_PLC = "EW_TO_PLC"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    MANAGEMENT = "MANAGEMENT"


class ProtocolDirection(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BIDIRECTIONAL = "BIDIRECTIONAL"


# --------------------------------------------------------------------------- #
# Protocols (normalized names only)
# --------------------------------------------------------------------------- #
class NormalizedProtocol(StrEnum):
    MODBUS_TCP = "MODBUS_TCP"
    S7COMM = "S7COMM"
    ETHERNET_IP_CIP = "ETHERNET_IP_CIP"
    OPC_UA = "OPC_UA"
    DNP3 = "DNP3"
    PROFINET = "PROFINET"
    BACNET = "BACNET"
    IEC_60870_5_104 = "IEC_60870_5_104"
    MQTT = "MQTT"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SMB = "SMB"
    RDP = "RDP"
    SSH = "SSH"


# OT/ICS control protocols (used for EW->PLC and zone-sensitivity heuristics).
OT_CONTROL_PROTOCOLS: frozenset[NormalizedProtocol] = frozenset(
    {
        NormalizedProtocol.MODBUS_TCP,
        NormalizedProtocol.S7COMM,
        NormalizedProtocol.ETHERNET_IP_CIP,
        NormalizedProtocol.OPC_UA,
        NormalizedProtocol.DNP3,
        NormalizedProtocol.PROFINET,
        NormalizedProtocol.IEC_60870_5_104,
    }
)

REMOTE_ACCESS_PROTOCOLS: frozenset[NormalizedProtocol] = frozenset(
    {NormalizedProtocol.RDP, NormalizedProtocol.SSH}
)


# --------------------------------------------------------------------------- #
# Severity / confidence / risk
# --------------------------------------------------------------------------- #
class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskBand(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #
class DetectionType(StrEnum):
    MALWARE = "MALWARE"
    QUARANTINED_FILE = "QUARANTINED_FILE"
    YARA_MATCH = "YARA_MATCH"
    HASH_REPUTATION = "HASH_REPUTATION"
    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"
    USB_INSERTION = "USB_INSERTION"
    AUTORUN_PERSISTENCE = "AUTORUN_PERSISTENCE"
    UNSIGNED_BINARY = "UNSIGNED_BINARY"
    ENG_TOOL_ABUSE = "ENG_TOOL_ABUSE"
    UNKNOWN_ASSET = "UNKNOWN_ASSET"
    UNKNOWN_COMM_PATH = "UNKNOWN_COMM_PATH"
    NEW_DEVICE_IN_ZONE = "NEW_DEVICE_IN_ZONE"
    EW_TO_PLC = "EW_TO_PLC"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    RDP_FROM_UNAPPROVED = "RDP_FROM_UNAPPROVED"
    OUT_OF_WINDOW_CHANGE = "OUT_OF_WINDOW_CHANGE"
    UNUSUAL_OUTBOUND = "UNUSUAL_OUTBOUND"
    FIREWALL_EXPOSURE = "FIREWALL_EXPOSURE"
    UNSUPPORTED_OS = "UNSUPPORTED_OS"
    KEV_EXPOSURE = "KEV_EXPOSURE"
    ENDPOINT_PROTECTION_STATUS = "ENDPOINT_PROTECTION_STATUS"


class DetectionStatus(StrEnum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class EvidenceKind(StrEnum):
    HASH = "HASH"
    PROCESS = "PROCESS"
    FILE_META = "FILE_META"
    YARA = "YARA"
    USB = "USB"
    LOG = "LOG"
    NETWORK = "NETWORK"
    CONFIG = "CONFIG"


# --------------------------------------------------------------------------- #
# Vulnerabilities
# --------------------------------------------------------------------------- #
class VulnRemediationStatus(StrEnum):
    OPEN = "OPEN"
    PATCH_NOW = "PATCH_NOW"
    MITIGATE = "MITIGATE"
    MONITOR = "MONITOR"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    REMEDIATED = "REMEDIATED"


class PatchRisk(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    REQUIRES_OUTAGE = "REQUIRES_OUTAGE"


class MatchBasis(StrEnum):
    VENDOR_MODEL_VERSION = "VENDOR_MODEL_VERSION"
    VENDOR_PRODUCT = "VENDOR_PRODUCT"
    MANUAL = "MANUAL"


# --------------------------------------------------------------------------- #
# Config / change management
# --------------------------------------------------------------------------- #
class SnapshotKind(StrEnum):
    PLC_PROGRAM = "PLC_PROGRAM"
    FIRMWARE = "FIRMWARE"
    LOGIC = "LOGIC"
    NETWORK_CONFIG = "NETWORK_CONFIG"
    FIREWALL_RULES = "FIREWALL_RULES"
    SOFTWARE_INVENTORY = "SOFTWARE_INVENTORY"
    ACCOUNT_CONFIG = "ACCOUNT_CONFIG"
    BACKUP_STATUS = "BACKUP_STATUS"


class ChangeDisposition(StrEnum):
    UNREVIEWED = "UNREVIEWED"
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"


# --------------------------------------------------------------------------- #
# Compliance
# --------------------------------------------------------------------------- #
class FrameworkKey(StrEnum):
    IEC_62443 = "IEC_62443"
    NERC_CIP = "NERC_CIP"
    TSA = "TSA"
    NIS2 = "NIS2"
    NCA_OTCC = "NCA_OTCC"
    CISA_CPG = "CISA_CPG"
    ISO_27001 = "ISO_27001"
    NIST_800_82 = "NIST_800_82"
    MITRE_ATTCK_ICS = "MITRE_ATTCK_ICS"


class ControlStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    PARTIAL = "PARTIAL"
    IMPLEMENTED = "IMPLEMENTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Control statuses considered an open gap for readiness scoring.
GAP_CONTROL_STATUSES: frozenset[ControlStatus] = frozenset(
    {ControlStatus.NOT_STARTED, ControlStatus.PARTIAL}
)


class EvidenceSourceType(StrEnum):
    ASSET = "ASSET"
    DETECTION = "DETECTION"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    VULN = "VULN"
    INCIDENT = "INCIDENT"
    REPORT = "REPORT"
    MANUAL = "MANUAL"


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #
class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class TimelineEventKind(StrEnum):
    NOTE = "NOTE"
    EVIDENCE = "EVIDENCE"
    STATUS_CHANGE = "STATUS_CHANGE"
    CONTAINMENT = "CONTAINMENT"
    RECOVERY = "RECOVERY"
    LINK = "LINK"


class IncidentLinkType(StrEnum):
    DETECTION = "DETECTION"
    ASSET = "ASSET"
    VULN = "VULN"
    CONFIG_CHANGE = "CONFIG_CHANGE"


# --------------------------------------------------------------------------- #
# Reports / integrations / audit
# --------------------------------------------------------------------------- #
class ReportType(StrEnum):
    EXEC_RISK_SUMMARY = "EXEC_RISK_SUMMARY"
    ASSET_INVENTORY = "ASSET_INVENTORY"
    VULN_REMEDIATION_PLAN = "VULN_REMEDIATION_PLAN"
    UNAUTHORIZED_CHANGE = "UNAUTHORIZED_CHANGE"
    COMPLIANCE_GAP = "COMPLIANCE_GAP"
    IEC62443_EVIDENCE = "IEC62443_EVIDENCE"
    NERC_CIP_EVIDENCE = "NERC_CIP_EVIDENCE"
    NIS2_READINESS = "NIS2_READINESS"
    OTCC_READINESS = "OTCC_READINESS"
    INCIDENT_REPORT = "INCIDENT_REPORT"
    AI_DAILY_BRIEF = "AI_DAILY_BRIEF"


class ReportFormat(StrEnum):
    MARKDOWN = "MARKDOWN"
    HTML = "HTML"
    PDF = "PDF"


class IntegrationKind(StrEnum):
    SIEM_WEBHOOK = "SIEM_WEBHOOK"
    SPLUNK = "SPLUNK"
    SENTINEL = "SENTINEL"
    SERVICENOW = "SERVICENOW"
    JIRA = "JIRA"
    DEFENDER = "DEFENDER"
    OT_PLATFORM_IMPORT = "OT_PLATFORM_IMPORT"  # Claroty / Nozomi / Dragos
    VULN_SCANNER_IMPORT = "VULN_SCANNER_IMPORT"  # Tenable / Qualys / Rapid7
    OEM_IMPORT = "OEM_IMPORT"  # Siemens / Rockwell / Schneider / ABB / Honeywell / Emerson


class IntegrationDirection(StrEnum):
    EXPORT = "EXPORT"
    IMPORT = "IMPORT"


class AuditAction(StrEnum):
    LOGIN = "LOGIN"
    USER_PROVISION = "USER_PROVISION"
    ASSET_CREATE = "ASSET_CREATE"
    ASSET_UPDATE = "ASSET_UPDATE"
    ASSET_DELETE = "ASSET_DELETE"
    ASSET_IMPORT = "ASSET_IMPORT"
    ASSET_EXPORT = "ASSET_EXPORT"
    CONFIG_BASELINE = "CONFIG_BASELINE"
    CONFIG_SNAPSHOT = "CONFIG_SNAPSHOT"
    CHANGE_DISPOSITION = "CHANGE_DISPOSITION"
    DETECTION_STATUS_CHANGE = "DETECTION_STATUS_CHANGE"
    VULN_RISK_ACCEPTANCE = "VULN_RISK_ACCEPTANCE"
    VULN_STATUS_CHANGE = "VULN_STATUS_CHANGE"
    COMPLIANCE_EVIDENCE_UPLOAD = "COMPLIANCE_EVIDENCE_UPLOAD"
    CONTROL_STATUS_CHANGE = "CONTROL_STATUS_CHANGE"
    INCIDENT_CREATE = "INCIDENT_CREATE"
    INCIDENT_UPDATE = "INCIDENT_UPDATE"
    AI_PROMPT = "AI_PROMPT"
    AI_RESPONSE = "AI_RESPONSE"
    REPORT_GENERATE = "REPORT_GENERATE"
    INTEGRATION_EXPORT = "INTEGRATION_EXPORT"
    INTEGRATION_IMPORT = "INTEGRATION_IMPORT"
    INGEST = "INGEST"
    RISK_RECOMPUTE = "RISK_RECOMPUTE"


# --------------------------------------------------------------------------- #
# Discovery / ingestion
# --------------------------------------------------------------------------- #
class SourceType(StrEnum):
    PCAP_META = "PCAP_META"
    NETWORK_OBS = "NETWORK_OBS"
    SYSLOG = "SYSLOG"
    EDR = "EDR"
    FIREWALL = "FIREWALL"
    MANUAL = "MANUAL"
    SEED = "SEED"


class EventKind(StrEnum):
    ASSET_OBSERVED = "ASSET_OBSERVED"
    COMM_OBSERVED = "COMM_OBSERVED"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    EDR_ALERT = "EDR_ALERT"
    FIREWALL_EVENT = "FIREWALL_EVENT"
    CONFIG_HINT = "CONFIG_HINT"
    USB_EVENT = "USB_EVENT"


# --------------------------------------------------------------------------- #
# AI
# --------------------------------------------------------------------------- #
class AIProviderKind(StrEnum):
    LOCAL_FOUNDATION_SEC = "local_foundation_sec"
    OPENAI_COMPATIBLE = "openai_compatible"
    MOCK = "mock"


class AIUseCase(StrEnum):
    CHAT = "CHAT"
    ASSET_RISK = "ASSET_RISK"
    DAILY_BRIEF = "DAILY_BRIEF"
    VULN_IMPACT = "VULN_IMPACT"
    REMEDIATION_PLAN = "REMEDIATION_PLAN"
    COMPLIANCE_GAP = "COMPLIANCE_GAP"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    INCIDENT_SUMMARY = "INCIDENT_SUMMARY"
    EXEC_SUMMARY = "EXEC_SUMMARY"
    ALERT_TRANSLATE = "ALERT_TRANSLATE"
    NEXT_ACTION = "NEXT_ACTION"
    EVIDENCE_MAP = "EVIDENCE_MAP"


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
