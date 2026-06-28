// Mirror of backend app/core/enums.py (values are stable uppercase identifiers)
// plus human-readable labels for the UI.

export type RiskBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Confidence = "LOW" | "MEDIUM" | "HIGH";
export type Criticality = "LOW" | "MEDIUM" | "HIGH" | "SAFETY_CRITICAL";

export type AssetType =
  | "PLC" | "RTU" | "HMI" | "SCADA_SERVER" | "HISTORIAN" | "ENG_WORKSTATION"
  | "SAFETY_SIS" | "NETWORK_DEVICE" | "REMOTE_ACCESS_GATEWAY" | "IIOT_EDGE" | "OEM_VENDOR_SYSTEM";

export type DetectionStatus = "NEW" | "TRIAGING" | "CONFIRMED" | "FALSE_POSITIVE" | "RESOLVED";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "CLOSED";
export type ControlStatus = "NOT_STARTED" | "PARTIAL" | "IMPLEMENTED" | "NOT_APPLICABLE";
export type VulnStatus = "OPEN" | "PATCH_NOW" | "MITIGATE" | "MONITOR" | "RISK_ACCEPTED" | "REMEDIATED";

export const ASSET_TYPE_LABELS: Record<string, string> = {
  PLC: "PLC", RTU: "RTU", HMI: "HMI", SCADA_SERVER: "SCADA Server", HISTORIAN: "Historian",
  ENG_WORKSTATION: "Engineering Workstation", SAFETY_SIS: "Safety / SIS",
  NETWORK_DEVICE: "Network Device", REMOTE_ACCESS_GATEWAY: "Remote Access Gateway",
  IIOT_EDGE: "IIoT / Edge Gateway", OEM_VENDOR_SYSTEM: "OEM / Vendor System",
};

export const CRITICALITY_LABELS: Record<string, string> = {
  LOW: "Low", MEDIUM: "Medium", HIGH: "High", SAFETY_CRITICAL: "Safety-Critical",
};

export const RISK_BAND_LABELS: Record<string, string> = {
  LOW: "Low", MEDIUM: "Medium", HIGH: "High", CRITICAL: "Critical",
};

export const ROLE_LABELS: Record<string, string> = {
  ADMIN: "Administrator",
  OT_SECURITY_ENGINEER: "OT Security Engineer",
  SOC_ANALYST: "SOC Analyst",
  COMPLIANCE_OFFICER: "Compliance Officer",
  VIEWER: "Viewer",
};

export const FRAMEWORK_LABELS: Record<string, string> = {
  IEC_62443: "IEC 62443",
  NERC_CIP: "NERC CIP",
  TSA: "TSA Directives",
  NIS2: "NIS2",
  NCA_OTCC: "Saudi NCA OTCC",
  CISA_CPG: "CISA CPGs",
  ISO_27001: "ISO 27001",
  NIST_800_82: "NIST SP 800-82",
  MITRE_ATTCK_ICS: "MITRE ATT&CK for ICS",
};

export function titleCase(value: string | null | undefined): string {
  if (!value) return "—";
  return value
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
