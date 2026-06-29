// Loosely-typed API shapes. The backend returns rich dicts; pages use these as
// a convenient surface. Unknown extra fields are tolerated.

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  is_demo_environment?: boolean;
}

export interface Asset {
  id: string;
  asset_tag: string;
  hostname: string | null;
  ip_address: string | null;
  mac_address: string | null;
  vendor: string | null;
  model: string | null;
  firmware_version: string | null;
  software_version: string | null;
  os_name: string | null;
  site_id: string;
  zone_id: string | null;
  area: string | null;
  process_line: string | null;
  purdue_level: number;
  asset_type: string;
  criticality: string;
  safety_impact: string;
  business_impact: string;
  owner: string | null;
  support_status: string;
  patch_status: string;
  backup_available: boolean;
  config_available: boolean;
  internet_reachable: boolean;
  it_reachable: boolean;
  remote_access_enabled: boolean;
  last_seen: string | null;
  risk_score: number;
  risk_band: string;
  compliance_tags: string[];
  notes: string | null;
  is_demo: boolean;
  [key: string]: unknown;
}

export interface RiskFactor {
  key: string;
  label: string;
  points: number;
  max_points: number;
  detail: string;
  record_refs: string[];
}

export interface RiskResult {
  score: number;
  band: string;
  factors: RiskFactor[];
  top_factors: string[];
  recommended_action: string;
}

export interface Detection {
  id: string;
  title: string;
  detection_type: string;
  severity: string;
  confidence: string;
  status: string;
  asset_id: string | null;
  site_id: string | null;
  description: string;
  attck_ics_technique: string | null;
  attck_ics_tactic: string | null;
  triage_steps: string[];
  safe_containment_steps: string[];
  ai_summary: string | null;
  detected_at: string | null;
  [key: string]: unknown;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  cvss_base: number;
  known_exploited: boolean;
  vendor: string | null;
  product: string | null;
  patch_available: boolean;
  safety_impact: string;
  remediation: string | null;
  [key: string]: unknown;
}

export interface Citation {
  ref: string;
  label: string;
}

export interface AttackPathStep {
  stage: string;
  technique_id: string;
  technique_name: string;
  rationale: string;
  detection_gap: string;
  mitigation: string;
}

export interface AIAnswer {
  conversation_id?: string;
  message_id?: string;
  use_case?: string;
  summary: string;
  findings: string[];
  citations: Citation[];
  confidence: string;
  assumptions: string[];
  safe_ot_actions: string[];
  attack_path?: AttackPathStep[];
  reasoning?: string | null;
  // "analysis" = grounded answer; "greeting"/"help"/"out_of_scope" = plain reply.
  intent?: string;
  // Clickable starter questions offered with capability/greeting replies.
  suggestions?: string[];
  disclaimer: string;
  provider_name?: string;
  model_name?: string;
  latency_ms?: number;
}

export interface RiskRollup {
  scope: string;
  asset_count: number;
  average_score: number;
  max_score: number;
  band_counts: Record<string, number>;
}

export interface Site {
  id: string;
  name: string;
  code: string;
  industry: string;
  location: string;
  [key: string]: unknown;
}

export interface NetworkMap {
  sites: Site[];
  zones: Array<Record<string, unknown>>;
  nodes: Array<{
    id: string;
    label: string;
    asset_type: string;
    purdue_level: number;
    zone_id: string | null;
    site_id: string;
    risk_band: string;
    risk_score: number;
    criticality: string;
    internet_reachable: boolean;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    protocol: string | null;
    relationship_type: string;
    is_unknown: boolean;
    is_internet_path: boolean;
    critical: boolean;
  }>;
}
