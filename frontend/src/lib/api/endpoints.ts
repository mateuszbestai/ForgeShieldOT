// Typed API surface for every backend domain. Pages import these.
import { api } from "./client";
import type {
  AIAnswer,
  Asset,
  Detection,
  NetworkMap,
  Paged,
  RiskResult,
  RiskRollup,
  Site,
  Vulnerability,
} from "../../types/api";

const unwrap = async <T>(p: Promise<{ data: T }>): Promise<T> => (await p).data;

// Local LLM inference — especially a *reasoning* model — routinely runs longer
// than the shared 90s client timeout. AI calls get a higher ceiling (above the
// backend's AI_TIMEOUT_SECONDS) so a slow-but-working answer surfaces as a real
// result, or as the backend's explicit 503 — never as the misleading
// "Cannot reach the API" axios-abort message.
const aiCfg = { timeout: 240_000 } as const;

export const authApi = {
  me: () => unwrap(api.get("/auth/me")),
  config: () => unwrap(api.get("/auth/config")),
};

export const sitesApi = {
  list: () => unwrap<Site[]>(api.get("/sites")),
  zones: (siteId: string) => unwrap(api.get(`/sites/${siteId}/zones`)),
};

export const assetsApi = {
  list: (params?: Record<string, unknown>) => unwrap<Paged<Asset>>(api.get("/assets", { params })),
  // Detail endpoints return a rich composite dict; callers cast to their own shape.
  get: (id: string) => unwrap<any>(api.get(`/assets/${id}`)),
  create: (body: Record<string, unknown>) => unwrap<Asset>(api.post("/assets", body)),
  update: (id: string, body: Record<string, unknown>) => unwrap<Asset>(api.patch(`/assets/${id}`, body)),
  remove: (id: string) => api.delete(`/assets/${id}`),
  exportCsv: () => api.get("/assets/export", { responseType: "text" }),
  importCsv: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return unwrap(api.post("/assets/import", fd, { headers: { "Content-Type": "multipart/form-data" } }));
  },
  aiAttackPath: (id: string) => unwrap<AIAnswer>(api.post(`/assets/${id}/ai-attack-path`, undefined, aiCfg)),
  aiNextAction: (id: string) => unwrap<AIAnswer>(api.post(`/assets/${id}/ai-next-action`, undefined, aiCfg)),
};

export const riskApi = {
  asset: (id: string) => unwrap<RiskResult & { asset_tag: string }>(api.get(`/risk/asset/${id}`)),
  rollup: (siteId?: string) => unwrap<RiskRollup>(api.get("/risk/rollup", { params: { site_id: siteId } })),
  recompute: () => unwrap(api.post("/risk/recompute")),
};

export const detectionsApi = {
  list: (params?: Record<string, unknown>) => unwrap<Paged<Detection>>(api.get("/detections", { params })),
  stats: () => unwrap<Record<string, unknown>>(api.get("/detections/stats")),
  get: (id: string) => unwrap<any>(api.get(`/detections/${id}`)),
  update: (id: string, body: Record<string, unknown>) => unwrap(api.patch(`/detections/${id}`, body)),
  aiTranslate: (id: string) => unwrap<AIAnswer>(api.post(`/detections/${id}/ai-translate`, undefined, aiCfg)),
  aiNextAction: (id: string) => unwrap<AIAnswer>(api.post(`/detections/${id}/ai-next-action`, undefined, aiCfg)),
};

export const vulnsApi = {
  list: (params?: Record<string, unknown>) => unwrap<Paged<Vulnerability>>(api.get("/vulnerabilities", { params })),
  stats: () => unwrap<Record<string, unknown>>(api.get("/vulnerabilities/stats")),
  get: (id: string) => unwrap<any>(api.get(`/vulnerabilities/${id}`)),
  assets: (id: string) => unwrap(api.get(`/vulnerabilities/${id}/assets`)),
  match: (id: string) => unwrap(api.post(`/vulnerabilities/${id}/match`)),
  setStatus: (linkId: string, body: Record<string, unknown>) =>
    unwrap(api.post(`/vulnerabilities/asset-links/${linkId}/status`, body)),
  remediationPlan: (id: string) => unwrap(api.post(`/vulnerabilities/${id}/remediation-plan`, undefined, aiCfg)),
  aiExplain: (id: string) => unwrap<AIAnswer>(api.post(`/vulnerabilities/${id}/ai-explain`, undefined, aiCfg)),
  aiRemediation: (id: string) => unwrap<AIAnswer>(api.post(`/vulnerabilities/${id}/ai-remediation`, undefined, aiCfg)),
};

export const configApi = {
  snapshots: (assetId?: string) => unwrap(api.get("/config/snapshots", { params: { asset_id: assetId } })),
  changes: (params?: Record<string, unknown>) => unwrap(api.get("/config/changes", { params })),
  change: (id: string) => unwrap(api.get(`/config/changes/${id}`)),
  setDisposition: (id: string, body: Record<string, unknown>) =>
    unwrap(api.post(`/config/changes/${id}/disposition`, body)),
  compare: (body: Record<string, unknown>) => unwrap(api.post("/config/compare", body)),
  setBaseline: (id: string) => unwrap(api.post(`/config/snapshots/${id}/baseline`)),
  aiExplain: (id: string) => unwrap<AIAnswer>(api.post(`/config/changes/${id}/ai-explain`, undefined, aiCfg)),
};

export const complianceApi = {
  frameworks: () => unwrap(api.get("/compliance/frameworks")),
  mapping: () => unwrap(api.get("/compliance/frameworks/mapping")),
  controls: (params?: Record<string, unknown>) => unwrap(api.get("/compliance/controls", { params })),
  control: (id: string) => unwrap(api.get(`/compliance/controls/${id}`)),
  updateControl: (id: string, body: Record<string, unknown>) => unwrap(api.patch(`/compliance/controls/${id}`, body)),
  addEvidence: (body: Record<string, unknown>) => unwrap(api.post("/compliance/evidence", body)),
  autoLink: () => unwrap(api.post("/compliance/auto-link")),
  gapReport: (frameworkId?: string) => unwrap(api.get("/compliance/gap-report", { params: { framework_id: frameworkId } })),
  aiGap: (id: string) => unwrap<AIAnswer>(api.post(`/compliance/controls/${id}/ai-gap`, undefined, aiCfg)),
  aiEvidenceMap: (id: string) => unwrap<AIAnswer>(api.post(`/compliance/controls/${id}/ai-evidence-map`, undefined, aiCfg)),
};

export const incidentsApi = {
  list: (params?: Record<string, unknown>) => unwrap(api.get("/incidents", { params })),
  stats: () => unwrap<Record<string, unknown>>(api.get("/incidents/stats")),
  get: (id: string) => unwrap(api.get(`/incidents/${id}`)),
  create: (body: Record<string, unknown>) => unwrap(api.post("/incidents", body)),
  fromDetection: (detectionId: string) => unwrap(api.post("/incidents/from-detection", { detection_id: detectionId })),
  update: (id: string, body: Record<string, unknown>) => unwrap(api.patch(`/incidents/${id}`, body)),
  addTimeline: (id: string, body: Record<string, unknown>) => unwrap(api.post(`/incidents/${id}/timeline`, body)),
  aiSummary: (id: string) => unwrap<AIAnswer>(api.post(`/incidents/${id}/ai-summary`, undefined, aiCfg)),
  aiExec: (id: string) => unwrap<AIAnswer>(api.post(`/incidents/${id}/ai-exec-summary`, undefined, aiCfg)),
  aiNextAction: (id: string) => unwrap<AIAnswer>(api.post(`/incidents/${id}/ai-next-action`, undefined, aiCfg)),
  checklist: () => unwrap<{ safe_ot_response_checklist: string[] }>(api.get("/incidents/checklist")),
};

export const reportsApi = {
  types: () => unwrap<any>(api.get("/reports/types")),
  list: (params?: Record<string, unknown>) => unwrap(api.get("/reports", { params })),
  generate: (body: Record<string, unknown>) => unwrap<any>(api.post("/reports/generate", body)),
  get: (id: string) => unwrap<any>(api.get(`/reports/${id}`)),
};

export const integrationsApi = {
  list: () => unwrap(api.get("/integrations")),
  get: (id: string) => unwrap(api.get(`/integrations/${id}`)),
  toggle: (id: string, enabled: boolean) => unwrap(api.post(`/integrations/${id}/toggle`, { enabled })),
  export: (id: string) => unwrap(api.post(`/integrations/${id}/export`)),
  simulateImport: (id: string) => unwrap(api.post(`/integrations/${id}/import`)),
};

export const aiApi = {
  chat: (body: { question: string; use_case?: string; entity_id?: string; conversation_id?: string }) =>
    unwrap<AIAnswer>(api.post("/ai/chat", body, aiCfg)),
  health: () => unwrap<Record<string, unknown>>(api.get("/ai/health")),
  conversations: () => unwrap(api.get("/ai/conversations")),
  messages: (conversationId: string) => unwrap(api.get(`/ai/conversations/${conversationId}/messages`)),
};

export const networkApi = {
  map: (siteId?: string) => unwrap<NetworkMap>(api.get("/network-map", { params: { site_id: siteId } })),
};

export const auditApi = {
  list: (params?: Record<string, unknown>) => unwrap(api.get("/audit-log", { params })),
};

export const ingestApi = {
  sources: () => unwrap<{ sources: Array<{ source: string; sample_payload: Record<string, unknown> }> }>(api.get("/ingest/sources")),
  ingest: (source: string, payload: Record<string, unknown>) => unwrap(api.post(`/ingest/${source.toLowerCase()}`, payload)),
};
