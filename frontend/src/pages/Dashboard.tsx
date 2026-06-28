import { useMutation, useQueries } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Boxes,
  Bug,
  GitCompareArrows,
  HelpCircle,
  Loader2,
  ShieldAlert,
  ShieldX,
  Sparkles,
} from "lucide-react";
import { Link } from "react-router-dom";
import { AnswerCard } from "@/components/ai/AnswerCard";
import { AttckIcsCoverageChart, type AttckRow } from "@/components/charts/AttckIcsCoverageChart";
import { BandDistribution } from "@/components/charts/BandDistribution";
import { ComplianceReadinessChart } from "@/components/charts/ComplianceReadinessChart";
import { CriticalityHeatmap } from "@/components/charts/CriticalityHeatmap";
import { RiskTrendChart } from "@/components/charts/RiskTrendChart";
import { VulnExposureChart } from "@/components/charts/VulnExposureChart";
import { ErrorState } from "@/components/common/ErrorState";
import { KpiCard } from "@/components/common/KpiCard";
import { CardGridLoading, LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { RiskBadge } from "@/components/common/RiskBadge";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  assetsApi,
  complianceApi,
  configApi,
  detectionsApi,
  incidentsApi,
  riskApi,
  vulnsApi,
  aiApi,
} from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useSiteStore } from "@/lib/siteStore";
import { formatRelative } from "@/lib/format";
import type { Asset, Detection, RiskRollup } from "@/types/api";

function num(v: unknown, fallback = 0): number {
  return typeof v === "number" ? v : fallback;
}

function AiDailyBrief() {
  const mutation = useMutation({
    mutationFn: () =>
      aiApi.chat({
        question: "Generate the OT security daily brief: top risks, urgent detections, and recommended safe actions.",
        use_case: "DAILY_BRIEF",
      }),
  });
  const error = mutation.error as ApiError | null;
  const errMsg =
    error?.status === 503
      ? "AI provider unreachable. Configure AI_BASE_URL/AI_API_KEY/AI_MODEL_NAME or set AI_PROVIDER=mock."
      : error?.message;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Sparkles className="h-4 w-4 text-primary" /> AI daily brief
        </CardTitle>
        <Button size="sm" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
          {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
          Generate
        </Button>
      </CardHeader>
      <CardContent>
        {mutation.isIdle && (
          <p className="text-sm text-muted-foreground">
            Generate a grounded, advisory-only summary of the most urgent OT risks for today.
          </p>
        )}
        {mutation.isPending && <LoadingState label="Composing daily brief…" />}
        {mutation.isError && (
          <div className="flex gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
            <AlertTriangle className="h-5 w-5 shrink-0 text-destructive" />
            <p className="text-muted-foreground">{errMsg}</p>
          </div>
        )}
        {mutation.data && <AnswerCard answer={mutation.data} />}
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const { siteId } = useSiteStore();

  const results = useQueries({
    queries: [
      { queryKey: ["risk-rollup", siteId], queryFn: () => riskApi.rollup(siteId ?? undefined) },
      {
        queryKey: ["assets-dash", siteId],
        queryFn: () => assetsApi.list({ site_id: siteId ?? undefined, limit: 500 }),
      },
      { queryKey: ["detection-stats"], queryFn: () => detectionsApi.stats() },
      { queryKey: ["vuln-stats"], queryFn: () => vulnsApi.stats() },
      { queryKey: ["incident-stats"], queryFn: () => incidentsApi.stats() },
      { queryKey: ["frameworks"], queryFn: () => complianceApi.frameworks() },
      {
        queryKey: ["recent-detections", siteId],
        queryFn: () => detectionsApi.list({ site_id: siteId ?? undefined, limit: 6 }),
      },
      {
        queryKey: ["recent-changes"],
        queryFn: () => configApi.changes({ limit: 6 }),
      },
    ],
  });

  const [rollupQ, assetsQ, detStatsQ, vulnStatsQ, incStatsQ, frameworksQ, recentDetQ, recentChgQ] =
    results;

  const isLoading = results.some((r) => r.isLoading);
  const isError = results.some((r) => r.isError);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" description="OT security posture at a glance." />
        <CardGridLoading count={8} />
        <LoadingState />
      </div>
    );
  }
  if (isError) {
    const firstErr = results.find((r) => r.isError)?.error as ApiError | undefined;
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" />
        <ErrorState message={firstErr?.message} onRetry={() => results.forEach((r) => r.refetch())} />
      </div>
    );
  }

  const rollup = rollupQ.data as RiskRollup;
  const assets = (assetsQ.data?.items ?? []) as Asset[];
  const detStats = (detStatsQ.data ?? {}) as Record<string, unknown>;
  const vulnStats = (vulnStatsQ.data ?? {}) as Record<string, unknown>;
  const incStats = (incStatsQ.data ?? {}) as Record<string, unknown>;
  const frameworks = (frameworksQ.data as { items?: Array<Record<string, unknown>> })?.items ?? [];
  const recentDetections = (recentDetQ.data?.items ?? []) as Detection[];
  const recentChanges =
    ((recentChgQ.data as { items?: Array<Record<string, unknown>> })?.items ?? []) as Array<
      Record<string, unknown>
    >;

  const criticalAssets = assets.filter((a) => a.criticality === "SAFETY_CRITICAL" || a.criticality === "HIGH").length;
  const unknownAssets = assets.filter((a) => !a.vendor || !a.model || a.asset_type === "OEM_VENDOR_SYSTEM").length;
  const openDetections = num(detStats.open);
  const kevVulns = num((vulnStats.kev as number) ?? (vulnStats.known_exploited as number));
  const incidentByStatus = (incStats.by_status ?? {}) as Record<string, number>;
  const openIncidents = num(incidentByStatus.OPEN) + num(incidentByStatus.INVESTIGATING);
  const unauthorizedChanges = recentChanges.filter((c) => c.disposition === "UNAUTHORIZED").length;

  // Average framework readiness
  const readinessVals = frameworks
    .map((f) => num((f.readiness as Record<string, unknown> | undefined)?.readiness_pct))
    .filter((v) => !Number.isNaN(v));
  const complianceScore =
    readinessVals.length > 0
      ? Math.round(readinessVals.reduce((a, b) => a + b, 0) / readinessVals.length)
      : 0;

  const frameworkReadiness = frameworks.map((f) => ({
    name: String(f.name ?? f.key ?? "—"),
    readiness_pct: num((f.readiness as Record<string, unknown> | undefined)?.readiness_pct),
  }));

  const vulnBands = (vulnStats.bands ?? {}) as Record<string, number>;

  // ATT&CK coverage from recent detections (group by technique)
  const attckMap = new Map<string, number>();
  for (const d of recentDetections) {
    const t = d.attck_ics_technique;
    if (t) attckMap.set(t, (attckMap.get(t) ?? 0) + 1);
  }
  const attckRows: AttckRow[] = Array.from(attckMap.entries()).map(([technique, count]) => ({
    technique,
    count,
  }));

  // Top risky assets
  const topAssets = [...assets].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="OT security posture at a glance — risk, detections, vulnerabilities and compliance."
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="Total assets" value={rollup.asset_count} icon={Boxes} accent="primary" />
        <KpiCard label="Critical assets" value={criticalAssets} icon={ShieldAlert} accent="high" />
        <KpiCard label="Unknown assets" value={unknownAssets} icon={HelpCircle} accent="medium" hint="Missing vendor/model" />
        <KpiCard label="Open detections" value={openDetections} icon={Activity} accent="high" />
        <KpiCard label="KEV vulnerabilities" value={kevVulns} icon={Bug} accent="critical" hint="Known exploited" />
        <KpiCard label="Unauthorized changes" value={unauthorizedChanges} icon={GitCompareArrows} accent="high" />
        <KpiCard label="Compliance score" value={`${complianceScore}%`} icon={BadgeCheck} accent={complianceScore >= 60 ? "low" : "medium"} />
        <KpiCard label="Open incidents" value={openIncidents} icon={ShieldX} accent="critical" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Risk trend (snapshot)</CardTitle>
          </CardHeader>
          <CardContent>
            <RiskTrendChart currentScore={rollup.average_score} />
            <p className="mt-2 text-xs text-muted-foreground">
              Synthesized snapshot ending at current average risk ({Math.round(rollup.average_score)}); not historical.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Risk band distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <BandDistribution bandCounts={rollup.band_counts} />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Criticality × risk heatmap</CardTitle>
          </CardHeader>
          <CardContent>
            <CriticalityHeatmap assets={assets} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Vulnerability exposure</CardTitle>
          </CardHeader>
          <CardContent>
            <VulnExposureChart bands={vulnBands} />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base">Recent detections</CardTitle>
            <Button asChild variant="link" size="sm">
              <Link to="/detections">View all</Link>
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentDetections.length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">No recent detections.</p>
            )}
            {recentDetections.map((d) => (
              <Link
                key={d.id}
                to={`/detections/${d.id}`}
                className="flex items-center justify-between gap-3 rounded-md border p-2.5 text-sm transition-colors hover:bg-accent/50"
              >
                <span className="min-w-0">
                  <span className="block truncate font-medium">{d.title}</span>
                  <span className="block text-xs text-muted-foreground">{formatRelative(d.detected_at)}</span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5">
                  <SeverityBadge severity={d.severity} />
                  <StatusBadge status={d.status} />
                </span>
              </Link>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base">Recent config changes</CardTitle>
            <Button asChild variant="link" size="sm">
              <Link to="/change-management">View all</Link>
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentChanges.length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">No recent changes.</p>
            )}
            {recentChanges.map((c) => (
              <Link
                key={String(c.id)}
                to="/change-management"
                className="flex items-center justify-between gap-3 rounded-md border p-2.5 text-sm transition-colors hover:bg-accent/50"
              >
                <span className="min-w-0">
                  <span className="block truncate font-medium">{String(c.summary || "Configuration change")}</span>
                  <span className="block text-xs text-muted-foreground">
                    {formatRelative(c.detected_at as string | null)}
                  </span>
                </span>
                <StatusBadge status={String(c.disposition ?? "UNREVIEWED")} />
              </Link>
            ))}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Compliance readiness</CardTitle>
          </CardHeader>
          <CardContent>
            <ComplianceReadinessChart frameworks={frameworkReadiness} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">ATT&CK for ICS coverage</CardTitle>
          </CardHeader>
          <CardContent>
            <AttckIcsCoverageChart data={attckRows} />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top risky assets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {topAssets.length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">No assets.</p>
            )}
            {topAssets.map((a) => (
              <Link
                key={a.id}
                to={`/assets/${a.id}`}
                className="flex items-center justify-between gap-3 rounded-md border p-2.5 text-sm transition-colors hover:bg-accent/50"
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono font-medium">{a.asset_tag}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {a.hostname || a.ip_address || "—"}
                  </span>
                </span>
                <RiskBadge band={a.risk_band} score={a.risk_score} />
              </Link>
            ))}
          </CardContent>
        </Card>

        <AiDailyBrief />
      </div>
    </div>
  );
}
