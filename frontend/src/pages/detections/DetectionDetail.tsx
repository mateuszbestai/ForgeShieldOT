import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ListChecks, Loader2, ShieldCheck, Siren } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { Stat } from "@/components/common/Stat";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/components/ui/use-toast";
import { detectionsApi, incidentsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";
import { formatDate } from "@/lib/format";
import type { Detection } from "@/types/api";
import { titleCase } from "@/types/enums";

const STATUSES = ["NEW", "TRIAGING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"];
const SOC_ROLES = new Set(["ADMIN", "OT_SECURITY_ENGINEER", "SOC_ANALYST"]);

interface DetectionDetailData {
  detection: Detection;
  evidence: Array<Record<string, unknown>>;
  asset: { id: string; asset_tag: string; risk_band: string; risk_score: number } | null;
}

export default function DetectionDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const isSoc = SOC_ROLES.has(user?.role ?? "");

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["detection", id],
    queryFn: () => detectionsApi.get(id) as Promise<DetectionDetailData>,
  });

  const statusMut = useMutation({
    mutationFn: (value: string) => detectionsApi.update(id, { status: value }),
    onSuccess: () => {
      toast({ title: "Status updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["detection", id] });
    },
    onError: (err) =>
      toast({ title: "Update failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const createIncidentMut = useMutation({
    mutationFn: () => incidentsApi.fromDetection(id),
    onSuccess: (inc) => {
      const i = inc as Record<string, unknown>;
      toast({ title: "Incident created", variant: "success" });
      navigate(`/incidents/${i.id}`);
    },
    onError: (err) =>
      toast({ title: "Could not create incident", description: (err as ApiError).message, variant: "destructive" }),
  });

  if (isLoading) return <LoadingState label="Loading detection…" />;
  if (isError || !data)
    return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const d = data.detection;

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm" className="-ml-2 w-fit">
        <Link to="/detections"><ArrowLeft className="h-4 w-4" /> Detections</Link>
      </Button>

      <PageHeader
        title={d.title}
        description={titleCase(d.detection_type)}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={d.severity} />
            {isSoc ? (
              <Select value={d.status} onValueChange={(v) => statusMut.mutate(v)}>
                <SelectTrigger className="h-9 w-[150px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <StatusBadge status={d.status} />
            )}
            {isSoc && (
              <Button size="sm" onClick={() => createIncidentMut.mutate()} disabled={createIncidentMut.isPending}>
                {createIncidentMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Siren className="h-4 w-4" />}
                Create incident
              </Button>
            )}
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader><CardTitle className="text-base">Description</CardTitle></CardHeader>
            <CardContent><p className="text-sm leading-relaxed">{d.description || "—"}</p></CardContent>
          </Card>

          {Array.isArray(d.triage_steps) && d.triage_steps.length > 0 && (
            <StepCard icon={<ListChecks className="h-4 w-4" />} title="Triage steps" steps={d.triage_steps} />
          )}

          {Array.isArray(d.safe_containment_steps) && d.safe_containment_steps.length > 0 && (
            <Card className="border-risk-low/30">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-1.5 text-base text-risk-low">
                  <ShieldCheck className="h-4 w-4" /> Safe containment steps
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ol className="space-y-2">
                  {(d.safe_containment_steps as string[]).map((s, i) => (
                    <li key={i} className="flex gap-2.5 text-sm">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-risk-low/15 text-xs font-semibold text-risk-low">
                        {i + 1}
                      </span>
                      <span>{s}</span>
                    </li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          )}

          {data.evidence.length > 0 && (
            <Card>
              <CardHeader><CardTitle className="text-base">Evidence</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {data.evidence.map((e, i) => (
                  <div key={i} className="rounded-md border bg-muted/30 p-3 text-sm">
                    <p className="font-medium">{String(e.label ?? e.kind ?? "Evidence")}</p>
                    <p className="text-muted-foreground">{String(e.detail ?? e.value ?? e.description ?? "")}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {d.ai_summary && (
            <Card className="border-primary/20">
              <CardHeader><CardTitle className="text-base">AI summary</CardTitle></CardHeader>
              <CardContent><p className="text-sm leading-relaxed">{d.ai_summary}</p></CardContent>
            </Card>
          )}
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader><CardTitle className="text-base">Details</CardTitle></CardHeader>
            <CardContent className="grid grid-cols-2 gap-4">
              <Stat label="Severity" value={titleCase(d.severity)} />
              <Stat label="Confidence" value={titleCase(d.confidence)} />
              <Stat label="Status" value={titleCase(d.status)} />
              <Stat label="Detected" value={formatDate(d.detected_at)} />
              <Stat label="ATT&CK tactic" value={d.attck_ics_tactic ? <span className="font-mono">{d.attck_ics_tactic}</span> : "—"} />
              <Stat label="ATT&CK technique" value={d.attck_ics_technique ? <span className="font-mono">{d.attck_ics_technique}</span> : "—"} />
            </CardContent>
          </Card>

          {data.asset && (
            <Card>
              <CardHeader><CardTitle className="text-base">Affected asset</CardTitle></CardHeader>
              <CardContent>
                <Link
                  to={`/assets/${data.asset.id}`}
                  className="flex items-center justify-between rounded-md border p-3 text-sm transition-colors hover:bg-accent/50"
                >
                  <span className="font-mono font-medium">{data.asset.asset_tag}</span>
                  <Badge variant="muted">Risk {Math.round(data.asset.risk_score)}</Badge>
                </Link>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function StepCard({ icon, title, steps }: { icon: React.ReactNode; title: string; steps: string[] }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-1.5 text-base">{icon} {title}</CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="space-y-2">
          {steps.map((s, i) => (
            <li key={i} className="flex gap-2.5 text-sm">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
                {i + 1}
              </span>
              <span>{s}</span>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
