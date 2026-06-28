import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ClipboardList, Link2, Loader2, Sparkles } from "lucide-react";
import * as React from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { AnswerCard } from "@/components/ai/AnswerCard";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { Stat } from "@/components/common/Stat";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { vulnsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { canWrite, useAuth } from "@/lib/auth";
import { titleCase } from "@/types/enums";
import type { AIAnswer, Vulnerability } from "@/types/api";

interface VulnDetailData {
  vulnerability: Vulnerability;
  affected_assets: Array<{ link: Record<string, unknown>; asset: Record<string, unknown> }>;
}

const WORKFLOW = [
  { value: "PATCH_NOW", label: "Patch now" },
  { value: "MITIGATE", label: "Mitigate" },
  { value: "MONITOR", label: "Monitor" },
  { value: "RISK_ACCEPTED", label: "Accept risk" },
  { value: "REMEDIATED", label: "Remediated" },
];

export default function VulnDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const writable = canWrite(user?.role);

  const [remediationPlan, setRemediationPlan] = React.useState<string | null>(null);
  const [aiAnswer, setAiAnswer] = React.useState<AIAnswer | null>(null);
  const [aiError, setAiError] = React.useState<string | null>(null);
  const [acceptOpen, setAcceptOpen] = React.useState(false);
  const [pendingLink, setPendingLink] = React.useState<string | null>(null);
  const [reason, setReason] = React.useState("");

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["vuln", id],
    queryFn: () => vulnsApi.get(id) as Promise<VulnDetailData>,
  });

  const matchMut = useMutation({
    mutationFn: () => vulnsApi.match(id),
    onSuccess: () => {
      toast({ title: "Matched to assets", variant: "success" });
      qc.invalidateQueries({ queryKey: ["vuln", id] });
    },
    onError: (err) => toast({ title: "Match failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const statusMut = useMutation({
    mutationFn: ({ linkId, status, acceptance }: { linkId: string; status: string; acceptance?: Record<string, unknown> }) =>
      vulnsApi.setStatus(linkId, { status, acceptance }),
    onSuccess: () => {
      toast({ title: "Status updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["vuln", id] });
    },
    onError: (err) => toast({ title: "Update failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const planMut = useMutation({
    mutationFn: () => vulnsApi.remediationPlan(id) as Promise<{ remediation_plan: string }>,
    onSuccess: (res) => setRemediationPlan(res.remediation_plan),
    onError: (err) => toast({ title: "Plan failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const aiExplainMut = useMutation({
    mutationFn: () => vulnsApi.aiExplain(id),
    onSuccess: (a) => { setAiAnswer(a); setAiError(null); },
    onError: (err) => setAiError(aiErrorMessage(err as ApiError)),
  });

  const aiRemediationMut = useMutation({
    mutationFn: () => vulnsApi.aiRemediation(id),
    onSuccess: (a) => { setAiAnswer(a); setAiError(null); },
    onError: (err) => setAiError(aiErrorMessage(err as ApiError)),
  });

  if (isLoading) return <LoadingState label="Loading vulnerability…" />;
  if (isError || !data)
    return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const v = data.vulnerability;

  const changeStatus = (linkId: string, status: string) => {
    if (status === "RISK_ACCEPTED") {
      setPendingLink(linkId);
      setReason("");
      setAcceptOpen(true);
      return;
    }
    statusMut.mutate({ linkId, status });
  };

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm" className="-ml-2 w-fit">
        <Link to="/vulnerabilities"><ArrowLeft className="h-4 w-4" /> Vulnerabilities</Link>
      </Button>

      <PageHeader
        title={v.cve_id}
        description={v.title}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {v.known_exploited && <Badge variant="destructive">KEV</Badge>}
            <Badge variant="muted">CVSS {v.cvss_base.toFixed(1)}</Badge>
            {writable && (
              <Button variant="outline" size="sm" onClick={() => matchMut.mutate()} disabled={matchMut.isPending}>
                {matchMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />}
                Match to assets
              </Button>
            )}
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle className="text-base">Overview</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <Stat label="CVSS base" value={v.cvss_base.toFixed(1)} />
              <Stat label="Known exploited" value={v.known_exploited ? "Yes" : "No"} />
              <Stat label="Vendor" value={v.vendor} />
              <Stat label="Product" value={v.product} />
              <Stat label="Patch available" value={v.patch_available ? "Yes" : "No"} />
              <Stat label="Safety impact" value={titleCase(v.safety_impact)} />
            </div>
            {v.remediation && (
              <div className="space-y-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Remediation</p>
                <p className="text-sm">{v.remediation}</p>
              </div>
            )}
            {typeof v.description === "string" && v.description && (
              <div className="space-y-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Description</p>
                <p className="text-sm text-muted-foreground">{v.description}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {writable && (
          <Card>
            <CardHeader><CardTitle className="text-base">Actions</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              <Button variant="outline" className="w-full justify-start" onClick={() => planMut.mutate()} disabled={planMut.isPending}>
                {planMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ClipboardList className="h-4 w-4" />}
                Generate remediation plan
              </Button>
              <Button variant="outline" className="w-full justify-start" onClick={() => aiExplainMut.mutate()} disabled={aiExplainMut.isPending}>
                {aiExplainMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                AI impact explanation
              </Button>
              <Button variant="outline" className="w-full justify-start" onClick={() => aiRemediationMut.mutate()} disabled={aiRemediationMut.isPending}>
                {aiRemediationMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                AI remediation plan
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      {remediationPlan && (
        <Card>
          <CardHeader><CardTitle className="text-base">Remediation plan (deterministic)</CardTitle></CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap rounded-md bg-muted/40 p-4 text-sm">{remediationPlan}</pre>
          </CardContent>
        </Card>
      )}

      {aiError && (
        <Card className="border-destructive/30 bg-destructive/5">
          <CardContent className="p-4 text-sm text-muted-foreground">{aiError}</CardContent>
        </Card>
      )}
      {aiAnswer && <AnswerCard answer={aiAnswer} />}

      <Card>
        <CardHeader><CardTitle className="text-base">Affected assets ({data.affected_assets.length})</CardTitle></CardHeader>
        <CardContent>
          {data.affected_assets.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No assets linked yet. Use “Match to assets” to discover affected assets.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Status</TableHead>
                  {writable && <TableHead>Workflow</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.affected_assets.map(({ link, asset }) => (
                  <TableRow key={String(link.id)}>
                    <TableCell>
                      <Link className="font-mono text-primary hover:underline" to={`/assets/${asset.id}`}>
                        {String(asset.asset_tag)}
                      </Link>
                    </TableCell>
                    <TableCell>{titleCase(String(asset.asset_type))}</TableCell>
                    <TableCell className="tabular-nums">{String(link.priority_score ?? "—")}</TableCell>
                    <TableCell><StatusBadge status={String(link.status ?? "OPEN")} /></TableCell>
                    {writable && (
                      <TableCell>
                        <Select value="" onValueChange={(val) => changeStatus(String(link.id), val)}>
                          <SelectTrigger className="h-7 w-[140px] text-xs"><SelectValue placeholder="Set status…" /></SelectTrigger>
                          <SelectContent>
                            {WORKFLOW.map((w) => (
                              <SelectItem key={w.value} value={w.value}>{w.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={acceptOpen}
        onOpenChange={setAcceptOpen}
        title="Accept risk"
        description="Risk acceptance is recorded for audit. Provide a justification."
        confirmLabel="Accept risk"
        destructive
        loading={statusMut.isPending}
        onConfirm={() => {
          if (!pendingLink) return;
          statusMut.mutate(
            {
              linkId: pendingLink,
              status: "RISK_ACCEPTED",
              acceptance: { reason, accepted_by: user?.email ?? "unknown" },
            },
            { onSuccess: () => setAcceptOpen(false) },
          );
        }}
      >
        <div className="space-y-1.5">
          <Label className="text-xs">Justification *</Label>
          <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this risk accepted?" />
        </div>
      </ConfirmDialog>
    </div>
  );
}

function aiErrorMessage(e: ApiError): string {
  return e.status === 503
    ? "AI provider unreachable. Configure AI_BASE_URL/AI_API_KEY/AI_MODEL_NAME or set AI_PROVIDER=mock."
    : e.message;
}
