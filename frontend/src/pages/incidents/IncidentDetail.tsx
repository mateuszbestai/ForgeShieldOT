import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ClipboardCheck, FileText, Loader2, Plus, Sparkles } from "lucide-react";
import * as React from "react";
import { Link, useParams } from "react-router-dom";
import { AnswerCard } from "@/components/ai/AnswerCard";
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
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/use-toast";
import { incidentsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";
import { formatDate } from "@/lib/format";
import type { AIAnswer } from "@/types/api";
import { titleCase } from "@/types/enums";

const STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];
const SOC_ROLES = new Set(["ADMIN", "OT_SECURITY_ENGINEER", "SOC_ANALYST"]);

interface IncidentDetailData {
  incident: {
    id: string;
    reference: string;
    title: string;
    severity: string;
    status: string;
    summary: string;
    attck_ics_technique: string | null;
    lead_owner: string | null;
    containment_actions: string[];
    recovery_actions: string[];
    ai_summary: string | null;
    executive_summary: string | null;
    opened_at: string | null;
    closed_at: string | null;
  };
  timeline: Array<{ id: string; kind: string; description: string; occurred_at: string | null; author: string | null; ref: string | null }>;
  links: Array<{ link: Record<string, unknown>; summary: Record<string, unknown> | null }>;
  safe_ot_response_checklist: string[];
}

export default function IncidentDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const isSoc = SOC_ROLES.has(user?.role ?? "");

  const [noteOpen, setNoteOpen] = React.useState(false);
  const [aiAnswer, setAiAnswer] = React.useState<AIAnswer | null>(null);
  const [aiError, setAiError] = React.useState<string | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => incidentsApi.get(id) as Promise<IncidentDetailData>,
  });

  const statusMut = useMutation({
    mutationFn: (status: string) => incidentsApi.update(id, { status }),
    onSuccess: () => {
      toast({ title: "Status updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["incident", id] });
    },
    onError: (err) => toast({ title: "Update failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const aiSummaryMut = useMutation({
    mutationFn: () => incidentsApi.aiSummary(id),
    onSuccess: (a) => { setAiAnswer(a); setAiError(null); },
    onError: (err) => setAiError(aiMsg(err as ApiError)),
  });
  const aiExecMut = useMutation({
    mutationFn: () => incidentsApi.aiExec(id),
    onSuccess: (a) => { setAiAnswer(a); setAiError(null); },
    onError: (err) => setAiError(aiMsg(err as ApiError)),
  });
  const aiNextActionMut = useMutation({
    mutationFn: () => incidentsApi.aiNextAction(id),
    onSuccess: (a) => { setAiAnswer(a); setAiError(null); },
    onError: (err) => setAiError(aiMsg(err as ApiError)),
  });

  if (isLoading) return <LoadingState label="Loading incident…" />;
  if (isError || !data)
    return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const inc = data.incident;
  const reportUrl = `${import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"}/api/reports`;

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm" className="-ml-2 w-fit">
        <Link to="/incidents"><ArrowLeft className="h-4 w-4" /> Incidents</Link>
      </Button>

      <PageHeader
        title={`${inc.reference} — ${inc.title}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={inc.severity} />
            {isSoc ? (
              <Select value={inc.status} onValueChange={(v) => statusMut.mutate(v)}>
                <SelectTrigger className="h-9 w-[160px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <StatusBadge status={inc.status} />
            )}
            <Button variant="outline" size="sm" onClick={() => window.open(reportUrl, "_blank")}>
              <FileText className="h-4 w-4" /> Reports
            </Button>
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader><CardTitle className="text-base">Summary</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm leading-relaxed">{inc.summary || "—"}</p>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <Stat label="Status" value={titleCase(inc.status)} />
                <Stat label="Severity" value={titleCase(inc.severity)} />
                <Stat label="Lead owner" value={inc.lead_owner} />
                <Stat label="ATT&CK" value={inc.attck_ics_technique ? <span className="font-mono">{inc.attck_ics_technique}</span> : "—"} />
                <Stat label="Opened" value={formatDate(inc.opened_at)} />
                <Stat label="Closed" value={formatDate(inc.closed_at)} />
              </div>
            </CardContent>
          </Card>

          {/* Timeline */}
          <Card>
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <CardTitle className="text-base">Timeline</CardTitle>
              {isSoc && (
                <Button size="sm" variant="outline" onClick={() => setNoteOpen(true)}>
                  <Plus className="h-4 w-4" /> Add note
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {data.timeline.length === 0 ? (
                <p className="py-4 text-center text-sm text-muted-foreground">No timeline events yet.</p>
              ) : (
                <ol className="relative space-y-4 border-l pl-5">
                  {data.timeline.map((t) => (
                    <li key={t.id} className="relative">
                      <span className="absolute -left-[1.45rem] top-1 h-2.5 w-2.5 rounded-full border-2 border-card bg-primary" />
                      <div className="flex items-center gap-2">
                        <Badge variant="muted">{titleCase(t.kind)}</Badge>
                        <span className="text-xs text-muted-foreground">{formatDate(t.occurred_at)}</span>
                      </div>
                      <p className="mt-1 text-sm">{t.description}</p>
                      {t.author && <p className="text-xs text-muted-foreground">— {t.author}</p>}
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>

          {(inc.containment_actions?.length > 0 || inc.recovery_actions?.length > 0) && (
            <div className="grid gap-6 sm:grid-cols-2">
              {inc.containment_actions?.length > 0 && (
                <ActionList title="Containment actions" actions={inc.containment_actions} />
              )}
              {inc.recovery_actions?.length > 0 && (
                <ActionList title="Recovery actions" actions={inc.recovery_actions} />
              )}
            </div>
          )}

          {aiError && <Card className="border-destructive/30 bg-destructive/5"><CardContent className="p-4 text-sm text-muted-foreground">{aiError}</CardContent></Card>}
          {aiAnswer && <AnswerCard answer={aiAnswer} />}
        </div>

        <div className="space-y-6">
          {/* Safe OT response checklist */}
          <Card className="border-risk-low/30">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-1.5 text-base text-risk-low">
                <ClipboardCheck className="h-4 w-4" /> Safe OT response checklist
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {data.safe_ot_response_checklist.map((c, i) => (
                  <li key={i} className="flex gap-2 text-sm">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-risk-low" />
                    <span>{c}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Linked entities */}
          <Card>
            <CardHeader><CardTitle className="text-base">Linked records ({data.links.length})</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {data.links.length === 0 ? (
                <p className="py-2 text-center text-sm text-muted-foreground">No linked records.</p>
              ) : (
                data.links.map(({ link, summary }, i) => {
                  const type = String(link.link_type ?? "");
                  const entityId = String(link.entity_id ?? "");
                  const to =
                    type === "DETECTION" ? `/detections/${entityId}` : type === "ASSET" ? `/assets/${entityId}` : undefined;
                  const label = String(summary?.title ?? summary?.asset_tag ?? entityId);
                  const inner = (
                    <div className="flex items-center justify-between gap-2 rounded-md border p-2.5 text-sm">
                      <span className="min-w-0 truncate">{label}</span>
                      <Badge variant="muted">{titleCase(type)}</Badge>
                    </div>
                  );
                  return to ? (
                    <Link key={i} to={to} className="block transition-colors hover:opacity-80">{inner}</Link>
                  ) : (
                    <div key={i}>{inner}</div>
                  );
                })
              )}
            </CardContent>
          </Card>

          {isSoc && (
            <Card>
              <CardHeader><CardTitle className="text-base">AI analysis</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                <Button variant="outline" className="w-full justify-start" onClick={() => aiSummaryMut.mutate()} disabled={aiSummaryMut.isPending}>
                  {aiSummaryMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                  AI summary
                </Button>
                <Button variant="outline" className="w-full justify-start" onClick={() => aiExecMut.mutate()} disabled={aiExecMut.isPending}>
                  {aiExecMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                  AI executive summary
                </Button>
                <Button variant="outline" className="w-full justify-start" onClick={() => aiNextActionMut.mutate()} disabled={aiNextActionMut.isPending}>
                  {aiNextActionMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                  AI next action
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <AddNoteDialog incidentId={id} open={noteOpen} onOpenChange={setNoteOpen} />
    </div>
  );
}

function ActionList({ title, actions }: { title: string; actions: string[] }) {
  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle className="text-base">{title}</CardTitle></CardHeader>
      <CardContent>
        <ul className="space-y-1.5">
          {actions.map((a, i) => (
            <li key={i} className="flex gap-2 text-sm">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
              <span>{a}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function AddNoteDialog({ incidentId, open, onOpenChange }: { incidentId: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [description, setDescription] = React.useState("");

  const mutation = useMutation({
    mutationFn: () => incidentsApi.addTimeline(incidentId, { kind: "NOTE", description }),
    onSuccess: () => {
      toast({ title: "Note added", variant: "success" });
      qc.invalidateQueries({ queryKey: ["incident", incidentId] });
      onOpenChange(false);
      setDescription("");
    },
    onError: (err) => toast({ title: "Failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>Add timeline note</DialogTitle></DialogHeader>
        <div className="space-y-1.5">
          <Label className="text-xs">Note *</Label>
          <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={4} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={!description || mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Add note
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function aiMsg(e: ApiError): string {
  return e.status === 503
    ? "AI provider unreachable. Configure AI_BASE_URL/AI_API_KEY/AI_MODEL_NAME or set AI_PROVIDER=mock."
    : e.message;
}
