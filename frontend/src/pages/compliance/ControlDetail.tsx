import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Loader2, Plus } from "lucide-react";
import * as React from "react";
import { Link, useParams } from "react-router-dom";
import { AiActionCard } from "@/components/ai/AiActionCard";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/components/ui/use-toast";
import { complianceApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";
import { formatDate } from "@/lib/format";
import { FRAMEWORK_LABELS, titleCase } from "@/types/enums";

const STATUSES = ["NOT_STARTED", "PARTIAL", "IMPLEMENTED", "NOT_APPLICABLE"];
const COMPLIANCE_ROLES = new Set(["ADMIN", "COMPLIANCE_OFFICER", "OT_SECURITY_ENGINEER"]);

interface ControlDetailData {
  control: {
    id: string;
    control_ref: string;
    title: string;
    description: string;
    evidence_required: string;
    status: string;
    owner: string | null;
    due_date: string | null;
    last_reviewed: string | null;
    ai_gap_summary: string | null;
  };
  framework_key: string | null;
  framework_name: string | null;
  evidence: Array<{ evidence: Record<string, unknown>; source: Record<string, unknown> | null }>;
  is_gap: boolean;
}

export default function ControlDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const canManage = COMPLIANCE_ROLES.has(user?.role ?? "");
  const [evidenceOpen, setEvidenceOpen] = React.useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["control", id],
    queryFn: () => complianceApi.control(id) as Promise<ControlDetailData>,
  });

  const statusMut = useMutation({
    mutationFn: (status: string) => complianceApi.updateControl(id, { status }),
    onSuccess: () => {
      toast({ title: "Control updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["control", id] });
    },
    onError: (err) => toast({ title: "Update failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  if (isLoading) return <LoadingState label="Loading control…" />;
  if (isError || !data)
    return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const c = data.control;

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm" className="-ml-2 w-fit">
        <Link to="/compliance"><ArrowLeft className="h-4 w-4" /> Compliance</Link>
      </Button>

      <PageHeader
        title={`${c.control_ref} — ${c.title}`}
        description={data.framework_name ? FRAMEWORK_LABELS[data.framework_key ?? ""] ?? data.framework_name : undefined}
        actions={
          <div className="flex items-center gap-2">
            {data.is_gap && <Badge variant="destructive">Gap</Badge>}
            {canManage ? (
              <Select value={c.status} onValueChange={(v) => statusMut.mutate(v)}>
                <SelectTrigger className="h-9 w-[170px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <StatusBadge status={c.status} />
            )}
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle className="text-base">Control</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm leading-relaxed">{c.description || "—"}</p>
            {c.evidence_required && (
              <div className="space-y-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence required</p>
                <p className="text-sm">{c.evidence_required}</p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Status</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <Stat label="Status" value={titleCase(c.status)} />
            <Stat label="Owner" value={c.owner} />
            <Stat label="Due" value={formatDate(c.due_date)} />
            <Stat label="Last reviewed" value={formatDate(c.last_reviewed)} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Linked evidence ({data.evidence.length})</CardTitle>
          {canManage && (
            <Button size="sm" variant="outline" onClick={() => setEvidenceOpen(true)}>
              <Plus className="h-4 w-4" /> Add evidence
            </Button>
          )}
        </CardHeader>
        <CardContent className="space-y-2">
          {data.evidence.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">No evidence linked yet.</p>
          ) : (
            data.evidence.map((e, i) => (
              <div key={i} className="rounded-md border bg-muted/30 p-3 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <p className="font-medium">{String(e.evidence.description || e.evidence.file_name || "Evidence")}</p>
                  <div className="flex items-center gap-1.5">
                    {Boolean(e.evidence.auto_linked) && <Badge variant="muted">Auto-linked</Badge>}
                    <Badge variant="muted">{titleCase(String(e.evidence.source_type ?? "MANUAL"))}</Badge>
                  </div>
                </div>
                {e.source && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {String(e.source.label ?? e.source.asset_tag ?? e.source.title ?? "")}
                  </p>
                )}
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {canManage && (
        <AiActionCard
          title="AI gap summary"
          description="Summarize the gap and the evidence still required for this control."
          buttonLabel="Generate gap summary"
          mutationFn={() => complianceApi.aiGap(id)}
        />
      )}

      {c.ai_gap_summary && !canManage && (
        <Card className="border-primary/20">
          <CardHeader><CardTitle className="text-base">AI gap summary</CardTitle></CardHeader>
          <CardContent><p className="text-sm leading-relaxed">{c.ai_gap_summary}</p></CardContent>
        </Card>
      )}

      <AddEvidenceDialog controlId={id} open={evidenceOpen} onOpenChange={setEvidenceOpen} />
    </div>
  );
}

function AddEvidenceDialog({
  controlId,
  open,
  onOpenChange,
}: {
  controlId: string;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [description, setDescription] = React.useState("");
  const [fileName, setFileName] = React.useState("");

  const mutation = useMutation({
    mutationFn: () =>
      complianceApi.addEvidence({
        control_id: controlId,
        source_type: "MANUAL",
        description,
        file_name: fileName || null,
      }),
    onSuccess: () => {
      toast({ title: "Evidence added", variant: "success" });
      qc.invalidateQueries({ queryKey: ["control", controlId] });
      onOpenChange(false);
      setDescription("");
      setFileName("");
    },
    onError: (err) => toast({ title: "Failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>Add evidence</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs">Description *</Label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What evidence demonstrates this control?" />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">File name (metadata only)</Label>
            <Input value={fileName} onChange={(e) => setFileName(e.target.value)} placeholder="e.g. network-segmentation-policy.pdf" />
          </div>
          <p className="text-xs text-muted-foreground">No file bytes are stored — metadata only in this demo.</p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={!description || mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Add
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
