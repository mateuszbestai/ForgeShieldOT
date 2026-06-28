import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Sparkles } from "lucide-react";
import * as React from "react";
import { AnswerCard } from "@/components/ai/AnswerCard";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { type Column, DataTable } from "@/components/common/DataTable";
import { PageHeader } from "@/components/common/PageHeader";
import { Pagination } from "@/components/common/Pagination";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { configApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { canWrite, useAuth } from "@/lib/auth";
import { formatRelative } from "@/lib/format";
import type { AIAnswer } from "@/types/api";
import { titleCase } from "@/types/enums";

const ALL = "__all__";
const PAGE_SIZE = 25;
const DISPOSITIONS = ["UNREVIEWED", "AUTHORIZED", "UNAUTHORIZED"];

interface ConfigChange {
  id: string;
  asset_id: string;
  summary: string;
  diff: Array<{ field: string; before: unknown; after: unknown }>;
  disposition: string;
  change_ticket: string | null;
  within_approved_window: boolean;
  detected_at: string | null;
  [key: string]: unknown;
}

export default function ChangeManagement() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const writable = canWrite(user?.role);

  const [disposition, setDisposition] = React.useState(ALL);
  const [offset, setOffset] = React.useState(0);
  const [selected, setSelected] = React.useState<ConfigChange | null>(null);

  React.useEffect(() => setOffset(0), [disposition]);

  const params = {
    disposition: disposition === ALL ? undefined : disposition,
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["config-changes", params],
    queryFn: () => configApi.changes(params) as Promise<{ items: ConfigChange[]; total: number }>,
  });

  const columns: Column<ConfigChange>[] = [
    { key: "summary", header: "Change", cell: (c) => <span className="font-medium">{c.summary || "Configuration change"}</span> },
    {
      key: "ticket",
      header: "Ticket",
      cell: (c) => (c.change_ticket ? <span className="font-mono text-xs">{c.change_ticket}</span> : "—"),
    },
    {
      key: "window",
      header: "Window",
      cell: (c) =>
        c.within_approved_window ? (
          <Badge variant="muted">In window</Badge>
        ) : (
          <Badge variant="destructive">Out of window</Badge>
        ),
    },
    { key: "disp", header: "Disposition", cell: (c) => <StatusBadge status={c.disposition} /> },
    { key: "when", header: "Detected", cell: (c) => <span className="text-muted-foreground">{formatRelative(c.detected_at)}</span> },
  ];

  const unauthorizedCount = (data?.items ?? []).filter((c) => c.disposition === "UNAUTHORIZED").length;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Change Management"
        description="Detect and review configuration changes; flag unauthorized changes to critical assets."
      />

      {unauthorizedCount > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-risk-high/30 bg-risk-high/10 p-3 text-sm text-risk-high">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          {unauthorizedCount} unauthorized change{unauthorizedCount > 1 ? "s" : ""} on this page require review.
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <Select value={disposition} onValueChange={setDisposition}>
          <SelectTrigger className="h-9 w-[200px]"><SelectValue placeholder="All dispositions" /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All dispositions</SelectItem>
            {DISPOSITIONS.map((d) => (
              <SelectItem key={d} value={d}>{titleCase(d)}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        rows={data?.items}
        rowKey={(c) => c.id}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as ApiError | undefined)?.message}
        onRetry={refetch}
        onRowClick={(c) => setSelected(c)}
        emptyTitle="No changes"
        emptyMessage="No configuration changes match the filter."
      />

      {data && data.total > 0 && (
        <Pagination total={data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      )}

      <ChangeDialog
        change={selected}
        onClose={() => setSelected(null)}
        writable={writable}
        onChanged={() => {
          qc.invalidateQueries({ queryKey: ["config-changes"] });
          setSelected(null);
        }}
        toast={toast}
      />
    </div>
  );
}

function ChangeDialog({
  change,
  onClose,
  writable,
  onChanged,
  toast,
}: {
  change: ConfigChange | null;
  onClose: () => void;
  writable: boolean;
  onChanged: () => void;
  toast: (t: { title?: string; description?: string; variant?: "default" | "success" | "destructive" }) => void;
}) {
  const [confirm, setConfirm] = React.useState<{ disposition: string } | null>(null);
  const [ticket, setTicket] = React.useState("");
  const [aiAnswer, setAiAnswer] = React.useState<AIAnswer | null>(null);
  const [aiError, setAiError] = React.useState<string | null>(null);

  React.useEffect(() => {
    setAiAnswer(null);
    setAiError(null);
    setTicket(change?.change_ticket ?? "");
  }, [change]);

  const dispositionMut = useMutation({
    mutationFn: ({ disposition }: { disposition: string }) =>
      configApi.setDisposition(change!.id, { disposition, change_ticket: ticket || null }),
    onSuccess: () => {
      toast({ title: "Disposition saved", variant: "success" });
      onChanged();
    },
    onError: (err) => toast({ title: "Failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const aiMut = useMutation({
    mutationFn: () => configApi.aiExplain(change!.id),
    onSuccess: (a) => { setAiAnswer(a); setAiError(null); },
    onError: (err) => {
      const e = err as ApiError;
      setAiError(e.status === 503 ? "AI provider unreachable. Configure AI_BASE_URL or use mock." : e.message);
    },
  });

  if (!change) return null;

  return (
    <Dialog open={!!change} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {change.summary || "Configuration change"}
            <StatusBadge status={change.disposition} />
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Diff (before → after)</p>
            {change.diff && change.diff.length > 0 ? (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Field</TableHead>
                      <TableHead>Before</TableHead>
                      <TableHead>After</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {change.diff.map((d, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{d.field}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{String(d.before ?? "—")}</TableCell>
                        <TableCell className="font-mono text-xs text-risk-high">{String(d.after ?? "—")}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No structured diff recorded.</p>
            )}
          </div>

          {writable && (
            <div className="space-y-2">
              <Label className="text-xs">Change ticket (optional)</Label>
              <Input value={ticket} onChange={(e) => setTicket(e.target.value)} placeholder="e.g. CHG-2026-0042" />
              <div className="flex flex-wrap gap-2 pt-1">
                <Button size="sm" variant="outline" onClick={() => setConfirm({ disposition: "AUTHORIZED" })}>
                  Mark authorized
                </Button>
                <Button size="sm" variant="outline" onClick={() => setConfirm({ disposition: "UNAUTHORIZED" })}>
                  Mark unauthorized
                </Button>
                <Button size="sm" variant="outline" onClick={() => aiMut.mutate()} disabled={aiMut.isPending}>
                  {aiMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                  AI explain change
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => window.open(`${import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"}/api/config/changes/${change.id}/evidence-report`, "_blank")}
                >
                  Evidence report
                </Button>
              </div>
            </div>
          )}

          {aiError && <p className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-muted-foreground">{aiError}</p>}
          {aiAnswer && <AnswerCard answer={aiAnswer} />}
        </div>
      </DialogContent>

      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Mark ${confirm?.disposition === "AUTHORIZED" ? "authorized" : "unauthorized"}`}
        description="This disposition is recorded for audit."
        destructive={confirm?.disposition === "UNAUTHORIZED"}
        confirmLabel="Confirm"
        loading={dispositionMut.isPending}
        onConfirm={() =>
          confirm &&
          dispositionMut.mutate({ disposition: confirm.disposition }, { onSuccess: () => setConfirm(null) })
        }
      />
    </Dialog>
  );
}
