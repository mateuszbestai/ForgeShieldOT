import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus } from "lucide-react";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { type Column, DataTable } from "@/components/common/DataTable";
import { PageHeader } from "@/components/common/PageHeader";
import { Pagination } from "@/components/common/Pagination";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Button } from "@/components/ui/button";
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
import { incidentsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";
import { formatRelative } from "@/lib/format";
import { useSiteStore } from "@/lib/siteStore";
import { titleCase } from "@/types/enums";

const ALL = "__all__";
const PAGE_SIZE = 25;
const STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SOC_ROLES = new Set(["ADMIN", "OT_SECURITY_ENGINEER", "SOC_ANALYST"]);

interface Incident {
  id: string;
  reference: string;
  title: string;
  severity: string;
  status: string;
  site_id: string | null;
  opened_at: string | null;
}

export default function IncidentsList() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const isSoc = SOC_ROLES.has(user?.role ?? "");
  const { siteId } = useSiteStore();

  const [status, setStatus] = React.useState(ALL);
  const [severity, setSeverity] = React.useState(ALL);
  const [offset, setOffset] = React.useState(0);
  const [newOpen, setNewOpen] = React.useState(false);

  React.useEffect(() => setOffset(0), [status, severity, siteId]);

  const params = {
    site_id: siteId ?? undefined,
    status: status === ALL ? undefined : status,
    severity: severity === ALL ? undefined : severity,
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["incidents", params],
    queryFn: () => incidentsApi.list(params) as Promise<{ items: Incident[]; total: number }>,
  });

  const columns: Column<Incident>[] = [
    { key: "ref", header: "Reference", cell: (i) => <span className="font-mono font-medium">{i.reference}</span> },
    { key: "title", header: "Title", cell: (i) => <span className="line-clamp-1">{i.title}</span> },
    { key: "sev", header: "Severity", cell: (i) => <SeverityBadge severity={i.severity} /> },
    { key: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
    { key: "opened", header: "Opened", cell: (i) => <span className="text-muted-foreground">{formatRelative(i.opened_at)}</span> },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Incidents"
        description="OT incident & case management with safe response checklists."
        actions={
          isSoc && (
            <Button size="sm" onClick={() => setNewOpen(true)}>
              <Plus className="h-4 w-4" /> New incident
            </Button>
          )
        }
      />

      <div className="flex flex-wrap gap-2">
        <FilterSelect value={status} onChange={setStatus} placeholder="All statuses" options={STATUSES} />
        <FilterSelect value={severity} onChange={setSeverity} placeholder="All severities" options={SEVERITIES} />
      </div>

      <DataTable
        columns={columns}
        rows={data?.items}
        rowKey={(i) => i.id}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as ApiError | undefined)?.message}
        onRetry={refetch}
        onRowClick={(i) => navigate(`/incidents/${i.id}`)}
        emptyTitle="No incidents"
        emptyMessage="No incidents match the current filters."
      />

      {data && data.total > 0 && (
        <Pagination total={data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      )}

      <NewIncidentDialog open={newOpen} onOpenChange={setNewOpen} />
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  options: string[];
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="h-9 w-[180px]"><SelectValue placeholder={placeholder} /></SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{placeholder}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o} value={o}>{titleCase(o)}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function NewIncidentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { siteId } = useSiteStore();
  const [title, setTitle] = React.useState("");
  const [severity, setSeverity] = React.useState("MEDIUM");
  const [summary, setSummary] = React.useState("");

  const mutation = useMutation({
    mutationFn: () =>
      incidentsApi.create({ title, severity, summary: summary || null, site_id: siteId ?? undefined }),
    onSuccess: (inc) => {
      const i = inc as Record<string, unknown>;
      toast({ title: "Incident created", variant: "success" });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      onOpenChange(false);
      navigate(`/incidents/${i.id}`);
    },
    onError: (err) => toast({ title: "Failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>New incident</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs">Title *</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {SEVERITIES.map((s) => (
                  <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Summary</Label>
            <Input value={summary} onChange={(e) => setSummary(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={!title || mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
