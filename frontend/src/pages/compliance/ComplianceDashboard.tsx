import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link2, Loader2 } from "lucide-react";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { ComplianceReadinessChart } from "@/components/charts/ComplianceReadinessChart";
import { type Column, DataTable } from "@/components/common/DataTable";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Pagination } from "@/components/common/Pagination";
import { useToast } from "@/components/ui/use-toast";
import { complianceApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";
import { pct } from "@/lib/format";
import { FRAMEWORK_LABELS, titleCase } from "@/types/enums";

const ALL = "__all__";
const PAGE_SIZE = 25;
const STATUSES = ["NOT_STARTED", "PARTIAL", "IMPLEMENTED", "NOT_APPLICABLE"];
const COMPLIANCE_ROLES = new Set(["ADMIN", "COMPLIANCE_OFFICER", "OT_SECURITY_ENGINEER"]);

interface Framework {
  id: string;
  key: string;
  name: string;
  readiness: { readiness_pct: number; implemented: number; partial: number; not_started: number; total: number };
}
interface Control {
  id: string;
  framework_id: string;
  control_ref: string;
  title: string;
  status: string;
  owner: string | null;
}

export default function ComplianceDashboard() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const canManage = COMPLIANCE_ROLES.has(user?.role ?? "");

  const [framework, setFramework] = React.useState(ALL);
  const [status, setStatus] = React.useState(ALL);
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [offset, setOffset] = React.useState(0);

  React.useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(search.trim());
      setOffset(0);
    }, 350);
    return () => clearTimeout(t);
  }, [search]);
  React.useEffect(() => setOffset(0), [framework, status]);

  const [frameworksQ, gapQ] = useQueries({
    queries: [
      { queryKey: ["frameworks"], queryFn: () => complianceApi.frameworks() },
      { queryKey: ["gap-report"], queryFn: () => complianceApi.gapReport() },
    ],
  });

  const controlParams = {
    framework_id: framework === ALL ? undefined : framework,
    status: status === ALL ? undefined : status,
    search: debouncedSearch || undefined,
    limit: PAGE_SIZE,
    offset,
  };
  const controlsQ = useQuery({
    queryKey: ["controls", controlParams],
    queryFn: () => complianceApi.controls(controlParams) as Promise<{ items: Control[]; total: number }>,
  });

  const autoLinkMut = useMutation({
    mutationFn: () => complianceApi.autoLink(),
    onSuccess: (res) => {
      toast({ title: "Evidence auto-linked", description: `Created ${(res as { created?: number }).created ?? 0} links.`, variant: "success" });
      qc.invalidateQueries({ queryKey: ["frameworks"] });
      qc.invalidateQueries({ queryKey: ["controls"] });
    },
    onError: (err) => toast({ title: "Auto-link failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  if (frameworksQ.isLoading) return <LoadingState label="Loading compliance…" />;
  if (frameworksQ.isError)
    return <ErrorState message={(frameworksQ.error as ApiError | undefined)?.message} onRetry={frameworksQ.refetch} />;

  const frameworks = ((frameworksQ.data as { items?: Framework[] })?.items ?? []) as Framework[];
  const gapItems = ((gapQ.data as { items?: Array<Record<string, unknown>> })?.items ?? []);

  const chartData = frameworks.map((f) => ({
    name: FRAMEWORK_LABELS[f.key] ?? f.name,
    readiness_pct: f.readiness?.readiness_pct ?? 0,
  }));

  const columns: Column<Control>[] = [
    { key: "ref", header: "Control", cell: (c) => <span className="font-mono font-medium">{c.control_ref}</span> },
    { key: "title", header: "Title", cell: (c) => <span className="line-clamp-1">{c.title}</span> },
    { key: "status", header: "Status", cell: (c) => <StatusBadge status={c.status} /> },
    { key: "owner", header: "Owner", cell: (c) => <span className="text-muted-foreground">{c.owner || "—"}</span> },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance"
        description="Framework readiness, control status and evidence gaps."
        actions={
          canManage && (
            <Button size="sm" onClick={() => autoLinkMut.mutate()} disabled={autoLinkMut.isPending}>
              {autoLinkMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />}
              Auto-link evidence
            </Button>
          )
        }
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-base">Framework readiness</CardTitle></CardHeader>
          <CardContent><ComplianceReadinessChart frameworks={chartData} /></CardContent>
        </Card>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {frameworks.map((f) => (
            <Card key={f.id}>
              <CardContent className="p-4">
                <p className="text-sm font-semibold">{FRAMEWORK_LABELS[f.key] ?? f.name}</p>
                <p className="mt-1 text-2xl font-semibold tabular-nums text-primary">{pct(f.readiness?.readiness_pct)}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {f.readiness?.implemented ?? 0} implemented · {f.readiness?.partial ?? 0} partial · {f.readiness?.total ?? 0} controls
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">Controls</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Input placeholder="Search controls…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-52" />
            <Select value={framework} onValueChange={setFramework}>
              <SelectTrigger className="h-9 w-[180px]"><SelectValue placeholder="All frameworks" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All frameworks</SelectItem>
                {frameworks.map((f) => (
                  <SelectItem key={f.id} value={f.id}>{FRAMEWORK_LABELS[f.key] ?? f.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger className="h-9 w-[160px]"><SelectValue placeholder="All statuses" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All statuses</SelectItem>
                {STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <DataTable
            columns={columns}
            rows={controlsQ.data?.items}
            rowKey={(c) => c.id}
            isLoading={controlsQ.isLoading}
            isError={controlsQ.isError}
            errorMessage={(controlsQ.error as ApiError | undefined)?.message}
            onRetry={controlsQ.refetch}
            onRowClick={(c) => navigate(`/compliance/controls/${c.id}`)}
            emptyTitle="No controls"
          />
          {controlsQ.data && controlsQ.data.total > 0 && (
            <Pagination total={controlsQ.data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Gap report</CardTitle></CardHeader>
        <CardContent>
          {gapItems.length === 0 ? (
            <EmptyState title="No gaps" message="All scored controls are implemented or not applicable." />
          ) : (
            <ul className="space-y-2">
              {gapItems.slice(0, 12).map((g, i) => (
                <li
                  key={i}
                  className="flex cursor-pointer items-center justify-between gap-3 rounded-md border p-2.5 text-sm transition-colors hover:bg-accent/50"
                  onClick={() => g.control_id && navigate(`/compliance/controls/${g.control_id}`)}
                >
                  <span className="min-w-0">
                    <span className="block truncate font-mono font-medium">{String(g.control_ref ?? "—")}</span>
                    <span className="block truncate text-xs text-muted-foreground">{String(g.title ?? g.evidence_required ?? "")}</span>
                  </span>
                  <StatusBadge status={String(g.status ?? "NOT_STARTED")} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
