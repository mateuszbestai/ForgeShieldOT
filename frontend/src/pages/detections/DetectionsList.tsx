import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { type Column, DataTable } from "@/components/common/DataTable";
import { PageHeader } from "@/components/common/PageHeader";
import { Pagination } from "@/components/common/Pagination";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/components/ui/use-toast";
import { detectionsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";
import { formatRelative } from "@/lib/format";
import { useSiteStore } from "@/lib/siteStore";
import type { Detection } from "@/types/api";
import { titleCase } from "@/types/enums";

const ALL = "__all__";
const PAGE_SIZE = 25;
const STATUSES = ["NEW", "TRIAGING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const TYPES = [
  "ANOMALOUS_TRAFFIC",
  "UNAUTHORIZED_ACCESS",
  "MALWARE",
  "PROTOCOL_VIOLATION",
  "CONFIG_TAMPER",
  "ROGUE_DEVICE",
  "POLICY_VIOLATION",
];

const SOC_ROLES = new Set(["ADMIN", "OT_SECURITY_ENGINEER", "SOC_ANALYST"]);

export default function DetectionsList() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const isSoc = SOC_ROLES.has(user?.role ?? "");
  const { siteId } = useSiteStore();

  const [status, setStatus] = React.useState(ALL);
  const [severity, setSeverity] = React.useState(ALL);
  const [type, setType] = React.useState(ALL);
  const [offset, setOffset] = React.useState(0);

  React.useEffect(() => setOffset(0), [status, severity, type, siteId]);

  const params = {
    site_id: siteId ?? undefined,
    status: status === ALL ? undefined : status,
    severity: severity === ALL ? undefined : severity,
    detection_type: type === ALL ? undefined : type,
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["detections", params],
    queryFn: () => detectionsApi.list(params),
  });

  const statusMut = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      detectionsApi.update(id, { status: value }),
    onSuccess: () => {
      toast({ title: "Detection updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["detections"] });
    },
    onError: (err) =>
      toast({ title: "Update failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const columns: Column<Detection>[] = [
    { key: "title", header: "Detection", cell: (d) => <span className="font-medium">{d.title}</span> },
    { key: "type", header: "Type", cell: (d) => titleCase(d.detection_type) },
    { key: "sev", header: "Severity", cell: (d) => <SeverityBadge severity={d.severity} /> },
    { key: "conf", header: "Confidence", cell: (d) => <Badge variant="muted">{titleCase(d.confidence)}</Badge> },
    {
      key: "status",
      header: "Status",
      cell: (d) =>
        isSoc ? (
          <div onClick={(e) => e.stopPropagation()}>
            <Select value={d.status} onValueChange={(v) => statusMut.mutate({ id: d.id, value: v })}>
              <SelectTrigger className="h-7 w-[140px] text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                {STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        ) : (
          <Badge variant="muted">{titleCase(d.status)}</Badge>
        ),
    },
    {
      key: "attck",
      header: "ATT&CK",
      cell: (d) => (d.attck_ics_technique ? <span className="font-mono text-xs">{d.attck_ics_technique}</span> : "—"),
    },
    {
      key: "when",
      header: "Detected",
      cell: (d) => <span className="text-muted-foreground">{formatRelative(d.detected_at)}</span>,
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader title="Detections" description="Triage of simulated OT/ICS detections, mapped to ATT&CK for ICS." />

      <div className="flex flex-wrap gap-2">
        <FilterSelect value={status} onChange={setStatus} placeholder="All statuses" options={STATUSES} />
        <FilterSelect value={severity} onChange={setSeverity} placeholder="All severities" options={SEVERITIES} />
        <FilterSelect value={type} onChange={setType} placeholder="All types" options={TYPES} />
      </div>

      <DataTable
        columns={columns}
        rows={data?.items}
        rowKey={(d) => d.id}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as ApiError | undefined)?.message}
        onRetry={refetch}
        onRowClick={(d) => navigate(`/detections/${d.id}`)}
        emptyTitle="No detections"
        emptyMessage="No detections match the current filters."
      />

      {data && data.total > 0 && (
        <Pagination total={data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      )}
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
      <SelectTrigger className="h-9 w-[180px]">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{placeholder}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o} value={o}>{titleCase(o)}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
