import { useQuery } from "@tanstack/react-query";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { type Column, DataTable } from "@/components/common/DataTable";
import { PageHeader } from "@/components/common/PageHeader";
import { Pagination } from "@/components/common/Pagination";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { vulnsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import type { Vulnerability } from "@/types/api";

const ALL = "__all__";
const PAGE_SIZE = 25;

function cvssColor(cvss: number): string {
  if (cvss >= 9) return "text-risk-critical";
  if (cvss >= 7) return "text-risk-high";
  if (cvss >= 4) return "text-risk-medium";
  return "text-risk-low";
}

export default function VulnsList() {
  const navigate = useNavigate();

  const [vendor, setVendor] = React.useState("");
  const [debouncedVendor, setDebouncedVendor] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [kevOnly, setKevOnly] = React.useState(false);
  const [minCvss, setMinCvss] = React.useState(ALL);
  const [offset, setOffset] = React.useState(0);

  React.useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(search.trim());
      setDebouncedVendor(vendor.trim());
      setOffset(0);
    }, 350);
    return () => clearTimeout(t);
  }, [search, vendor]);

  React.useEffect(() => setOffset(0), [kevOnly, minCvss]);

  const params = {
    vendor: debouncedVendor || undefined,
    known_exploited: kevOnly ? true : undefined,
    min_cvss: minCvss === ALL ? undefined : Number(minCvss),
    search: debouncedSearch || undefined,
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["vulns", params],
    queryFn: () => vulnsApi.list(params),
  });

  const columns: Column<Vulnerability>[] = [
    { key: "cve", header: "CVE", cell: (v) => <span className="font-mono font-medium">{v.cve_id}</span> },
    { key: "title", header: "Title", cell: (v) => <span className="line-clamp-1">{v.title}</span> },
    {
      key: "cvss",
      header: "CVSS",
      cell: (v) => <span className={`font-semibold tabular-nums ${cvssColor(v.cvss_base)}`}>{v.cvss_base.toFixed(1)}</span>,
    },
    { key: "kev", header: "KEV", cell: (v) => (v.known_exploited ? <Badge variant="destructive">KEV</Badge> : "—") },
    {
      key: "vp",
      header: "Vendor / Product",
      cell: (v) => <span className="text-muted-foreground">{[v.vendor, v.product].filter(Boolean).join(" / ") || "—"}</span>,
    },
    { key: "patch", header: "Patch", cell: (v) => (v.patch_available ? <Badge variant="muted">Available</Badge> : <Badge variant="muted">None</Badge>) },
  ];

  return (
    <div className="space-y-5">
      <PageHeader title="Vulnerabilities" description="OT-aware vulnerability catalog with KEV flags and CVSS." />

      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label className="text-xs">Search</Label>
          <Input placeholder="CVE, title…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-52" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Vendor</Label>
          <Input placeholder="e.g. Siemens" value={vendor} onChange={(e) => setVendor(e.target.value)} className="w-44" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Min CVSS</Label>
          <Select value={minCvss} onValueChange={setMinCvss}>
            <SelectTrigger className="h-9 w-[120px]"><SelectValue placeholder="Any" /></SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>Any</SelectItem>
              <SelectItem value="4">4.0+</SelectItem>
              <SelectItem value="7">7.0+</SelectItem>
              <SelectItem value="9">9.0+</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2 pb-2">
          <Switch id="kev" checked={kevOnly} onCheckedChange={setKevOnly} />
          <Label htmlFor="kev" className="text-sm">KEV only</Label>
        </div>
      </div>

      <DataTable
        columns={columns}
        rows={data?.items}
        rowKey={(v) => v.id}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as ApiError | undefined)?.message}
        onRetry={refetch}
        onRowClick={(v) => navigate(`/vulnerabilities/${v.id}`)}
        emptyTitle="No vulnerabilities"
        emptyMessage="No vulnerabilities match the current filters."
      />

      {data && data.total > 0 && (
        <Pagination total={data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      )}
    </div>
  );
}
