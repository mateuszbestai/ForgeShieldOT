import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Loader2, Plus, Upload } from "lucide-react";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { type Column, DataTable } from "@/components/common/DataTable";
import { PageHeader } from "@/components/common/PageHeader";
import { Pagination } from "@/components/common/Pagination";
import { RiskBadge } from "@/components/common/RiskBadge";
import { Badge } from "@/components/ui/badge";
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
import { assetsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useAuth, canWrite } from "@/lib/auth";
import { formatRelative } from "@/lib/format";
import { useSiteStore } from "@/lib/siteStore";
import type { Asset } from "@/types/api";
import {
  ASSET_TYPE_LABELS,
  CRITICALITY_LABELS,
  RISK_BAND_LABELS,
  titleCase,
} from "@/types/enums";

const ALL = "__all__";
const PAGE_SIZE = 25;

const ASSET_TYPES = Object.keys(ASSET_TYPE_LABELS);
const CRITICALITIES = ["LOW", "MEDIUM", "HIGH", "SAFETY_CRITICAL"];
const BANDS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export default function AssetsList() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const writable = canWrite(user?.role);
  const qc = useQueryClient();
  const { toast } = useToast();
  const { siteId } = useSiteStore();

  const [type, setType] = React.useState<string>(ALL);
  const [criticality, setCriticality] = React.useState<string>(ALL);
  const [band, setBand] = React.useState<string>(ALL);
  const [purdue, setPurdue] = React.useState<string>(ALL);
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [offset, setOffset] = React.useState(0);
  const [addOpen, setAddOpen] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(search.trim());
      setOffset(0);
    }, 350);
    return () => clearTimeout(t);
  }, [search]);

  React.useEffect(() => setOffset(0), [type, criticality, band, purdue, siteId]);

  const params = {
    site_id: siteId ?? undefined,
    asset_type: type === ALL ? undefined : type,
    criticality: criticality === ALL ? undefined : criticality,
    risk_band: band === ALL ? undefined : band,
    purdue_level: purdue === ALL ? undefined : Number(purdue),
    search: debouncedSearch || undefined,
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["assets", params],
    queryFn: () => assetsApi.list(params),
  });

  const importMut = useMutation({
    mutationFn: (file: File) => assetsApi.importCsv(file),
    onSuccess: (res) => {
      const r = res as Record<string, unknown>;
      toast({
        title: "CSV imported",
        description: `Created ${r.created ?? 0}, updated ${r.updated ?? 0}.`,
        variant: "success",
      });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (err) =>
      toast({ title: "Import failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const handleExport = async () => {
    try {
      const res = await assetsApi.exportCsv();
      const blob = new Blob([res.data as string], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "forgeshield-assets.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast({ title: "Export failed", description: (err as ApiError).message, variant: "destructive" });
    }
  };

  const columns: Column<Asset>[] = [
    { key: "tag", header: "Tag", cell: (a) => <span className="font-mono font-medium">{a.asset_tag}</span> },
    {
      key: "host",
      header: "Host / IP",
      cell: (a) => (
        <span className="text-muted-foreground">{a.hostname || a.ip_address || "—"}</span>
      ),
    },
    { key: "type", header: "Type", cell: (a) => ASSET_TYPE_LABELS[a.asset_type] ?? a.asset_type },
    {
      key: "vendor",
      header: "Vendor / Model",
      cell: (a) => (a.vendor || a.model ? `${a.vendor ?? "—"} ${a.model ?? ""}`.trim() : "—"),
    },
    { key: "purdue", header: "Purdue", cell: (a) => <Badge variant="muted">L{a.purdue_level}</Badge> },
    { key: "crit", header: "Criticality", cell: (a) => CRITICALITY_LABELS[a.criticality] ?? a.criticality },
    { key: "risk", header: "Risk", cell: (a) => <RiskBadge band={a.risk_band} score={a.risk_score} /> },
    {
      key: "seen",
      header: "Last seen",
      cell: (a) => <span className="text-muted-foreground">{formatRelative(a.last_seen)}</span>,
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Asset Inventory"
        description="OT/ICS asset register with risk scoring and criticality."
        actions={
          <>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) importMut.mutate(f);
                e.target.value = "";
              }}
            />
            {writable && (
              <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={importMut.isPending}>
                {importMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                Import CSV
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4" /> Export CSV
            </Button>
            {writable && (
              <Button size="sm" onClick={() => setAddOpen(true)}>
                <Plus className="h-4 w-4" /> Add asset
              </Button>
            )}
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search tag, host, IP…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full max-w-xs"
        />
        <FilterSelect value={type} onChange={setType} placeholder="All types" options={ASSET_TYPES} labels={ASSET_TYPE_LABELS} />
        <FilterSelect value={criticality} onChange={setCriticality} placeholder="All criticality" options={CRITICALITIES} labels={CRITICALITY_LABELS} />
        <FilterSelect value={band} onChange={setBand} placeholder="All risk" options={BANDS} labels={RISK_BAND_LABELS} />
        <Select value={purdue} onValueChange={setPurdue}>
          <SelectTrigger className="h-9 w-[130px]">
            <SelectValue placeholder="All levels" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All levels</SelectItem>
            {[0, 1, 2, 3, 4, 5].map((l) => (
              <SelectItem key={l} value={String(l)}>
                Level {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        rows={data?.items}
        rowKey={(a) => a.id}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as ApiError | undefined)?.message}
        onRetry={refetch}
        onRowClick={(a) => navigate(`/assets/${a.id}`)}
        emptyTitle="No assets found"
        emptyMessage="Try adjusting filters, or import an asset CSV."
      />

      {data && data.total > 0 && (
        <Pagination total={data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      )}

      <AddAssetDialog open={addOpen} onOpenChange={setAddOpen} />
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
  labels,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  options: string[];
  labels: Record<string, string>;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="h-9 w-[170px]">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{placeholder}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o} value={o}>
            {labels[o] ?? titleCase(o)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function AddAssetDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { siteId } = useSiteStore();
  const [form, setForm] = React.useState({
    asset_tag: "",
    hostname: "",
    ip_address: "",
    vendor: "",
    model: "",
    asset_type: "PLC",
    criticality: "MEDIUM",
    purdue_level: "2",
  });

  const mutation = useMutation({
    mutationFn: () =>
      assetsApi.create({
        asset_tag: form.asset_tag,
        hostname: form.hostname || null,
        ip_address: form.ip_address || null,
        vendor: form.vendor || null,
        model: form.model || null,
        asset_type: form.asset_type,
        criticality: form.criticality,
        purdue_level: Number(form.purdue_level),
        site_id: siteId ?? undefined,
      }),
    onSuccess: (asset) => {
      toast({ title: "Asset created", variant: "success" });
      qc.invalidateQueries({ queryKey: ["assets"] });
      onOpenChange(false);
      navigate(`/assets/${asset.id}`);
    },
    onError: (err) =>
      toast({ title: "Could not create asset", description: (err as ApiError).message, variant: "destructive" }),
  });

  const set = (k: string, v: string) => setForm((p) => ({ ...p, [k]: v }));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add asset</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Asset tag *">
            <Input value={form.asset_tag} onChange={(e) => set("asset_tag", e.target.value)} />
          </Field>
          <Field label="Hostname">
            <Input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} />
          </Field>
          <Field label="IP address">
            <Input value={form.ip_address} onChange={(e) => set("ip_address", e.target.value)} />
          </Field>
          <Field label="Vendor">
            <Input value={form.vendor} onChange={(e) => set("vendor", e.target.value)} />
          </Field>
          <Field label="Model">
            <Input value={form.model} onChange={(e) => set("model", e.target.value)} />
          </Field>
          <Field label="Type">
            <Select value={form.asset_type} onValueChange={(v) => set("asset_type", v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {Object.keys(ASSET_TYPE_LABELS).map((t) => (
                  <SelectItem key={t} value={t}>{ASSET_TYPE_LABELS[t]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Criticality">
            <Select value={form.criticality} onValueChange={(v) => set("criticality", v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {["LOW", "MEDIUM", "HIGH", "SAFETY_CRITICAL"].map((c) => (
                  <SelectItem key={c} value={c}>{CRITICALITY_LABELS[c]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Purdue level">
            <Select value={form.purdue_level} onValueChange={(v) => set("purdue_level", v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {[0, 1, 2, 3, 4, 5].map((l) => (
                  <SelectItem key={l} value={String(l)}>Level {l}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={!form.asset_tag || mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs">{label}</Label>
      {children}
    </div>
  );
}
