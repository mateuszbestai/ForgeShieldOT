import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Loader2, Pencil, Trash2 } from "lucide-react";
import * as React from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { AiActionCard } from "@/components/ai/AiActionCard";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { RiskBadge } from "@/components/common/RiskBadge";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { aiApi, assetsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { canWrite, useAuth } from "@/lib/auth";
import { formatDate } from "@/lib/format";
import type { Asset, RiskResult } from "@/types/api";
import { ASSET_TYPE_LABELS, CRITICALITY_LABELS, titleCase } from "@/types/enums";

interface AssetDetailData {
  asset: Asset;
  protocols: Array<Record<string, unknown>>;
  vulnerabilities: Array<{ link: Record<string, unknown>; vulnerability: Record<string, unknown> }>;
  detections: Array<Record<string, unknown>>;
  config_changes: Array<Record<string, unknown>>;
  relationships: Array<Record<string, unknown>>;
  compliance_links: Array<{ evidence: Record<string, unknown>; control: Record<string, unknown> }>;
  risk: RiskResult;
}

export default function AssetDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const writable = canWrite(user?.role);
  const [editOpen, setEditOpen] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["asset", id],
    queryFn: () => assetsApi.get(id) as Promise<AssetDetailData>,
  });

  const deleteMut = useMutation({
    mutationFn: () => assetsApi.remove(id),
    onSuccess: () => {
      toast({ title: "Asset deleted", variant: "success" });
      qc.invalidateQueries({ queryKey: ["assets"] });
      navigate("/assets");
    },
    onError: (err) =>
      toast({ title: "Delete failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  if (isLoading) return <LoadingState label="Loading asset…" />;
  if (isError || !data)
    return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const { asset, protocols, vulnerabilities, detections, config_changes, relationships, compliance_links, risk } = data;

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm" className="-ml-2 w-fit">
        <Link to="/assets">
          <ArrowLeft className="h-4 w-4" /> Assets
        </Link>
      </Button>

      <PageHeader
        title={asset.asset_tag}
        description={`${ASSET_TYPE_LABELS[asset.asset_type] ?? asset.asset_type} · ${asset.hostname || asset.ip_address || "no host"}`}
        actions={
          <div className="flex items-center gap-2">
            <RiskBadge band={asset.risk_band} score={asset.risk_score} />
            {writable && (
              <>
                <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
                  <Pencil className="h-4 w-4" /> Edit
                </Button>
                <Button variant="outline" size="sm" onClick={() => setDeleteOpen(true)}>
                  <Trash2 className="h-4 w-4" /> Delete
                </Button>
              </>
            )}
          </div>
        }
      />

      {risk?.recommended_action && (
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Recommended action
            </p>
            <p className="mt-1 text-sm">{risk.recommended_action}</p>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="overview">
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="risk">Risk ({risk?.factors?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="protocols">Protocols ({protocols.length})</TabsTrigger>
          <TabsTrigger value="vulns">Vulnerabilities ({vulnerabilities.length})</TabsTrigger>
          <TabsTrigger value="detections">Detections ({detections.length})</TabsTrigger>
          <TabsTrigger value="changes">Changes ({config_changes.length})</TabsTrigger>
          <TabsTrigger value="rels">Relationships ({relationships.length})</TabsTrigger>
          <TabsTrigger value="compliance">Compliance ({compliance_links.length})</TabsTrigger>
          <TabsTrigger value="ai">Ask AI</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <Card>
            <CardContent className="grid grid-cols-2 gap-4 p-5 sm:grid-cols-3 lg:grid-cols-4">
              <Stat label="Asset tag" value={asset.asset_tag} mono />
              <Stat label="Hostname" value={asset.hostname} />
              <Stat label="IP address" value={asset.ip_address} mono />
              <Stat label="MAC" value={asset.mac_address} mono />
              <Stat label="Vendor" value={asset.vendor} />
              <Stat label="Model" value={asset.model} />
              <Stat label="Firmware" value={asset.firmware_version} mono />
              <Stat label="OS" value={asset.os_name} />
              <Stat label="Type" value={ASSET_TYPE_LABELS[asset.asset_type] ?? asset.asset_type} />
              <Stat label="Criticality" value={CRITICALITY_LABELS[asset.criticality] ?? asset.criticality} />
              <Stat label="Purdue level" value={`L${asset.purdue_level}`} />
              <Stat label="Area / Line" value={[asset.area, asset.process_line].filter(Boolean).join(" / ") || "—"} />
              <Stat label="Owner" value={asset.owner} />
              <Stat label="Support status" value={titleCase(asset.support_status)} />
              <Stat label="Patch status" value={titleCase(asset.patch_status)} />
              <Stat label="Safety impact" value={titleCase(asset.safety_impact)} />
              <Stat label="Backup available" value={asset.backup_available ? "Yes" : "No"} />
              <Stat label="Internet reachable" value={asset.internet_reachable ? "Yes" : "No"} />
              <Stat label="IT reachable" value={asset.it_reachable ? "Yes" : "No"} />
              <Stat label="Remote access" value={asset.remote_access_enabled ? "Enabled" : "Disabled"} />
              <Stat label="Last seen" value={formatDate(asset.last_seen)} />
            </CardContent>
          </Card>
          {asset.notes && (
            <Card className="mt-4">
              <CardHeader><CardTitle className="text-base">Notes</CardTitle></CardHeader>
              <CardContent><p className="text-sm text-muted-foreground">{asset.notes}</p></CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="risk">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                Risk breakdown <RiskBadge band={risk.band} score={risk.score} />
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {risk.top_factors?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {risk.top_factors.map((f, i) => (
                    <Badge key={i} variant="muted">{f}</Badge>
                  ))}
                </div>
              )}
              <div className="space-y-3">
                {risk.factors?.map((f) => (
                  <div key={f.key} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium">{f.label}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {f.points} / {f.max_points}
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${f.max_points ? Math.min(100, (f.points / f.max_points) * 100) : 0}%` }}
                      />
                    </div>
                    {f.detail && <p className="text-xs text-muted-foreground">{f.detail}</p>}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="protocols">
          <SimpleTable
            empty="No protocol observations."
            headers={["Protocol", "Port", "Direction", "Notes"]}
            rows={protocols.map((p) => [
              String(p.protocol ?? "—"),
              String(p.port ?? "—"),
              titleCase(String(p.direction ?? "")),
              String(p.notes ?? p.description ?? "—"),
            ])}
          />
        </TabsContent>

        <TabsContent value="vulns">
          {vulnerabilities.length === 0 ? (
            <SimpleEmpty text="No linked vulnerabilities." />
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>CVE</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>KEV</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vulnerabilities.map(({ link, vulnerability: v }) => (
                    <TableRow
                      key={String(v.id)}
                      className="cursor-pointer"
                      onClick={() => navigate(`/vulnerabilities/${v.id}`)}
                    >
                      <TableCell className="font-mono">{String(v.cve_id)}</TableCell>
                      <TableCell className="max-w-xs truncate">{String(v.title)}</TableCell>
                      <TableCell className="tabular-nums">{String(v.cvss_base)}</TableCell>
                      <TableCell>{v.known_exploited ? <Badge variant="destructive">KEV</Badge> : "—"}</TableCell>
                      <TableCell><StatusBadge status={String(link.status ?? "OPEN")} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="detections">
          {detections.length === 0 ? (
            <SimpleEmpty text="No detections for this asset." />
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Title</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Detected</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {detections.map((d) => (
                    <TableRow
                      key={String(d.id)}
                      className="cursor-pointer"
                      onClick={() => navigate(`/detections/${d.id}`)}
                    >
                      <TableCell>{String(d.title)}</TableCell>
                      <TableCell><SeverityBadge severity={String(d.severity)} /></TableCell>
                      <TableCell><StatusBadge status={String(d.status)} /></TableCell>
                      <TableCell className="text-muted-foreground">{formatDate(d.detected_at as string | null)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="changes">
          <SimpleTable
            empty="No configuration changes."
            headers={["Summary", "Disposition", "Detected"]}
            rows={config_changes.map((c) => [
              String(c.summary ?? "—"),
              titleCase(String(c.disposition ?? "")),
              formatDate(c.detected_at as string | null),
            ])}
          />
        </TabsContent>

        <TabsContent value="rels">
          <SimpleTable
            empty="No relationships."
            headers={["Type", "Protocol", "Flags"]}
            rows={relationships.map((r) => [
              titleCase(String(r.relationship_type ?? "")),
              String(r.protocol ?? "—"),
              [r.is_internet_path && "internet", r.is_unknown && "unknown"].filter(Boolean).join(", ") || "—",
            ])}
          />
        </TabsContent>

        <TabsContent value="compliance">
          {compliance_links.length === 0 ? (
            <SimpleEmpty text="No compliance evidence linked." />
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Control</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Evidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {compliance_links.map(({ evidence, control }, i) => (
                    <TableRow
                      key={i}
                      className="cursor-pointer"
                      onClick={() => navigate(`/compliance/controls/${control.id}`)}
                    >
                      <TableCell className="font-mono">{String(control.control_ref)}</TableCell>
                      <TableCell>{String(control.title)}</TableCell>
                      <TableCell className="text-muted-foreground">{String(evidence.description ?? "—")}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="ai" className="space-y-4">
          <AiActionCard
            title="Ask AI about this asset"
            description="Grounded risk analysis with safe OT actions only."
            buttonLabel="Analyze asset risk"
            mutationFn={() => aiApi.chat({ question: `Assess the OT risk for asset ${asset.asset_tag}.`, use_case: "ASSET_RISK", entity_id: asset.id })}
          />
          <AiActionCard
            title="Next best defensive action"
            description="The single safest next step, grounded in this asset's evidence."
            buttonLabel="Recommend next action"
            mutationFn={() => assetsApi.aiNextAction(asset.id)}
          />
          {writable && (
            <AiActionCard
              title="Model attack paths (defensive)"
              description="Map plausible ATT&CK-for-ICS paths across this asset's blast radius, with detection gaps and safe mitigations."
              buttonLabel="Simulate attack path"
              mutationFn={() => assetsApi.aiAttackPath(asset.id)}
            />
          )}
        </TabsContent>
      </Tabs>

      <EditAssetDialog asset={asset} open={editOpen} onOpenChange={setEditOpen} />
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete asset"
        description={`This permanently removes ${asset.asset_tag} and its links. This action cannot be undone.`}
        confirmLabel="Delete asset"
        destructive
        loading={deleteMut.isPending}
        onConfirm={() => deleteMut.mutate()}
      />
    </div>
  );
}

function SimpleEmpty({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-dashed py-10 text-center text-sm text-muted-foreground">
      {text}
    </div>
  );
}

function SimpleTable({ headers, rows, empty }: { headers: string[]; rows: string[][]; empty: string }) {
  if (rows.length === 0) return <SimpleEmpty text={empty} />;
  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            {headers.map((h) => (
              <TableHead key={h}>{h}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row, i) => (
            <TableRow key={i}>
              {row.map((cell, j) => (
                <TableCell key={j}>{cell}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function EditAssetDialog({
  asset,
  open,
  onOpenChange,
}: {
  asset: Asset;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [form, setForm] = React.useState({
    hostname: asset.hostname ?? "",
    ip_address: asset.ip_address ?? "",
    vendor: asset.vendor ?? "",
    model: asset.model ?? "",
    owner: asset.owner ?? "",
    notes: asset.notes ?? "",
  });

  React.useEffect(() => {
    setForm({
      hostname: asset.hostname ?? "",
      ip_address: asset.ip_address ?? "",
      vendor: asset.vendor ?? "",
      model: asset.model ?? "",
      owner: asset.owner ?? "",
      notes: asset.notes ?? "",
    });
  }, [asset]);

  const mutation = useMutation({
    mutationFn: () =>
      assetsApi.update(asset.id, {
        hostname: form.hostname || null,
        ip_address: form.ip_address || null,
        vendor: form.vendor || null,
        model: form.model || null,
        owner: form.owner || null,
        notes: form.notes || null,
      }),
    onSuccess: () => {
      toast({ title: "Asset updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["asset", asset.id] });
      qc.invalidateQueries({ queryKey: ["assets"] });
      onOpenChange(false);
    },
    onError: (err) =>
      toast({ title: "Update failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const set = (k: string, v: string) => setForm((p) => ({ ...p, [k]: v }));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit {asset.asset_tag}</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          {(["hostname", "ip_address", "vendor", "model", "owner"] as const).map((k) => (
            <div key={k} className="space-y-1.5">
              <Label className="text-xs capitalize">{k.replace("_", " ")}</Label>
              <Input value={form[k]} onChange={(e) => set(k, e.target.value)} />
            </div>
          ))}
          <div className="col-span-2 space-y-1.5">
            <Label className="text-xs">Notes</Label>
            <Input value={form.notes} onChange={(e) => set("notes", e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
