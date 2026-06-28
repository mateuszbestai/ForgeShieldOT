import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Loader2, Plug, Upload } from "lucide-react";
import * as React from "react";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/ui/use-toast";
import { integrationsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { canWrite, useAuth } from "@/lib/auth";
import { titleCase } from "@/types/enums";

interface Integration {
  id: string;
  kind: string;
  name: string;
  direction: string;
  enabled: boolean;
  is_mock: boolean;
  description: string | null;
}

export default function Integrations() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const writable = canWrite(user?.role);
  const [payload, setPayload] = React.useState<{ title: string; data: unknown } | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["integrations"],
    queryFn: () => integrationsApi.list() as Promise<{ items: Integration[]; notice?: string }>,
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => integrationsApi.toggle(id, enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
    onError: (err) => toast({ title: "Toggle failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const exportMut = useMutation({
    mutationFn: (id: string) => integrationsApi.export(id),
    onSuccess: (res) => setPayload({ title: "Simulated export payload", data: res }),
    onError: (err) => toast({ title: "Export failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const importMut = useMutation({
    mutationFn: (id: string) => integrationsApi.simulateImport(id),
    onSuccess: (res) => setPayload({ title: "Simulated import summary", data: res }),
    onError: (err) => toast({ title: "Import failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  if (isLoading) return <LoadingState label="Loading integrations…" />;
  if (isError) return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const items = data?.items ?? [];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Integrations"
        description={data?.notice ?? "All connectors are simulated/mock and read-only."}
      />

      {items.length === 0 ? (
        <EmptyState icon={Plug} title="No integrations" message="No connectors are configured." />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {items.map((it) => (
            <Card key={it.id}>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Plug className="h-4 w-4 text-primary" /> {it.name}
                  </CardTitle>
                  {writable && (
                    <Switch
                      checked={it.enabled}
                      onCheckedChange={(v) => toggleMut.mutate({ id: it.id, enabled: v })}
                    />
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <Badge variant="muted">{titleCase(it.kind)}</Badge>
                  <Badge variant="muted">{titleCase(it.direction)}</Badge>
                  {it.is_mock && <Badge variant="muted">Mock</Badge>}
                  <Badge variant={it.enabled ? "default" : "muted"}>{it.enabled ? "Enabled" : "Disabled"}</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">{it.description || "Simulated, read-only connector."}</p>
                <p className="text-xs italic text-muted-foreground">Simulated / read-only — no external systems are contacted.</p>
                <div className="flex gap-2">
                  {(it.direction === "EXPORT" || it.direction === "BIDIRECTIONAL") && (
                    <Button size="sm" variant="outline" disabled={!it.enabled || exportMut.isPending} onClick={() => exportMut.mutate(it.id)}>
                      {exportMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                      Export
                    </Button>
                  )}
                  {(it.direction === "IMPORT" || it.direction === "BIDIRECTIONAL") && (
                    <Button size="sm" variant="outline" disabled={!it.enabled || importMut.isPending} onClick={() => importMut.mutate(it.id)}>
                      {importMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                      Import
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={!!payload} onOpenChange={(o) => !o && setPayload(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader><DialogTitle>{payload?.title}</DialogTitle></DialogHeader>
          <pre className="max-h-[60vh] overflow-auto rounded-md bg-muted/40 p-4 text-xs">
            {JSON.stringify(payload?.data, null, 2)}
          </pre>
        </DialogContent>
      </Dialog>
    </div>
  );
}
