import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, Loader2 } from "lucide-react";
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
import "@/styles/report.css";
import { renderMarkdown } from "@/lib/markdown";
import { reportsApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { canWrite, useAuth } from "@/lib/auth";
import { formatRelative } from "@/lib/format";
import { titleCase } from "@/types/enums";

interface ReportType {
  report_type: string;
  title: string;
  description: string;
}
interface Report {
  id: string;
  report_type: string;
  title: string;
  fmt: string;
  summary: string;
  content: string;
  created_at: string | null;
}

// Report types that accept an entity id parameter.
const ENTITY_PARAM: Record<string, { key: string; label: string }> = {
  INCIDENT_REPORT: { key: "incident_id", label: "Incident ID" },
  VULN_REMEDIATION_PLAN: { key: "vuln_id", label: "Vulnerability ID" },
};

export default function Reports() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const writable = canWrite(user?.role);

  const [genType, setGenType] = React.useState<string>("");
  const [entityId, setEntityId] = React.useState("");
  const [viewing, setViewing] = React.useState<Report | null>(null);

  const typesQ = useQuery({
    queryKey: ["report-types"],
    queryFn: () => reportsApi.types() as Promise<{ items: ReportType[] }>,
  });
  const reportsQ = useQuery({
    queryKey: ["reports"],
    queryFn: () => reportsApi.list({ limit: 50 }) as Promise<{ items: Report[]; total: number }>,
  });

  const generateMut = useMutation({
    mutationFn: () => {
      const param = ENTITY_PARAM[genType];
      const params = param && entityId ? { [param.key]: entityId } : {};
      return reportsApi.generate({ report_type: genType, params }) as Promise<Report>;
    },
    onSuccess: (report) => {
      toast({ title: "Report generated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["reports"] });
      setViewing(report);
      setEntityId("");
    },
    onError: (err) => toast({ title: "Generation failed", description: (err as ApiError).message, variant: "destructive" }),
  });

  const download = (report: Report) => {
    const blob = new Blob([report.content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.report_type.toLowerCase()}-${report.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (typesQ.isLoading) return <LoadingState label="Loading report types…" />;
  if (typesQ.isError)
    return <ErrorState message={(typesQ.error as ApiError | undefined)?.message} onRetry={typesQ.refetch} />;

  const types = typesQ.data?.items ?? [];
  const needsEntity = ENTITY_PARAM[genType];

  return (
    <div className="space-y-6">
      <PageHeader title="Reports" description="Generate and review simulated OT security reports (Markdown)." />

      {writable && (
        <Card>
          <CardHeader><CardTitle className="text-base">Generate a report</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap items-end gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs">Report type</Label>
              <Select value={genType} onValueChange={setGenType}>
                <SelectTrigger className="h-9 w-[280px]"><SelectValue placeholder="Select a report type" /></SelectTrigger>
                <SelectContent>
                  {types.map((t) => (
                    <SelectItem key={t.report_type} value={t.report_type}>{t.title}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {needsEntity && (
              <div className="space-y-1.5">
                <Label className="text-xs">{needsEntity.label} (optional)</Label>
                <Input value={entityId} onChange={(e) => setEntityId(e.target.value)} placeholder="UUID" className="w-64" />
              </div>
            )}
            <Button onClick={() => generateMut.mutate()} disabled={!genType || generateMut.isPending}>
              {generateMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
              Generate
            </Button>
          </CardContent>
        </Card>
      )}

      <div>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Available report types</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {types.map((t) => (
            <Card key={t.report_type}>
              <CardContent className="p-4">
                <p className="text-sm font-semibold">{t.title}</p>
                <p className="mt-1 text-xs text-muted-foreground">{t.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Generated reports</h2>
        {reportsQ.isLoading ? (
          <LoadingState />
        ) : reportsQ.isError ? (
          <ErrorState message={(reportsQ.error as ApiError | undefined)?.message} onRetry={reportsQ.refetch} />
        ) : (reportsQ.data?.items ?? []).length === 0 ? (
          <EmptyState title="No reports yet" message="Generate a report above to see it here." />
        ) : (
          <div className="space-y-2">
            {reportsQ.data!.items.map((r) => (
              <div key={r.id} className="flex items-center justify-between gap-3 rounded-md border p-3">
                <div className="min-w-0">
                  <p className="flex items-center gap-2 font-medium">
                    {r.title}
                    <Badge variant="muted">{titleCase(r.report_type)}</Badge>
                  </p>
                  <p className="truncate text-xs text-muted-foreground">
                    {r.summary} · {formatRelative(r.created_at)}
                  </p>
                </div>
                <div className="flex shrink-0 gap-2">
                  <Button size="sm" variant="outline" onClick={() => setViewing(r)}>View</Button>
                  <Button size="sm" variant="ghost" onClick={() => download(r)}>
                    <Download className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <Dialog open={!!viewing} onOpenChange={(o) => !o && setViewing(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {viewing?.title}
              {viewing && <Badge variant="muted">{titleCase(viewing.report_type)}</Badge>}
            </DialogTitle>
          </DialogHeader>
          {viewing && (
            <div
              className="prose-report max-h-[65vh] overflow-y-auto rounded-md border bg-muted/20 p-4 text-sm"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(viewing.content) }}
            />
          )}
          <DialogFooter>
            {viewing && (
              <Button variant="outline" onClick={() => download(viewing)}>
                <Download className="h-4 w-4" /> Download Markdown
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
