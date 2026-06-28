import { useQuery } from "@tanstack/react-query";
import { Globe, HelpCircle, KeyRound } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { PageHeader } from "@/components/common/PageHeader";
import { NetworkLegend, PurdueGraph } from "@/components/network/PurdueGraph";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { networkApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import { useSiteStore } from "@/lib/siteStore";
import type { NetworkMap as NetworkMapType } from "@/types/api";

export default function NetworkMapPage() {
  const { siteId } = useSiteStore();
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["network-map", siteId],
    queryFn: () => networkApi.map(siteId ?? undefined),
  });

  if (isLoading) return <LoadingState label="Building network map…" />;
  if (isError || !data)
    return <ErrorState message={(error as ApiError | undefined)?.message} onRetry={refetch} />;

  const map = data as NetworkMapType;
  const nodeById = new Map(map.nodes.map((n) => [n.id, n]));

  const internetPaths = map.edges.filter((e) => e.is_internet_path);
  const remotePaths = map.edges.filter((e) => e.relationship_type === "REMOTE_ACCESS");
  const unknownPaths = map.edges.filter((e) => e.is_unknown);
  const internetNodes = map.nodes.filter((n) => n.internet_reachable);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Network Map — Purdue Model"
        description="Asset connectivity laid out by Purdue level. Node colour reflects risk band."
      />

      <div className="grid gap-5 lg:grid-cols-[1fr,320px]">
        <div className="space-y-3">
          <PurdueGraph map={map} />
          <Card>
            <CardContent className="p-4">
              <NetworkLegend />
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <WarningCard
            icon={<Globe className="h-4 w-4" />}
            title="Internet-exposed paths"
            count={internetPaths.length}
            accent="critical"
            description="Connectivity that traverses the internet boundary — highest priority to segment."
          >
            {internetNodes.length > 0 && (
              <ul className="space-y-1">
                {internetNodes.slice(0, 8).map((n) => (
                  <li key={n.id}>
                    <Link className="font-mono text-primary hover:underline" to={`/assets/${n.id}`}>
                      {n.label}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </WarningCard>

          <WarningCard
            icon={<KeyRound className="h-4 w-4" />}
            title="Remote-access paths"
            count={remotePaths.length}
            accent="high"
            description="Remote access into OT — verify MFA, jump hosts and monitoring."
          >
            <PathList edges={remotePaths} nodeById={nodeById} />
          </WarningCard>

          <WarningCard
            icon={<HelpCircle className="h-4 w-4" />}
            title="Unknown links"
            count={unknownPaths.length}
            accent="medium"
            description="Connections of unverified purpose — investigate and document."
          >
            <PathList edges={unknownPaths} nodeById={nodeById} />
          </WarningCard>
        </div>
      </div>
    </div>
  );
}

const ACCENT_BORDER: Record<string, string> = {
  critical: "border-risk-critical/30",
  high: "border-risk-high/30",
  medium: "border-risk-medium/30",
};
const ACCENT_TEXT: Record<string, string> = {
  critical: "text-risk-critical",
  high: "text-risk-high",
  medium: "text-risk-medium",
};

function WarningCard({
  icon,
  title,
  count,
  accent,
  description,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  accent: "critical" | "high" | "medium";
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <Card className={ACCENT_BORDER[accent]}>
      <CardHeader className="pb-2">
        <CardTitle className={`flex items-center justify-between gap-2 text-sm ${ACCENT_TEXT[accent]}`}>
          <span className="flex items-center gap-1.5">{icon} {title}</span>
          <span className="tabular-nums">{count}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-xs text-muted-foreground">
        <p>{description}</p>
        {count > 0 ? children : <p className="italic">None detected in this scope.</p>}
      </CardContent>
    </Card>
  );
}

function PathList({
  edges,
  nodeById,
}: {
  edges: NetworkMapType["edges"];
  nodeById: Map<string, NetworkMapType["nodes"][number]>;
}) {
  return (
    <ul className="space-y-1">
      {edges.slice(0, 8).map((e) => {
        const src = nodeById.get(e.source);
        const dst = nodeById.get(e.target);
        return (
          <li key={e.id} className="font-mono">
            {src?.label ?? "?"} → {dst?.label ?? "?"}
            {e.protocol ? ` (${e.protocol})` : ""}
          </li>
        );
      })}
    </ul>
  );
}
