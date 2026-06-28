import { useQuery } from "@tanstack/react-query";
import { Boxes, Bug, Activity, ShieldAlert, BadgeCheck, Loader2, Search } from "lucide-react";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverAnchor } from "@/components/ui/popover";
import {
  assetsApi,
  complianceApi,
  detectionsApi,
  incidentsApi,
  vulnsApi,
} from "@/lib/api/endpoints";

interface SearchHit {
  id: string;
  label: string;
  sub: string;
  to: string;
  icon: React.ReactNode;
  group: string;
}

function useDebounced(value: string, delay = 300): string {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

export function GlobalSearch() {
  const [term, setTerm] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const debounced = useDebounced(term.trim());
  const navigate = useNavigate();

  const enabled = debounced.length >= 2;

  const { data: hits = [], isFetching } = useQuery<SearchHit[]>({
    queryKey: ["global-search", debounced],
    enabled,
    queryFn: async () => {
      const params = { search: debounced, limit: 5 };
      const [assets, vulns, detections, incidents, controls] = await Promise.allSettled([
        assetsApi.list(params),
        vulnsApi.list(params),
        detectionsApi.list(params),
        incidentsApi.list(params) as Promise<{ items: Array<Record<string, unknown>> }>,
        complianceApi.controls(params) as Promise<{ items: Array<Record<string, unknown>> }>,
      ]);
      const out: SearchHit[] = [];
      if (assets.status === "fulfilled") {
        for (const a of assets.value.items) {
          out.push({
            id: a.id,
            label: a.asset_tag,
            sub: a.hostname || a.ip_address || a.asset_type,
            to: `/assets/${a.id}`,
            icon: <Boxes className="h-4 w-4 text-muted-foreground" />,
            group: "Assets",
          });
        }
      }
      if (vulns.status === "fulfilled") {
        for (const v of vulns.value.items) {
          out.push({
            id: v.id,
            label: v.cve_id,
            sub: v.title,
            to: `/vulnerabilities/${v.id}`,
            icon: <Bug className="h-4 w-4 text-muted-foreground" />,
            group: "Vulnerabilities",
          });
        }
      }
      if (detections.status === "fulfilled") {
        for (const d of detections.value.items) {
          out.push({
            id: d.id,
            label: d.title,
            sub: d.detection_type,
            to: `/detections/${d.id}`,
            icon: <Activity className="h-4 w-4 text-muted-foreground" />,
            group: "Detections",
          });
        }
      }
      if (incidents.status === "fulfilled") {
        for (const i of incidents.value.items) {
          out.push({
            id: String(i.id),
            label: String(i.reference ?? i.title),
            sub: String(i.title),
            to: `/incidents/${i.id}`,
            icon: <ShieldAlert className="h-4 w-4 text-muted-foreground" />,
            group: "Incidents",
          });
        }
      }
      if (controls.status === "fulfilled") {
        for (const c of controls.value.items) {
          out.push({
            id: String(c.id),
            label: String(c.control_ref),
            sub: String(c.title),
            to: `/compliance/controls/${c.id}`,
            icon: <BadgeCheck className="h-4 w-4 text-muted-foreground" />,
            group: "Compliance",
          });
        }
      }
      return out;
    },
  });

  React.useEffect(() => {
    if (enabled) setOpen(true);
  }, [enabled, hits]);

  const go = (to: string) => {
    setOpen(false);
    setTerm("");
    navigate(to);
  };

  const groups = ["Assets", "Vulnerabilities", "Detections", "Incidents", "Compliance"];

  return (
    <Popover open={open && enabled} onOpenChange={setOpen}>
      <PopoverAnchor asChild>
        <form
          className="relative w-full max-w-md"
          onSubmit={(e) => {
            e.preventDefault();
            if (hits.length > 0) go(hits[0].to);
          }}
        >
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            onFocus={() => enabled && setOpen(true)}
            placeholder="Search assets, CVEs, detections, incidents, controls…"
            className="pl-9"
          />
          {isFetching && (
            <Loader2 className="absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-muted-foreground" />
          )}
        </form>
      </PopoverAnchor>
      <PopoverContent
        align="start"
        className="w-[min(28rem,90vw)] p-0"
        onOpenAutoFocus={(e) => e.preventDefault()}
      >
        {hits.length === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">
            {isFetching ? "Searching…" : `No results for “${debounced}”.`}
          </div>
        ) : (
          <div className="max-h-[60vh] overflow-y-auto py-1">
            {groups.map((group) => {
              const groupHits = hits.filter((h) => h.group === group);
              if (groupHits.length === 0) return null;
              return (
                <div key={group}>
                  <p className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    {group}
                  </p>
                  {groupHits.map((h) => (
                    <button
                      key={`${group}-${h.id}`}
                      onClick={() => go(h.to)}
                      className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors hover:bg-accent hover:text-accent-foreground"
                    >
                      {h.icon}
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-medium">{h.label}</span>
                        <span className="block truncate text-xs text-muted-foreground">{h.sub}</span>
                      </span>
                    </button>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
