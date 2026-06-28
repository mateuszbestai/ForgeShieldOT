import { useQuery } from "@tanstack/react-query";
import { Building2 } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { sitesApi } from "@/lib/api/endpoints";
import { useSiteStore } from "@/lib/siteStore";
import type { Site } from "@/types/api";

const ALL = "__all__";

export function SiteSelector() {
  const { siteId, setSiteId } = useSiteStore();
  const { data: sites } = useQuery<Site[]>({ queryKey: ["sites"], queryFn: sitesApi.list });

  return (
    <Select
      value={siteId ?? ALL}
      onValueChange={(v) => setSiteId(v === ALL ? null : v)}
    >
      <SelectTrigger className="h-9 w-[180px] gap-1.5">
        <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
        <SelectValue placeholder="All sites" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All sites</SelectItem>
        {(sites ?? []).map((s) => (
          <SelectItem key={s.id} value={s.id}>
            {s.name}
            {s.code ? ` (${s.code})` : ""}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
