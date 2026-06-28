import { FlaskConical } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function DemoBadge({ className }: { className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 border-risk-medium/40 bg-risk-medium/10 text-risk-medium",
        className,
      )}
    >
      <FlaskConical className="h-3 w-3" />
      Demo data
    </Badge>
  );
}
