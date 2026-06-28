import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { STATUS_BADGE_CLASSES } from "@/lib/riskBands";
import { titleCase } from "@/types/enums";

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const key = (status || "").toUpperCase();
  const classes = STATUS_BADGE_CLASSES[key] ?? "bg-muted text-muted-foreground border-border";
  return (
    <Badge variant="outline" className={cn("border", classes, className)}>
      {titleCase(key)}
    </Badge>
  );
}
