import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { SEVERITY_BADGE_CLASSES } from "@/lib/riskBands";
import { titleCase } from "@/types/enums";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const key = (severity || "INFO").toUpperCase();
  const classes = SEVERITY_BADGE_CLASSES[key] ?? SEVERITY_BADGE_CLASSES.INFO;
  return (
    <Badge variant="outline" className={cn("border", classes, className)}>
      {titleCase(key)}
    </Badge>
  );
}
