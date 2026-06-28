import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { RISK_BADGE_CLASSES } from "@/lib/riskBands";
import { RISK_BAND_LABELS } from "@/types/enums";

interface RiskBadgeProps {
  band: string;
  score?: number;
  className?: string;
}

export function RiskBadge({ band, score, className }: RiskBadgeProps) {
  const key = (band || "LOW").toUpperCase();
  const classes = RISK_BADGE_CLASSES[key] ?? RISK_BADGE_CLASSES.LOW;
  const label = RISK_BAND_LABELS[key] ?? key;
  return (
    <Badge variant="outline" className={cn("border tabular-nums", classes, className)}>
      <span className="font-semibold">{label}</span>
      {score !== undefined && score !== null && (
        <span className="ml-1 opacity-80">{Math.round(score)}</span>
      )}
    </Badge>
  );
}
