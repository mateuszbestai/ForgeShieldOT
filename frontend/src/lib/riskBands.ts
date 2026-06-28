// Centralized risk/severity → color + label mapping used by badges and charts.

export type BandKey = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

// Tailwind utility classes (token-driven via index.css risk-* vars).
export const RISK_BADGE_CLASSES: Record<string, string> = {
  LOW: "bg-risk-low/15 text-risk-low border-risk-low/30",
  MEDIUM: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  HIGH: "bg-risk-high/15 text-risk-high border-risk-high/30",
  CRITICAL: "bg-risk-critical/15 text-risk-critical border-risk-critical/30",
};

export const SEVERITY_BADGE_CLASSES: Record<string, string> = {
  INFO: "bg-muted text-muted-foreground border-border",
  LOW: "bg-risk-low/15 text-risk-low border-risk-low/30",
  MEDIUM: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  HIGH: "bg-risk-high/15 text-risk-high border-risk-high/30",
  CRITICAL: "bg-risk-critical/15 text-risk-critical border-risk-critical/30",
};

// Hex-ish HSL strings for charts (Recharts needs concrete colors).
export const RISK_HEX: Record<string, string> = {
  LOW: "hsl(152 55% 42%)",
  MEDIUM: "hsl(38 92% 50%)",
  HIGH: "hsl(22 90% 52%)",
  CRITICAL: "hsl(0 72% 52%)",
};

export function bandForScore(score: number): BandKey {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

export const STATUS_BADGE_CLASSES: Record<string, string> = {
  // Detection / incident / control statuses → calm semantic colors.
  NEW: "bg-primary/15 text-primary border-primary/30",
  TRIAGING: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  CONFIRMED: "bg-risk-high/15 text-risk-high border-risk-high/30",
  FALSE_POSITIVE: "bg-muted text-muted-foreground border-border",
  RESOLVED: "bg-risk-low/15 text-risk-low border-risk-low/30",
  OPEN: "bg-risk-high/15 text-risk-high border-risk-high/30",
  INVESTIGATING: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  CONTAINED: "bg-primary/15 text-primary border-primary/30",
  CLOSED: "bg-muted text-muted-foreground border-border",
  IMPLEMENTED: "bg-risk-low/15 text-risk-low border-risk-low/30",
  PARTIAL: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  NOT_STARTED: "bg-risk-high/15 text-risk-high border-risk-high/30",
  NOT_APPLICABLE: "bg-muted text-muted-foreground border-border",
};
