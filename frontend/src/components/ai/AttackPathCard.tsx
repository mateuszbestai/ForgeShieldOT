import { Crosshair, Eye, ShieldCheck, Workflow } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { AttackPathStep } from "@/types/api";

/**
 * Renders a DEFENSIVE ATT&CK-for-ICS attack path as a staged timeline.
 * Blue-team framing only: each step pairs an adversary technique with the
 * detection gap and a safe mitigation. Used inside AnswerCard.
 */
export function AttackPathCard({ steps }: { steps: AttackPathStep[] }) {
  if (!steps?.length) return null;
  return (
    <div className="space-y-2">
      <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        <Workflow className="h-3.5 w-3.5" /> Modeled attack path (defensive)
      </p>
      <ol className="space-y-3 border-l border-border pl-4">
        {steps.map((step, i) => (
          <li key={i} className="relative">
            <span className="absolute -left-[1.30rem] top-1 flex h-4 w-4 items-center justify-center rounded-full border border-primary/40 bg-background text-[10px] font-semibold text-primary">
              {i + 1}
            </span>
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold">{step.stage || `Step ${i + 1}`}</span>
                {step.technique_id && (
                  <Badge variant="outline" className="gap-1 font-mono text-xs">
                    <Crosshair className="h-3 w-3" />
                    {step.technique_id}
                    {step.technique_name ? ` · ${step.technique_name}` : ""}
                  </Badge>
                )}
              </div>
              {step.rationale && <p className="text-sm text-foreground">{step.rationale}</p>}
              {step.detection_gap && (
                <p className="flex gap-1.5 text-xs text-risk-medium">
                  <Eye className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>
                    <span className="font-semibold">Detection gap:</span> {step.detection_gap}
                  </span>
                </p>
              )}
              {step.mitigation && (
                <p className="flex gap-1.5 text-xs text-risk-low">
                  <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>
                    <span className="font-semibold">Mitigation:</span> {step.mitigation}
                  </span>
                </p>
              )}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
