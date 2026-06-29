import { Brain, Quote, ShieldCheck, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { AIAnswer } from "@/types/api";
import { AttackPathCard } from "./AttackPathCard";

const CONFIDENCE_STYLES: Record<string, string> = {
  HIGH: "bg-risk-low/15 text-risk-low border-risk-low/30",
  MEDIUM: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  LOW: "bg-muted text-muted-foreground border-border",
};

function confidenceLabel(c: string): string {
  const key = (c || "").toUpperCase();
  if (key === "HIGH") return "High confidence";
  if (key === "MEDIUM") return "Medium confidence";
  if (key === "LOW") return "Low confidence";
  return c || "—";
}

export function AnswerCard({ answer, className }: { answer: AIAnswer; className?: string }) {
  const confKey = (answer.confidence || "").toUpperCase();
  return (
    <Card className={cn("border-primary/20", className)}>
      <CardHeader className="flex-row items-center justify-between gap-2 space-y-0 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Sparkles className="h-4 w-4 text-primary" />
          AI Analyst
        </div>
        <Badge
          variant="outline"
          className={cn("border", CONFIDENCE_STYLES[confKey] ?? CONFIDENCE_STYLES.LOW)}
        >
          {confidenceLabel(answer.confidence)}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        {answer.summary && (
          <p className="text-sm leading-relaxed text-foreground">{answer.summary}</p>
        )}

        {answer.findings?.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Findings
            </p>
            <ul className="space-y-1.5">
              {answer.findings.map((f, i) => (
                <li key={i} className="flex gap-2 text-sm">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                  <span>{f}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {answer.attack_path && answer.attack_path.length > 0 && (
          <AttackPathCard steps={answer.attack_path} />
        )}

        {answer.citations?.length > 0 && (
          <div className="space-y-1.5">
            <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <Quote className="h-3.5 w-3.5" /> Grounded in
            </p>
            <div className="flex flex-wrap gap-1.5">
              {answer.citations.map((c, i) => (
                <span
                  key={i}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-2 py-1 text-xs"
                  title={c.label}
                >
                  <code className="font-mono text-primary">{c.ref}</code>
                  <span className="text-muted-foreground">{c.label}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {answer.safe_ot_actions?.length > 0 && (
          <div className="rounded-md border border-risk-low/30 bg-risk-low/10 p-3">
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-risk-low">
              <ShieldCheck className="h-3.5 w-3.5" /> Safe OT actions only
            </p>
            <ul className="space-y-1">
              {answer.safe_ot_actions.map((a, i) => (
                <li key={i} className="flex gap-2 text-sm">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-risk-low" />
                  <span>{a}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {answer.assumptions?.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Assumptions
            </p>
            <ul className="list-inside list-disc space-y-1 text-sm text-muted-foreground">
              {answer.assumptions.map((a, i) => (
                <li key={i}>{a}</li>
              ))}
            </ul>
          </div>
        )}

        {answer.reasoning && (
          <details className="rounded-md border border-border bg-muted/30 p-3 text-sm">
            <summary className="flex cursor-pointer items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <Brain className="h-3.5 w-3.5" /> Analyst reasoning
            </summary>
            <p className="mt-2 whitespace-pre-wrap text-xs leading-relaxed text-muted-foreground">
              {answer.reasoning}
            </p>
          </details>
        )}

        {(answer.disclaimer || answer.provider_name) && (
          <div className="border-t pt-3 text-xs text-muted-foreground">
            {answer.disclaimer && <p>{answer.disclaimer}</p>}
            {(answer.provider_name || answer.model_name) && (
              <p className="mt-1 font-mono opacity-70">
                {answer.provider_name}
                {answer.model_name ? ` · ${answer.model_name}` : ""}
                {answer.latency_ms ? ` · ${answer.latency_ms}ms` : ""}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
