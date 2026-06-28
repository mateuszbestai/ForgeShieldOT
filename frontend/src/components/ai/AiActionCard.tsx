import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { ApiError } from "@/lib/api/client";
import type { AIAnswer } from "@/types/api";
import { AnswerCard } from "./AnswerCard";

interface AiActionCardProps {
  title: string;
  description?: string;
  buttonLabel: string;
  mutationFn: () => Promise<AIAnswer>;
}

/** A self-contained "run an AI query for this entity and render the answer" card. */
export function AiActionCard({ title, description, buttonLabel, mutationFn }: AiActionCardProps) {
  const mutation = useMutation({ mutationFn });

  const error = mutation.error as ApiError | null;
  const errorMsg =
    error?.status === 503
      ? "AI provider unreachable. Configure AI_BASE_URL/AI_API_KEY/AI_MODEL_NAME or set AI_PROVIDER=mock."
      : error?.message;

  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-0.5">
            <p className="flex items-center gap-1.5 text-sm font-semibold">
              <Sparkles className="h-4 w-4 text-primary" /> {title}
            </p>
            {description && <p className="text-sm text-muted-foreground">{description}</p>}
          </div>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="h-4 w-4" />
            )}
            {buttonLabel}
          </Button>
        </CardContent>
      </Card>

      {mutation.isError && (
        <Card className="border-destructive/30 bg-destructive/5">
          <CardContent className="flex gap-2 p-4 text-sm">
            <AlertTriangle className="h-5 w-5 shrink-0 text-destructive" />
            <p className="text-muted-foreground">{errorMsg}</p>
          </CardContent>
        </Card>
      )}

      {mutation.data && <AnswerCard answer={mutation.data} />}
    </div>
  );
}
