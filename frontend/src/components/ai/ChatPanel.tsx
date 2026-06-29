import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Loader2, SendHorizonal } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { aiApi } from "@/lib/api/endpoints";
import type { ApiError } from "@/lib/api/client";
import type { AIAnswer } from "@/types/api";
import { AnswerCard } from "./AnswerCard";

interface ChatTurn {
  id: string;
  question: string;
  answer?: AIAnswer;
  error?: string;
}

const EXAMPLE_PROMPTS = [
  "What are the top OT risks across the plant right now?",
  "Which critical assets are internet-reachable?",
  "Summarize today's most urgent detections.",
  "Which compliance controls have gaps?",
];

interface ChatPanelProps {
  conversationId?: string;
  initialTurns?: ChatTurn[];
  showExamples?: boolean;
  useCase?: string;
}

export function ChatPanel({
  conversationId,
  initialTurns = [],
  showExamples = true,
  useCase,
}: ChatPanelProps) {
  const [turns, setTurns] = React.useState<ChatTurn[]>(initialTurns);
  const [input, setInput] = React.useState("");
  const [convId, setConvId] = React.useState<string | undefined>(conversationId);
  const scrollRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    setTurns(initialTurns);
    setConvId(conversationId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversationId]);

  const mutation = useMutation({
    mutationFn: (question: string) =>
      aiApi.chat({ question, conversation_id: convId, use_case: useCase }),
  });

  React.useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [turns]);

  const send = (question: string) => {
    const q = question.trim();
    if (!q || mutation.isPending) return;
    const turnId = Math.random().toString(36).slice(2);
    setTurns((prev) => [...prev, { id: turnId, question: q }]);
    setInput("");
    mutation.mutate(q, {
      onSuccess: (answer) => {
        if (answer.conversation_id) setConvId(answer.conversation_id);
        setTurns((prev) => prev.map((t) => (t.id === turnId ? { ...t, answer } : t)));
      },
      onError: (err) => {
        const e = err as ApiError;
        const msg =
          e.status === 503
            ? "The AI provider is unreachable. Configure AI_BASE_URL / AI_API_KEY / AI_MODEL_NAME on the backend, or set AI_PROVIDER=mock for a deterministic demo."
            : e.message || "AI request failed.";
        setTurns((prev) => prev.map((t) => (t.id === turnId ? { ...t, error: msg } : t)));
      },
    });
  };

  return (
    <div className="flex h-full flex-col">
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
        <div className="space-y-4 p-1">
          {turns.length === 0 && (
            <div className="flex flex-col items-center gap-4 py-10 text-center">
              <p className="text-sm text-muted-foreground">
                Ask the grounded, advisory-only OT analyst. Answers cite the demo records they are
                based on and only ever propose safe OT actions.
              </p>
              {showExamples && (
                <div className="flex flex-wrap justify-center gap-2">
                  {EXAMPLE_PROMPTS.map((p) => (
                    <button
                      key={p}
                      onClick={() => send(p)}
                      className="rounded-full border border-border bg-muted/50 px-3 py-1.5 text-xs transition-colors hover:bg-accent hover:text-accent-foreground"
                    >
                      {p}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {turns.map((turn) => (
            <div key={turn.id} className="space-y-3">
              <div className="flex justify-end">
                <div className="max-w-[85%] rounded-lg rounded-br-sm bg-primary px-3 py-2 text-sm text-primary-foreground">
                  {turn.question}
                </div>
              </div>
              {turn.answer && <AnswerCard answer={turn.answer} onSuggestion={send} />}
              {turn.error && (
                <Card className="border-destructive/30 bg-destructive/5 p-4">
                  <div className="flex gap-2 text-sm">
                    <AlertTriangle className="h-5 w-5 shrink-0 text-destructive" />
                    <p className="text-muted-foreground">{turn.error}</p>
                  </div>
                </Card>
              )}
            </div>
          ))}

          {mutation.isPending && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> The analyst is thinking…
            </div>
          )}
        </div>
      </div>

      <form
        className="mt-3 flex items-end gap-2 border-t pt-3"
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
      >
        <Textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send(input);
            }
          }}
          placeholder="Ask about assets, risk, detections, vulnerabilities, compliance…"
          className="min-h-[44px] resize-none"
          rows={1}
        />
        <Button type="submit" size="icon" disabled={!input.trim() || mutation.isPending}>
          {mutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <SendHorizonal className="h-4 w-4" />
          )}
        </Button>
      </form>
    </div>
  );
}
