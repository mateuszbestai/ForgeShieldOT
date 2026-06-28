import { useQuery } from "@tanstack/react-query";
import { CircleDot, MessageSquare, Plus } from "lucide-react";
import * as React from "react";
import { ChatPanel } from "@/components/ai/ChatPanel";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { aiApi } from "@/lib/api/endpoints";
import { formatRelative } from "@/lib/format";

interface Conversation {
  id: string;
  title?: string | null;
  created_at?: string | null;
}

export default function AiAnalyst() {
  const [activeConv, setActiveConv] = React.useState<string | undefined>(undefined);

  const healthQ = useQuery({
    queryKey: ["ai-health"],
    queryFn: () => aiApi.health() as Promise<{ provider: string; model: string; healthy: boolean; note: string }>,
  });
  const convQ = useQuery({
    queryKey: ["ai-conversations"],
    queryFn: () => aiApi.conversations() as Promise<Conversation[]>,
  });

  const health = healthQ.data;

  return (
    <div className="flex h-[calc(100vh-9rem)] flex-col gap-4">
      <PageHeader
        title="AI Analyst"
        description="Grounded, advisory-only OT security analyst. Every answer is cited and limited to safe OT actions."
        actions={
          health && (
            <Badge
              variant="outline"
              className={cn(
                "gap-1.5 border",
                health.healthy
                  ? "border-risk-low/30 bg-risk-low/10 text-risk-low"
                  : "border-risk-high/30 bg-risk-high/10 text-risk-high",
              )}
            >
              <CircleDot className="h-3 w-3" />
              {health.healthy ? "Provider online" : "Provider offline"}
              <span className="font-mono opacity-70">· {health.provider}/{health.model}</span>
            </Badge>
          )
        }
      />

      {health && !health.healthy && (
        <Card className="border-risk-medium/30 bg-risk-medium/5">
          <CardContent className="p-3 text-sm text-muted-foreground">{health.note}</CardContent>
        </Card>
      )}

      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[260px,1fr]">
        <Card className="hidden min-h-0 flex-col lg:flex">
          <div className="flex items-center justify-between border-b p-3">
            <p className="text-sm font-semibold">Conversations</p>
            <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => setActiveConv(undefined)} title="New conversation">
              <Plus className="h-4 w-4" />
            </Button>
          </div>
          <ScrollArea className="flex-1">
            <div className="space-y-1 p-2">
              <button
                onClick={() => setActiveConv(undefined)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm transition-colors",
                  !activeConv ? "bg-primary/15 text-primary" : "hover:bg-accent",
                )}
              >
                <MessageSquare className="h-4 w-4" /> New conversation
              </button>
              {(convQ.data ?? []).map((c) => (
                <button
                  key={c.id}
                  onClick={() => setActiveConv(c.id)}
                  className={cn(
                    "flex w-full flex-col gap-0.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors",
                    activeConv === c.id ? "bg-primary/15 text-primary" : "hover:bg-accent",
                  )}
                >
                  <span className="truncate">{c.title || "Conversation"}</span>
                  <span className="text-xs text-muted-foreground">{formatRelative(c.created_at)}</span>
                </button>
              ))}
              {(convQ.data ?? []).length === 0 && !convQ.isLoading && (
                <p className="px-2 py-4 text-center text-xs text-muted-foreground">No past conversations.</p>
              )}
            </div>
          </ScrollArea>
        </Card>

        <Card className="flex min-h-0 flex-col p-4">
          <ChatPanel key={activeConv ?? "new"} conversationId={activeConv} />
        </Card>
      </div>
    </div>
  );
}
