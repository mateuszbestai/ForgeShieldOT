import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "./use-toast";

const VARIANT_STYLES: Record<string, string> = {
  default: "border-border bg-card",
  success: "border-risk-low/40 bg-card",
  destructive: "border-destructive/40 bg-card",
};

const VARIANT_ICON = {
  default: <Info className="h-5 w-5 text-primary" />,
  success: <CheckCircle2 className="h-5 w-5 text-risk-low" />,
  destructive: <XCircle className="h-5 w-5 text-destructive" />,
};

export function Toaster() {
  const { toasts, dismiss } = useToast();

  return (
    <div className="pointer-events-none fixed bottom-0 right-0 z-[100] flex w-full max-w-sm flex-col gap-2 p-4">
      {toasts.map((t) => {
        const variant = t.variant ?? "default";
        return (
          <div
            key={t.id}
            className={cn(
              "pointer-events-auto flex items-start gap-3 rounded-lg border p-4 shadow-lg animate-in slide-in-from-bottom-2",
              VARIANT_STYLES[variant],
            )}
          >
            <div className="mt-0.5 shrink-0">{VARIANT_ICON[variant]}</div>
            <div className="flex-1 space-y-1">
              {t.title && <p className="text-sm font-semibold leading-none">{t.title}</p>}
              {t.description && (
                <p className="text-sm text-muted-foreground">{t.description}</p>
              )}
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className="shrink-0 rounded-sm text-muted-foreground transition-colors hover:text-foreground"
              aria-label="Dismiss"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
