import { useQuery } from "@tanstack/react-query";
import { CircleDot, Moon, ShieldCheck, Sun } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { Stat } from "@/components/common/Stat";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { aiApi, authApi } from "@/lib/api/endpoints";
import { useAuth } from "@/lib/auth";
import { supabaseConfigured } from "@/lib/env";
import { useTheme } from "@/lib/theme";
import { ROLE_LABELS } from "@/types/enums";

const APP_VERSION = "0.1.0";

export default function Settings() {
  const { user } = useAuth();
  const { theme, toggle } = useTheme();

  const healthQ = useQuery({
    queryKey: ["ai-health"],
    queryFn: () => aiApi.health() as Promise<{ provider: string; model: string; healthy: boolean; note: string }>,
  });
  const configQ = useQuery({
    queryKey: ["auth-config"],
    queryFn: () => authApi.config() as Promise<Record<string, unknown>>,
  });

  const health = healthQ.data;

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Account, appearance, provider status and safety information." />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-base">Account</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <Stat label="Name" value={user?.full_name} />
            <Stat label="Email" value={user?.email} mono />
            <Stat label="Role" value={ROLE_LABELS[user?.role ?? ""] ?? user?.role} />
            <Stat label="User ID" value={user?.id} mono />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Appearance</CardTitle></CardHeader>
          <CardContent className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Theme</p>
              <p className="text-xs text-muted-foreground">Currently {theme === "dark" ? "dark" : "light"} mode</p>
            </div>
            <Button variant="outline" size="sm" onClick={toggle}>
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              Switch to {theme === "dark" ? "light" : "dark"}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">AI provider</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm">Status</span>
              <Badge
                variant="outline"
                className={cn(
                  "gap-1.5 border",
                  health?.healthy
                    ? "border-risk-low/30 bg-risk-low/10 text-risk-low"
                    : "border-risk-high/30 bg-risk-high/10 text-risk-high",
                )}
              >
                <CircleDot className="h-3 w-3" />
                {health?.healthy ? "Online" : "Offline"}
              </Badge>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <Stat label="Provider" value={health?.provider} mono />
              <Stat label="Model" value={health?.model} mono />
            </div>
            {health?.note && <p className="text-xs text-muted-foreground">{health.note}</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Environment</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <Stat
              label="Supabase configured"
              value={<Badge variant={supabaseConfigured ? "default" : "muted"}>{supabaseConfigured ? "Yes" : "No"}</Badge>}
            />
            <Stat
              label="Demo data"
              value={<Badge variant="muted">{configQ.data?.is_demo_environment === false ? "Disabled" : "Enabled"}</Badge>}
            />
            <Stat label="App version" value={APP_VERSION} mono />
            <Stat label="Auth mode" value={String(configQ.data?.auth_mode ?? "Supabase JWT")} />
          </CardContent>
        </Card>
      </div>

      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="h-4 w-4 text-primary" /> Security &amp; safety
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            ForgeShield OT is a <strong className="text-foreground">demonstration</strong> console. All data is
            simulated and no live OT/ICS systems are connected.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>The AI analyst is <strong className="text-foreground">advisory-only</strong> — it never executes actions and only proposes safe OT steps.</li>
            <li>All integrations are <strong className="text-foreground">read-only / simulated</strong>; no data leaves the environment.</li>
            <li>Every AI answer is grounded in cited demo records to keep responses auditable.</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
