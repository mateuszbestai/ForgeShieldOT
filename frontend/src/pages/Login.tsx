import { zodResolver } from "@hookform/resolvers/zod";
import { AlertTriangle, Loader2, ShieldCheck } from "lucide-react";
import * as React from "react";
import { useForm } from "react-hook-form";
import { Navigate } from "react-router-dom";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/lib/auth";

const schema = z.object({
  email: z.string().email("Enter a valid email"),
  password: z.string().min(1, "Password is required"),
});
type FormValues = z.infer<typeof schema>;

const DEMO_ACCOUNTS = [
  { email: "admin@forgeshield.local", role: "Administrator" },
  { email: "engineer@forgeshield.local", role: "OT Security Engineer" },
  { email: "analyst@forgeshield.local", role: "SOC Analyst" },
  { email: "compliance@forgeshield.local", role: "Compliance Officer" },
  { email: "viewer@forgeshield.local", role: "Viewer" },
];

export default function Login() {
  const { user, loading, configured, signIn } = useAuth();
  const [authError, setAuthError] = React.useState<string | null>(null);

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "" },
  });

  if (!loading && user) return <Navigate to="/" replace />;

  const onSubmit = async (values: FormValues) => {
    setAuthError(null);
    try {
      await signIn(values.email, values.password);
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Sign-in failed");
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-10">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/15 text-primary">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">ForgeShield OT</h1>
          <p className="text-sm text-muted-foreground">Defensive OT/ICS Cybersecurity Console</p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {!configured && (
              <div className="flex gap-2 rounded-md border border-risk-medium/40 bg-risk-medium/10 p-3 text-sm text-risk-medium">
                <AlertTriangle className="h-5 w-5 shrink-0" />
                <p>
                  Supabase is not configured. Set <code className="font-mono">VITE_SUPABASE_URL</code>{" "}
                  and <code className="font-mono">VITE_SUPABASE_ANON_KEY</code> to enable sign-in.
                </p>
              </div>
            )}

            <form className="space-y-4" onSubmit={form.handleSubmit(onSubmit)}>
              <div className="space-y-1.5">
                <Label htmlFor="email">Email</Label>
                <Input id="email" type="email" autoComplete="email" {...form.register("email")} />
                {form.formState.errors.email && (
                  <p className="text-xs text-destructive">{form.formState.errors.email.message}</p>
                )}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  {...form.register("password")}
                />
                {form.formState.errors.password && (
                  <p className="text-xs text-destructive">{form.formState.errors.password.message}</p>
                )}
              </div>

              {authError && (
                <div className="flex gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                  <AlertTriangle className="h-5 w-5 shrink-0" />
                  <p>{authError}</p>
                </div>
              )}

              <Button type="submit" className="w-full" disabled={form.formState.isSubmitting || !configured}>
                {form.formState.isSubmitting && <Loader2 className="h-4 w-4 animate-spin" />}
                Sign in
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card className="bg-muted/30">
          <CardContent className="space-y-2 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Demo accounts
            </p>
            <ul className="space-y-1 text-sm">
              {DEMO_ACCOUNTS.map((a) => (
                <li key={a.email} className="flex items-center justify-between gap-2">
                  <button
                    type="button"
                    className="font-mono text-primary hover:underline"
                    onClick={() => form.setValue("email", a.email)}
                  >
                    {a.email}
                  </button>
                  <span className="text-xs text-muted-foreground">{a.role}</span>
                </li>
              ))}
            </ul>
            <p className="pt-1 text-xs text-muted-foreground">
              The shared demo password is configured server-side (see backend seed/env). Click an
              email to fill it in.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
