import type { Session } from "@supabase/supabase-js";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "./api/client";
import { supabase, supabaseConfigured } from "./supabase";

export interface AppUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

interface AuthState {
  user: AppUser | null;
  session: Session | null;
  loading: boolean;
  configured: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<AppUser | null>(null);
  const [loading, setLoading] = useState(true);

  async function loadProfile(): Promise<AppUser | null> {
    try {
      const { data } = await api.get<AppUser>("/auth/me");
      setUser(data);
      return data;
    } catch {
      setUser(null);
      return null;
    }
  }

  useEffect(() => {
    let mounted = true;
    supabase.auth.getSession().then(async ({ data }) => {
      if (!mounted) return;
      setSession(data.session);
      if (data.session) await loadProfile();
      setLoading(false);
    });

    const { data: sub } = supabase.auth.onAuthStateChange(async (_event, newSession) => {
      setSession(newSession);
      if (newSession) {
        await loadProfile();
      } else {
        setUser(null);
      }
    });
    return () => {
      mounted = false;
      sub.subscription.unsubscribe();
    };
  }, []);

  async function signIn(email: string, password: string) {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);
    // Supabase auth succeeded — now confirm the ForgeShield backend accepts the
    // session. If it doesn't (e.g. backend down, or SUPABASE_JWT_SECRET/SUPABASE_URL
    // don't match the project) surface it instead of silently bouncing to /login.
    const profile = await loadProfile();
    if (!profile) {
      await supabase.auth.signOut();
      throw new Error(
        "Signed in with Supabase, but the ForgeShield backend rejected the session. " +
          "Confirm the backend is running and its SUPABASE_URL / SUPABASE_JWT_SECRET match this project.",
      );
    }
  }

  async function signOut() {
    await supabase.auth.signOut();
    setUser(null);
    setSession(null);
  }

  return (
    <AuthContext.Provider
      value={{ user, session, loading, configured: supabaseConfigured, signIn, signOut }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

// Role-gating helper for write actions in the UI.
export function canWrite(role: string | undefined): boolean {
  return role === "ADMIN" || role === "OT_SECURITY_ENGINEER";
}
