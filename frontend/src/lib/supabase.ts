import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { env, supabaseConfigured } from "./env";

// A single Supabase client for the app. When Supabase isn't configured (no env),
// we still create a client with placeholder values so imports don't crash; the
// login screen detects `supabaseConfigured` and shows setup guidance instead.
export const supabase: SupabaseClient = createClient(
  env.supabaseUrl || "https://placeholder.supabase.co",
  env.supabaseAnonKey || "public-anon-placeholder",
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
    },
  },
);

export { supabaseConfigured };

export async function getAccessToken(): Promise<string | null> {
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}
