// Centralized access to Vite env (only VITE_-prefixed vars reach the browser).
export const env = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
  supabaseUrl: import.meta.env.VITE_SUPABASE_URL ?? "",
  supabaseAnonKey: import.meta.env.VITE_SUPABASE_ANON_KEY ?? "",
};

export const supabaseConfigured = Boolean(env.supabaseUrl && env.supabaseAnonKey);
