import axios, { type AxiosError } from "axios";
import { env } from "../env";
import { getAccessToken, supabase } from "../supabase";

export const api = axios.create({
  baseURL: `${env.apiBaseUrl}/api`,
  headers: { "Content-Type": "application/json" },
  timeout: 90_000,
});

// Attach the Supabase access token to every request.
api.interceptors.request.use(async (config) => {
  const token = await getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface ApiError {
  status: number;
  code: string;
  message: string;
}

function normalizeError(error: AxiosError): ApiError {
  const status = error.response?.status ?? 0;
  const data = error.response?.data as { error?: { code?: string; message?: string }; detail?: unknown } | undefined;
  const code = data?.error?.code ?? (status === 0 ? "network_error" : "error");
  let message =
    data?.error?.message ??
    (typeof data?.detail === "string" ? data.detail : undefined) ??
    error.message ??
    "Request failed";
  if (status === 429) message = "Rate limit reached. Please slow down.";
  if (status === 0) message = "Cannot reach the API. Is the backend running?";
  return { status, code, message };
}

api.interceptors.response.use(
  (resp) => resp,
  async (error: AxiosError) => {
    const normalized = normalizeError(error);
    if (normalized.status === 401) {
      // Token expired/invalid — sign out so the route guard redirects to login.
      await supabase.auth.signOut().catch(() => undefined);
    }
    return Promise.reject(normalized);
  },
);

// Helper: unwrap a typed GET.
export async function get<T>(url: string, params?: Record<string, unknown>): Promise<T> {
  const { data } = await api.get<T>(url, { params });
  return data;
}
