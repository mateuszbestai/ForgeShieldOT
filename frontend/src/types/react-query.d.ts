// Make the normalized ApiError the default error type across TanStack Query.
// The axios client rejects with ApiError ({ status, code, message }), so this
// keeps `query.error` / `mutation.error` correctly typed everywhere.
import "@tanstack/react-query";
import type { ApiError } from "@/lib/api/client";

declare module "@tanstack/react-query" {
  interface Register {
    defaultError: ApiError;
  }
}
