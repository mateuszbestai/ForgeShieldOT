import { create } from "zustand";
import { persist } from "zustand/middleware";

interface SiteState {
  siteId: string | null;
  setSiteId: (siteId: string | null) => void;
}

// Persisted so the chosen site survives reloads. `null` means "All sites".
export const useSiteStore = create<SiteState>()(
  persist(
    (set) => ({
      siteId: null,
      setSiteId: (siteId) => set({ siteId }),
    }),
    { name: "forgeshield-site" },
  ),
);
