import {
  Activity,
  BadgeCheck,
  Boxes,
  Bug,
  FileText,
  GitCompareArrows,
  LayoutDashboard,
  type LucideIcon,
  Network,
  Plug,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
      { to: "/assets", label: "Assets", icon: Boxes },
      { to: "/network-map", label: "Network Map", icon: Network },
    ],
  },
  {
    label: "Operations",
    items: [
      { to: "/detections", label: "Detections", icon: Activity },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
      { to: "/change-management", label: "Change Mgmt", icon: GitCompareArrows },
      { to: "/incidents", label: "Incidents", icon: ShieldAlert },
    ],
  },
  {
    label: "Governance",
    items: [
      { to: "/compliance", label: "Compliance", icon: BadgeCheck },
      { to: "/reports", label: "Reports", icon: FileText },
      { to: "/integrations", label: "Integrations", icon: Plug },
    ],
  },
  {
    label: "Tools",
    items: [
      { to: "/ai", label: "AI Analyst", icon: Sparkles },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col bg-sidebar text-sidebar-foreground">
      <div className="flex items-center gap-2.5 border-b border-sidebar-border px-5 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/20 text-primary">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div className="leading-tight">
          <p className="text-sm font-semibold">ForgeShield OT</p>
          <p className="text-[11px] text-sidebar-foreground/60">Defensive OT/ICS Console</p>
        </div>
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {NAV.map((group) => (
          <div key={group.label}>
            <p className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-sidebar-foreground/45">
              {group.label}
            </p>
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition-colors",
                      isActive
                        ? "bg-primary/15 text-primary"
                        : "text-sidebar-foreground/75 hover:bg-sidebar-foreground/5 hover:text-sidebar-foreground",
                    )
                  }
                >
                  <item.icon className="h-4 w-4 shrink-0" />
                  {item.label}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-sidebar-border px-5 py-3 text-[11px] text-sidebar-foreground/50">
        Advisory-only · Read-only · Simulated data
      </div>
    </div>
  );
}

export function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 border-r border-sidebar-border lg:block">
      <div className="fixed inset-y-0 left-0 w-60">
        <SidebarContent />
      </div>
    </aside>
  );
}
