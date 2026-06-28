import { createBrowserRouter, Navigate, Outlet } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { LoadingState } from "@/components/common/LoadingState";
import { ToastProvider } from "@/components/ui/use-toast";
import { Toaster } from "@/components/ui/toaster";
import { useAuth } from "@/lib/auth";

import Login from "@/pages/Login";
import NotFound from "@/pages/NotFound";
import Dashboard from "@/pages/Dashboard";
import AssetsList from "@/pages/assets/AssetsList";
import AssetDetail from "@/pages/assets/AssetDetail";
import NetworkMapPage from "@/pages/NetworkMap";
import DetectionsList from "@/pages/detections/DetectionsList";
import DetectionDetail from "@/pages/detections/DetectionDetail";
import VulnsList from "@/pages/vulns/VulnsList";
import VulnDetail from "@/pages/vulns/VulnDetail";
import ChangeManagement from "@/pages/ChangeManagement";
import ComplianceDashboard from "@/pages/compliance/ComplianceDashboard";
import ControlDetail from "@/pages/compliance/ControlDetail";
import IncidentsList from "@/pages/incidents/IncidentsList";
import IncidentDetail from "@/pages/incidents/IncidentDetail";
import Reports from "@/pages/Reports";
import Integrations from "@/pages/Integrations";
import AiAnalyst from "@/pages/AiAnalyst";
import Settings from "@/pages/Settings";

/** Wraps the whole tree with the toast system (rendered above RouterProvider's outlet). */
function RootLayout() {
  return (
    <ToastProvider>
      <Outlet />
      <Toaster />
    </ToastProvider>
  );
}

function ProtectedRoute() {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingState label="Loading ForgeShield OT…" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <AppShell />;
}

export const router = createBrowserRouter([
  {
    element: <RootLayout />,
    children: [
      { path: "/login", element: <Login /> },
      {
        element: <ProtectedRoute />,
        children: [
          { path: "/", element: <Dashboard /> },
          { path: "/assets", element: <AssetsList /> },
          { path: "/assets/:id", element: <AssetDetail /> },
          { path: "/network-map", element: <NetworkMapPage /> },
          { path: "/detections", element: <DetectionsList /> },
          { path: "/detections/:id", element: <DetectionDetail /> },
          { path: "/vulnerabilities", element: <VulnsList /> },
          { path: "/vulnerabilities/:id", element: <VulnDetail /> },
          { path: "/change-management", element: <ChangeManagement /> },
          { path: "/compliance", element: <ComplianceDashboard /> },
          { path: "/compliance/controls/:id", element: <ControlDetail /> },
          { path: "/incidents", element: <IncidentsList /> },
          { path: "/incidents/:id", element: <IncidentDetail /> },
          { path: "/reports", element: <Reports /> },
          { path: "/integrations", element: <Integrations /> },
          { path: "/ai", element: <AiAnalyst /> },
          { path: "/settings", element: <Settings /> },
          { path: "*", element: <NotFound /> },
        ],
      },
    ],
  },
]);
