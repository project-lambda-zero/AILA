import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";

import { useAuthStore } from "@platform/auth/useAuthStore";
import {
  hasCapability,
  isAllowedRole,
  type AppRole,
  type Capability,
} from "@platform/auth/roles";
import { AppStateScreen } from "@platform/ui/AppStateScreen";

interface ProtectedRouteProps {
  children: ReactNode;
  requiredRole?: AppRole;
  requiresCapability?: Capability;
}

export function ProtectedRoute({
  children,
  requiredRole,
  requiresCapability,
}: ProtectedRouteProps) {
  const { status, role } = useAuthStore();
  const location = useLocation();

  if (status === "bootstrapping") {
    return (
      <AppStateScreen
        title="Restoring session"
        message="Checking the saved session before the console opens."
        tone="neutral"
      />
    );
  }

  if (status !== "authenticated") {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  if (requiredRole && !isAllowedRole(role, requiredRole)) {
    return <Navigate to="/403" replace />;
  }

  if (requiresCapability && !hasCapability(role, requiresCapability)) {
    return <Navigate to="/403" replace />;
  }

  return <>{children}</>;
}