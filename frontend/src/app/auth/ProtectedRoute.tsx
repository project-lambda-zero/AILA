import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole, type AppRole } from "@platform/auth/roles";
import { AppStateScreen } from "@platform/ui/AppStateScreen";

interface ProtectedRouteProps {
  children: ReactNode;
  requiredRole?: AppRole;
}

export function ProtectedRoute({
  children,
  requiredRole,
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

  return <>{children}</>;
}