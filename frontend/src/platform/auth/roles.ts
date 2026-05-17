export type AppRole = "admin" | "operator" | "reader";

const roleLevels: Record<AppRole, number> = {
  reader: 0,
  operator: 1,
  admin: 2,
};

export function isAllowedRole(
  actualRole: AppRole | null,
  requiredRole?: AppRole,
): boolean {
  if (!requiredRole) {
    return true;
  }
  if (!actualRole) {
    return false;
  }
  return roleLevels[actualRole] >= roleLevels[requiredRole];
}
