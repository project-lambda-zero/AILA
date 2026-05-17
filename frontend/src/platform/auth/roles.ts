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

/**
 * Module-scoped capability strings (08_FRONTEND_UX.md §6.1).
 *
 * Capabilities live alongside the role hierarchy and let modules
 * gate routes/nav items on finer-grained permissions than the
 * three-tier admin/operator/reader system. A capability lookup is
 * derived from the user's role today — `admin` and `operator` are
 * treated as holding every VR capability. The user record will gain
 * an explicit `vr_capabilities: string[]` claim once the team grows
 * past one user (currently single-tenant dev).
 *
 * Adding a capability does NOT bypass the role check — both must
 * pass for the route to mount.
 */
export type Capability = "vr:disclosure" | "vr:research" | "vr:exploit";

const CAPABILITIES_BY_ROLE: Record<AppRole, ReadonlySet<Capability>> = {
  admin: new Set<Capability>(["vr:disclosure", "vr:research", "vr:exploit"]),
  operator: new Set<Capability>(["vr:disclosure", "vr:research", "vr:exploit"]),
  reader: new Set<Capability>(),
};

export function hasCapability(
  role: AppRole | null,
  capability?: Capability,
): boolean {
  if (!capability) return true;
  if (!role) return false;
  return CAPABILITIES_BY_ROLE[role].has(capability);
}
