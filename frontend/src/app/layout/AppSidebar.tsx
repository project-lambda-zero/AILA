import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { type ModuleFrontendSpec } from "@platform/extension-registry/types";
import {
  getSidebarSections,
  type SidebarItem,
  type SidebarSection,
} from "@platform/navigation";
import { useRecentlyViewed } from "@/hooks/useRecentlyViewed";

/**
 * AppSidebar -- the AILA workbench left rail, rebuilt from the design mock.
 *
 * Sections (top to bottom):
 *   MODULE                -- module list (from moduleSpecs); active module
 *                            gets the pink inset marker + tinted row.
 *   PAGES (collapsible)   -- flat page list contributed to the current
 *                            module PLUS platform pages, mono uppercase small.
 *   INVESTIGATIONS        -- recent entities the operator has opened, with
 *                            status dots (from useRecentlyViewed).
 *   ADMIN SETTINGS        -- admin/operator-gated categorised list, collapsed
 *                            by default (matches the mock).
 *   USER SETTINGS         -- pinned foot button linking to /settings.
 *
 * Preserves all existing routes, admin gating via `isAllowedRole`, and the
 * shell's react-router links. Presentational tokens come from the mock
 * semantic set (--surface-chrome, --border-soft, --accent, --text-*).
 */
interface AppSidebarProps {
  moduleSpecs: ModuleFrontendSpec[];
}

// ---------------------------------------------------------------------------
// Small style helpers -- kept inline so the mock's exact px sizing survives
// Tailwind v4's lack of arbitrary-px utilities.
// ---------------------------------------------------------------------------

const SECTION_LABEL: React.CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.16em",
  textTransform: "uppercase",
  color: "var(--text-muted)",
  fontFamily: "var(--font-mono)",
};

const CATEGORY_LABEL: React.CSSProperties = {
  fontSize: 8,
  letterSpacing: "0.18em",
  textTransform: "uppercase",
  color: "var(--accent)",
  fontFamily: "var(--font-mono)",
  padding: "7px 9px 3px",
};

// ---------------------------------------------------------------------------
// Row primitives
// ---------------------------------------------------------------------------

function ModuleRow({ label, to, active }: { label: string; to: string; active: boolean }) {
  return (
    <Link
      to={to}
      data-active={active ? "true" : undefined}
      className="flex items-center"
      style={{
        gap: 8,
        padding: "6px 11px",
        fontFamily: "var(--font-mono)",
        fontSize: 11.5,
        letterSpacing: "0.02em",
        color: active ? "var(--accent)" : "var(--text-primary)",
        background: active
          ? "color-mix(in srgb, var(--accent) 12%, transparent)"
          : "transparent",
        boxShadow: active ? "inset 2px 0 0 var(--accent)" : "none",
        textDecoration: "none",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 6,
          height: 6,
          flex: "0 0 auto",
          background: active ? "var(--accent)" : "var(--text-faint)",
          boxShadow: active ? "0 0 6px var(--accent)" : "none",
        }}
      />
      <span className="truncate">{label}</span>
    </Link>
  );
}

function PageRow({ item }: { item: SidebarItem }) {
  const { pathname } = useLocation();
  const active =
    item.to === "/" ? pathname === "/" : pathname === item.to || pathname.startsWith(`${item.to}/`);
  return (
    <Link
      to={item.to}
      className="flex items-center"
      style={{
        gap: 7,
        padding: "5px 11px",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        letterSpacing: "0.02em",
        color: active ? "var(--accent)" : "var(--text-muted)",
        background: active
          ? "color-mix(in srgb, var(--accent) 10%, transparent)"
          : "transparent",
        textDecoration: "none",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 5,
          height: 5,
          flex: "0 0 auto",
          background: "var(--accent)",
        }}
      />
      <span className="truncate">{item.label.toLowerCase()}</span>
    </Link>
  );
}

function AdminRow({ item }: { item: SidebarItem }) {
  const { pathname } = useLocation();
  const active =
    item.to === "/" ? pathname === "/" : pathname === item.to || pathname.startsWith(`${item.to}/`);
  return (
    <Link
      to={item.to}
      className="flex items-center"
      style={{
        gap: 8,
        padding: "5px 8px",
        borderRadius: 2,
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        letterSpacing: "0.03em",
        color: active ? "var(--accent)" : "var(--text-muted)",
        background: active
          ? "color-mix(in srgb, var(--accent) 10%, transparent)"
          : "transparent",
        textDecoration: "none",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 5,
          height: 5,
          flex: "0 0 auto",
          background: active ? "var(--accent)" : "var(--text-faint)",
        }}
      />
      <span className="truncate">{item.label.toLowerCase()}</span>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Section groups
// ---------------------------------------------------------------------------

function InvestigationRow({
  id,
  name,
  href,
  onOpen,
}: {
  id: string;
  name: string;
  href: string;
  onOpen: () => void;
}) {
  return (
    <div
      onClick={onOpen}
      role="link"
      tabIndex={0}
      aria-label={`Open ${name}`}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
      style={{
        padding: "6px 8px",
        border: "1px solid var(--border-soft)",
        borderRadius: 2,
        background: "var(--surface-sunk)",
        cursor: "pointer",
      }}
    >
      <div className="flex items-center" style={{ gap: 7 }}>
        <span
          aria-hidden="true"
          style={{
            width: 6,
            height: 6,
            flex: "0 0 auto",
            background: "var(--status-ok)",
            boxShadow: "0 0 5px var(--status-ok)",
          }}
        />
        <span
          className="truncate"
          style={{
            fontSize: 10.5,
            color: "var(--text-primary)",
            letterSpacing: "0.04em",
            fontFamily: "var(--font-mono)",
            flex: 1,
          }}
        >
          {id}
        </span>
      </div>
      <div
        className="truncate"
        style={{
          marginTop: 3,
          fontSize: 9.5,
          color: "var(--text-faint)",
          letterSpacing: "0.02em",
          fontFamily: "var(--font-mono)",
        }}
        title={name}
      >
        {name || href}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AppSidebar({ moduleSpecs }: AppSidebarProps) {
  const { role } = useAuthStore();
  const location = useLocation();
  const navigate = useNavigate();
  const sections = getSidebarSections(moduleSpecs);
  const { items: recent } = useRecentlyViewed();

  const [pagesOpen, setPagesOpen] = useState(true);
  const [adminOpen, setAdminOpen] = useState(false);

  // Section indexing -----------------------------------------------------
  const platformSection: SidebarSection | undefined = sections.find(
    (s) => s.id === "platform",
  );
  const modulesSection: SidebarSection | undefined = sections.find(
    (s) => s.id === "modules",
  );
  const adminSection: SidebarSection | undefined = sections.find(
    (s) => s.id === "admin",
  );

  // Active module derivation: pick the module whose FIRST nav item's `to`
  // is a prefix of the current path. Falls back to the first module.
  const activeModuleId = useMemo<string | null>(() => {
    if (!modulesSection?.subgroups?.length) return null;
    for (const sub of modulesSection.subgroups) {
      const first = sub.items[0];
      if (!first) continue;
      const to = first.to;
      if (to === location.pathname || location.pathname.startsWith(`${to}/`)) {
        return sub.moduleId;
      }
      // Also match any of the subgroup's items.
      if (sub.items.some((it) => location.pathname.startsWith(it.to))) {
        return sub.moduleId;
      }
    }
    return modulesSection.subgroups[0]?.moduleId ?? null;
  }, [modulesSection, location.pathname]);

  // Pages shown inside the collapsible PAGES section -- the ACTIVE module's
  // pages if any, else platform pages.
  const pagesForActive: SidebarItem[] = useMemo(() => {
    if (activeModuleId && modulesSection?.subgroups) {
      const sub = modulesSection.subgroups.find((s) => s.moduleId === activeModuleId);
      if (sub && sub.items.length > 0) return sub.items;
    }
    return platformSection?.items ?? [];
  }, [activeModuleId, modulesSection, platformSection]);

  const workNoun = activeModuleId ? "investigations" : "recent";
  const canSeeAdmin = isAllowedRole(role, "operator");

  // Group admin items by category for the collapsible list. The mock uses
  // small accent group labels; we bucket by URL segment to keep it stable
  // even when new admin items are added.
  const adminGroups = useMemo<Array<{ label: string; items: SidebarItem[] }>>(() => {
    const items = (adminSection?.items ?? []).filter(
      (item) => !item.minRole || isAllowedRole(role, item.minRole),
    );
    const buckets: Record<string, SidebarItem[]> = {
      access: [],
      operations: [],
      cost: [],
      data: [],
      audit: [],
      other: [],
    };
    for (const it of items) {
      const seg = it.to.replace(/^\/admin\/?/, "").split("/")[0] ?? "";
      if (["users", "teams", "api-keys", "auth"].includes(seg)) buckets.access.push(it);
      else if (
        ["task-queue", "dead-letter", "health", "automation", "workflows", "scheduled-reports"].includes(seg)
      )
        buckets.operations.push(it);
      else if (["cost", "executive"].includes(seg)) buckets.cost.push(it);
      else if (["tags", "saved-filters", "config", "tools", "platform-ops", "platform-infra", "ml-ops"].includes(seg))
        buckets.data.push(it);
      else if (["audit", "llm-log"].includes(seg)) buckets.audit.push(it);
      else buckets.other.push(it);
    }
    const catLabel: Record<string, string> = {
      access: "access",
      operations: "operations",
      cost: "cost & reporting",
      data: "data & config",
      audit: "audit",
      other: "other",
    };
    return Object.entries(buckets)
      .filter(([, arr]) => arr.length > 0)
      .map(([k, arr]) => ({ label: catLabel[k] ?? k, items: arr }));
  }, [adminSection, role]);

  return (
    <aside
      aria-label="Primary"
      className="flex min-h-0 flex-none flex-col"
      style={{
        width: 216,
        background: "color-mix(in srgb, var(--surface-card) 72%, transparent)",
        borderRight: "1px solid var(--border-soft)",
        fontFamily: "var(--font-mono)",
        color: "var(--text-primary)",
      }}
    >
      {/* MODULE section header */}
      <div
        style={{
          flex: "0 0 auto",
          padding: "9px 11px",
          borderBottom: "1px solid var(--border-soft)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <span style={SECTION_LABEL}>module</span>
      </div>

      {/* Module list. Clicking navigates to the module's first nav route. */}
      <div style={{ flex: "0 0 auto", display: "flex", flexDirection: "column" }}>
        {modulesSection?.subgroups?.map((sub) => {
          const first = sub.items[0];
          const to = first?.to ?? "/";
          const active = activeModuleId === sub.moduleId;
          return (
            <ModuleRow
              key={sub.moduleId}
              label={sub.moduleId.replace(/_/g, " ")}
              to={to}
              active={active}
            />
          );
        })}
      </div>

      {/* PAGES (collapsible) */}
      <div style={{ flex: "0 0 auto", display: "flex", flexDirection: "column" }}>
        <button
          type="button"
          onClick={() => setPagesOpen((v) => !v)}
          className="flex items-center"
          style={{
            gap: 7,
            width: "100%",
            padding: "10px 11px 6px",
            background: "transparent",
            border: 0,
            cursor: "pointer",
            ...SECTION_LABEL,
          }}
          aria-expanded={pagesOpen}
        >
          <span aria-hidden="true" style={{ color: "var(--accent)", fontSize: 8 }}>
            {pagesOpen ? "▼" : "▶"}
          </span>
          pages
        </button>
        {pagesOpen && (
          <div
            style={{
              maxHeight: 220,
              overflow: "auto",
              padding: "0 0 6px",
              display: "flex",
              flexDirection: "column",
              gap: 1,
            }}
          >
            {pagesForActive
              .filter((it) => !it.minRole || isAllowedRole(role, it.minRole))
              .map((it) => (
                <PageRow key={it.id ?? it.to} item={it} />
              ))}
          </div>
        )}
      </div>

      {/* WORK NOUN header + intake (+) */}
      <div
        style={{
          flex: "0 0 auto",
          padding: "11px 11px 5px",
          display: "flex",
          alignItems: "center",
          gap: 8,
          borderTop: "1px solid var(--border-soft)",
        }}
      >
        <span style={SECTION_LABEL}>{workNoun}</span>
        <span style={{ flex: 1 }} />
        <button
          type="button"
          onClick={() => {
            // Route to the active module's first nav item as an intake seed.
            // Modules own their own "new investigation" surfaces; we only
            // switch context here.
            const to = pagesForActive[0]?.to ?? "/";
            navigate(to);
          }}
          aria-label="Open module"
          style={{
            border: "1px solid var(--border)",
            padding: "0 5px",
            fontSize: 12,
            lineHeight: "16px",
            color: "var(--accent)",
            background: "transparent",
            cursor: "pointer",
          }}
        >
          +
        </button>
      </div>

      {/* Recent entities as the investigations list. Real data from
          useRecentlyViewed -- no fabrication. Empty state matches the mock's
          faint muted copy. */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          padding: "0 7px 7px",
          display: "flex",
          flexDirection: "column",
          gap: 5,
        }}
      >
        {recent.length === 0 ? (
          <div
            style={{
              padding: "10px 6px",
              fontFamily: "var(--font-mono)",
              fontSize: 9.5,
              color: "var(--text-faint)",
              letterSpacing: "0.04em",
              lineHeight: 1.5,
            }}
          >
            no recent items. open a module page to seed this list.
          </div>
        ) : (
          recent.slice(0, 10).map((it) => {
            const id = it.path.length > 22 ? `${it.path.slice(0, 19)}…` : it.path;
            return (
              <InvestigationRow
                key={it.path}
                id={id}
                name={it.label}
                href={it.path}
                onOpen={() => navigate(it.path)}
              />
            );
          })
        )}
      </div>

      {/* ADMIN SETTINGS -- collapsible group. Admin/operator only. */}
      {canSeeAdmin && adminGroups.length > 0 && (
        <div
          style={{
            flex: "0 0 auto",
            maxHeight: 230,
            display: "flex",
            flexDirection: "column",
            minHeight: 0,
            borderTop: "1px solid var(--border-soft)",
          }}
        >
          <button
            type="button"
            onClick={() => setAdminOpen((v) => !v)}
            className="flex items-center"
            style={{
              gap: 7,
              width: "100%",
              padding: "9px 11px",
              background: "var(--surface-chrome)",
              border: 0,
              cursor: "pointer",
              ...SECTION_LABEL,
            }}
            aria-expanded={adminOpen}
          >
            <span aria-hidden="true" style={{ color: "var(--accent)", fontSize: 8 }}>
              {adminOpen ? "▼" : "▶"}
            </span>
            admin settings
          </button>
          {adminOpen && (
            <div
              style={{
                maxHeight: 190,
                overflow: "auto",
                padding: "0 7px 7px",
                display: "flex",
                flexDirection: "column",
                gap: 2,
              }}
            >
              {adminGroups.map((g) => (
                <div key={g.label}>
                  <div style={CATEGORY_LABEL}>{g.label}</div>
                  {g.items.map((it) => (
                    <AdminRow key={it.id ?? it.to} item={it} />
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* USER SETTINGS pin */}
      <Link
        to="/settings"
        className="flex items-center"
        style={{
          gap: 7,
          padding: "9px 11px",
          borderTop: "1px solid var(--border-soft)",
          background: "var(--surface-chrome)",
          color: "var(--text-muted)",
          fontFamily: "var(--font-mono)",
          fontSize: 9,
          letterSpacing: "0.16em",
          textTransform: "uppercase",
          textDecoration: "none",
        }}
      >
        <span aria-hidden="true" style={{ color: "var(--accent)" }}>
          ⚙
        </span>
        user settings
      </Link>
    </aside>
  );
}
