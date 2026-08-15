import { type ReactNode } from "react";
import { Link, useLocation } from "react-router";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { type ModuleFrontendSpec } from "@platform/extension-registry/types";
import { getSidebarSections, type SidebarItem } from "@platform/navigation";
import { RecentlyViewed } from "@/components/shell/RecentlyViewed";

/**
 * AppSidebar -- the AILA workbench module/investigation rail.
 *
 * The OS-frame left rail from the design system: mono uppercase section
 * labels, square status-dot markers, a hot-pink active indicator with an
 * inset left bar. Navigates the same routes as before (via
 * getSidebarSections). This is the mockup rail, not a restyled shadcn
 * sidebar.
 */
interface AppSidebarProps {
  moduleSpecs: ModuleFrontendSpec[];
}

function useIsActive(to: string): boolean {
  const location = useLocation();
  return to === "/" ? location.pathname === "/" : location.pathname.startsWith(to);
}

function RailItem({ item }: { item: SidebarItem }) {
  const Icon = item.icon;
  const active = useIsActive(item.to);
  return (
    <Link
      to={item.to}
      data-active={active ? "true" : undefined}
      className="flex items-center gap-2 px-3 py-1.5 font-mono transition-colors"
      style={{
        fontSize: "11.5px",
        letterSpacing: "0.02em",
        color: active ? "var(--color-text)" : "var(--color-text-muted)",
        background: active
          ? "color-mix(in srgb, var(--color-accent) 12%, transparent)"
          : "transparent",
        boxShadow: active ? "inset 2px 0 0 var(--color-accent)" : "none",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 5,
          height: 5,
          flex: "0 0 auto",
          background: active ? "var(--color-accent)" : "var(--color-text-faint)",
          boxShadow: active ? "0 0 6px var(--color-accent)" : "none",
        }}
      />
      {Icon ? <Icon size={15} weight="regular" /> : null}
      <span className="truncate">{item.label}</span>
    </Link>
  );
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div
      className="font-mono uppercase"
      style={{
        fontSize: "9px",
        letterSpacing: "0.16em",
        color: "var(--color-text-muted)",
        padding: "10px 12px 5px",
      }}
    >
      {children}
    </div>
  );
}

export function AppSidebar({ moduleSpecs }: AppSidebarProps) {
  const { role } = useAuthStore();
  const sections = getSidebarSections(moduleSpecs);

  return (
    <aside
      aria-label="Primary"
      className="flex min-h-0 flex-none flex-col"
      style={{
        width: 236,
        background: "var(--color-chrome)",
        borderRight: "1px solid var(--color-border-bright)",
      }}
    >
      <nav className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden py-1">
        {sections.map((section) => {
          if (section.id === "admin" && !isAllowedRole(role, "admin")) return null;
          return (
            <div key={section.id}>
              <SectionLabel>{section.label}</SectionLabel>
              {section.subgroups && section.subgroups.length > 0 ? (
                <div className="flex flex-col">
                  {section.subgroups.map((subgroup) => (
                    <div key={subgroup.moduleId} className="flex flex-col">
                      <span
                        className="font-mono uppercase"
                        style={{
                          fontSize: "8.5px",
                          letterSpacing: "0.16em",
                          color: "var(--color-text-faint)",
                          padding: "6px 12px 3px",
                        }}
                      >
                        {subgroup.label}
                      </span>
                      {subgroup.items.map((item) => (
                        <RailItem key={item.to} item={item} />
                      ))}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col">
                  {section.items.map((item) => (
                    <RailItem key={item.to} item={item} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
        <RecentlyViewed />
      </nav>
    </aside>
  );
}
