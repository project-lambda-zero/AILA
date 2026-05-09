import { Link, useLocation } from "react-router";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { type ModuleFrontendSpec } from "@platform/extension-registry/types";
import { getSidebarSections, type SidebarItem } from "@platform/navigation";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarSeparator,
  useSidebar,
} from "@/components/ui/sidebar";
import { ScrollArea } from "@/components/ui/scroll-area";
import { RecentlyViewed } from "@/components/shell/RecentlyViewed";

interface AppSidebarProps {
  moduleSpecs: ModuleFrontendSpec[];
}

function NavItem({ item }: { item: SidebarItem }) {
  const Icon = item.icon;
  const location = useLocation();
  const isActive = item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        tooltip={item.label}
        isActive={isActive}
        render={<Link to={item.to} />}
      >
        {Icon && <Icon size={20} weight="regular" />}
        <span>{item.label}</span>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

function BrandLogo() {
  const { state } = useSidebar();
  const isCollapsed = state === "collapsed";

  return (
    <div className="flex items-center h-10 px-2">
      <span className="font-mono font-bold text-accent tracking-widest text-sm select-none">
        {isCollapsed ? "A" : "AILA"}
      </span>
    </div>
  );
}

export function AppSidebar({ moduleSpecs }: AppSidebarProps) {
  const { role } = useAuthStore();
  const location = useLocation();
  const sections = getSidebarSections(moduleSpecs);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <BrandLogo />
      </SidebarHeader>

      <SidebarContent>
        <ScrollArea className="flex-1">
          {sections.map((section, index) => {
            // Admin section — hidden from non-admin users (D-14, T-140-10)
            if (section.id === "admin" && !isAllowedRole(role, "admin")) {
              return null;
            }

            const isLast = index === sections.length - 1;

            return (
              <div key={section.id}>
                <SidebarGroup>
                  <SidebarGroupLabel>{section.label}</SidebarGroupLabel>
                  <SidebarGroupContent>
                    {section.subgroups && section.subgroups.length > 0 ? (
                      // Subgroups render as separate <ul>s with header spans between them.
                      // D-02 / D-27 fix: a <li> wrapping a <ul> (nested SidebarMenuSub inside
                      // SidebarMenuItem) produced a nested-<li> hydration warning because the
                      // subgroup header was semantically a grouping, not a menu item. Split each
                      // subgroup into: header <span> + its own <ul> of menu items.
                      <div className="flex flex-col gap-1">
                        {section.subgroups.map((subgroup) => (
                          <div key={subgroup.moduleId}>
                            <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted px-2 py-1 block">
                              {subgroup.label}
                            </span>
                            {/*
                              C-M3: subgroup is rendered as a flat <ul> of
                              menu items. Using SidebarMenuSubItem without a
                              SidebarMenuSub parent produced a semantically
                              wrong tree (SubItem expects the Sub's
                              role="group" <ul>); falling back to the plain
                              SidebarMenuItem keeps the visual indentation
                              while preventing nested-<li> hydration bugs.
                            */}
                            <SidebarMenu>
                              {subgroup.items.map((item) => {
                                const isActive = item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);
                                return (
                                  <SidebarMenuItem key={item.id}>
                                    <SidebarMenuButton
                                      tooltip={item.label}
                                      isActive={isActive}
                                      render={<Link to={item.to} />}
                                    >
                                    <span>{item.label}</span>
                                  </SidebarMenuButton>
                                </SidebarMenuItem>
                                );
                              })}
                            </SidebarMenu>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <SidebarMenu>
                        {section.items.map((item) => (
                          <NavItem key={item.id} item={item} />
                        ))}
                      </SidebarMenu>
                    )}
                  </SidebarGroupContent>
                </SidebarGroup>
                {!isLast && <SidebarSeparator />}
              </div>
            );
          })}
        </ScrollArea>
      </SidebarContent>

      <SidebarFooter>
        <RecentlyViewed />
      </SidebarFooter>
    </Sidebar>
  );
}
