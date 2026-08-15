import { Link } from "react-router";
import { User } from "@phosphor-icons/react/dist/csr/User";
import { Monitor } from "@phosphor-icons/react/dist/csr/Monitor";
import { Info } from "@phosphor-icons/react/dist/csr/Info";
import { ArrowRight } from "@phosphor-icons/react/dist/csr/ArrowRight";
import { Palette } from "@phosphor-icons/react/dist/csr/Palette";

import { SlidersHorizontal } from "@phosphor-icons/react/dist/csr/SlidersHorizontal";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { usePreferences, type Density } from "@/providers/PreferencesProvider";
import { appEnv } from "@platform/config/env";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// ---------------------------------------------------------------------------
// Section card wrapper
// ---------------------------------------------------------------------------

function Section({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface p-6 space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-accent">{icon}</span>
        <h2 className="text-base font-semibold font-mono tracking-tight text-foreground">
          {title}
        </h2>
      </div>
      {children}
    </div>
  );
}

function ProfileRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border last:border-0">
      <span className="text-sm text-text-muted">{label}</span>
      <span className="text-sm font-medium text-foreground">{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SettingsPage() {
  const { username, role, userId } = useAuthStore();
  const {
    density,
    defaultPageSize,
    setDensity,
    setDefaultPageSize,
    resetPreferences,
    allowedPageSizes,
  } = usePreferences();

  return (
    <div className="space-y-6 max-w-3xl">

      {/* Profile */}
      <Section icon={<User size={18} />} title="Profile">
        <div>
          <ProfileRow label="Username" value={username ?? "\u2014"} />
          <ProfileRow
            label="Role"
            value={
              <Badge variant="outline" className="capitalize text-xs font-mono">
                {role ?? "\u2014"}
              </Badge>
            }
          />
          <ProfileRow
            label="User ID"
            value={
              <span className="font-mono text-xs text-text-muted">
                {userId ?? "\u2014"}
              </span>
            }
          />
        </div>
        <p className="text-xs text-text-muted">
          Contact your administrator to change your role or username.
        </p>
      </Section>

      {/* Sessions */}
      <Section icon={<Monitor size={18} />} title="Sessions">
        <p className="text-sm text-text-muted">
          Review and revoke active login sessions across all your devices.
        </p>
        <Link
          to="/settings/sessions"
          className="touch-target inline-flex items-center gap-2 text-sm text-accent hover:text-accent/80 font-medium transition-colors"
        >
          Manage active sessions
          <ArrowRight size={14} />
        </Link>
      </Section>

      {/* Appearance */}
      <Section icon={<Palette size={18} />} title="Appearance">
        <p
          className="font-mono text-xs uppercase text-text-muted"
          style={{ letterSpacing: "0.14em" }}
        >
          AILA ships one design; midnight cloud 8 · no theme switch
        </p>
      </Section>

      {/* Workspace preferences */}
      <Section icon={<SlidersHorizontal size={18} />} title="Workspace">
        <p className="text-xs text-text-muted -mt-1">
          Personal preferences for how this console renders on your machine.
          Persisted locally; not shared with other operators.
        </p>

        {/* Density */}
        <div className="flex items-center justify-between gap-4 pb-3 border-b border-border">
          <div className="min-w-0">
            <label
              htmlFor="pref-density"
              className="text-sm font-medium text-foreground"
            >
              Density
            </label>
            <p className="text-xs text-text-muted mt-0.5">
              Compact tightens row and cell padding on tables and lists.
            </p>
          </div>
          <Select
            value={density}
            onValueChange={(v) => {
              if (typeof v === "string") setDensity(v as Density);
            }}
          >
            <SelectTrigger
              id="pref-density"
              aria-label="Interface density"
              className="font-mono text-xs h-8 w-[160px]"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="comfortable" className="font-mono text-xs">
                Comfortable
              </SelectItem>
              <SelectItem value="compact" className="font-mono text-xs">
                Compact
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Default page size */}
        <div className="flex items-center justify-between gap-4 pb-3 border-b border-border">
          <div className="min-w-0">
            <label
              htmlFor="pref-page-size"
              className="text-sm font-medium text-foreground"
            >
              Default page size
            </label>
            <p className="text-xs text-text-muted mt-0.5">
              How many rows list screens load per page by default.
            </p>
          </div>
          <Select
            value={String(defaultPageSize)}
            onValueChange={(v) => {
              if (typeof v === "string") setDefaultPageSize(Number.parseInt(v, 10));
            }}
          >
            <SelectTrigger
              id="pref-page-size"
              aria-label="Default rows per page"
              className="font-mono text-xs h-8 w-[100px]"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {allowedPageSizes.map((n) => (
                <SelectItem
                  key={n}
                  value={String(n)}
                  className="font-mono text-xs"
                >
                  {n}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Reset */}
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-foreground">
              Reset preferences
            </p>
            <p className="text-xs text-text-muted mt-0.5">
              Restores density, page size, and sidebar defaults. Does not
              affect theme or session.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={resetPreferences}
            aria-label="Reset workspace preferences to defaults"
          >
            Reset
          </Button>
        </div>
      </Section>

      {/* About */}
      <Section icon={<Info size={18} />} title="About">
        <div>
          <ProfileRow label="Application" value="AILA \u2014 AI Lab Assistant" />
          <ProfileRow
            label="API Endpoint"
            value={
              <span className="font-mono text-xs text-text-muted">
                {appEnv.apiBaseUrl}
              </span>
            }
          />
        </div>
      </Section>
    </div>
  );
}
