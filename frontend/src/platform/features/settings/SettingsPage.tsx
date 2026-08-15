import { Link } from "react-router";
import { ArrowRight } from "@phosphor-icons/react/dist/csr/ArrowRight";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { usePreferences, type Density } from "@/providers/PreferencesProvider";
import { appEnv } from "@platform/config/env";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { SectionHeader, MonoBadge } from "@/components/aila/mock";

// ---------------------------------------------------------------------------
// Style tokens
// ---------------------------------------------------------------------------

const CONTROL_STYLE: React.CSSProperties = {
  height: 30,
  fontSize: 12,
  padding: "0 10px",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  fontFamily: "var(--font-mono)",
};

const ACTION_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  fontSize: 10,
  padding: "0 12px",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

const LABEL_STYLE: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
};

const SUBLABEL_STYLE: React.CSSProperties = {
  fontSize: 10,
  color: "var(--text-muted)",
  marginTop: 2,
  fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Small row primitives
// ---------------------------------------------------------------------------

function KVRow({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div
      className="flex items-start justify-between"
      style={{
        gap: 12,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono"
        style={{
          fontSize: 10,
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.12em",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono text-right"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
}

function ControlRow({
  htmlFor,
  label,
  help,
  control,
}: {
  htmlFor?: string;
  label: string;
  help?: string;
  control: React.ReactNode;
}) {
  return (
    <div
      className="flex items-center justify-between"
      style={{
        gap: 16,
        padding: "10px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <div className="min-w-0 flex flex-col">
        <label htmlFor={htmlFor} style={LABEL_STYLE}>
          {label}
        </label>
        {help && <p style={SUBLABEL_STYLE}>{help}</p>}
      </div>
      <div>{control}</div>
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
    <div
      className="flex flex-col"
      style={{ gap: 16, padding: 20, maxWidth: 880 }}
    >
      <SectionHeader icon={"\u25c7"} title="settings" />

      {/* Profile */}
      <WindowPanel title="profile" tone="muted">
        <div className="flex flex-col">
          <KVRow label="username" value={username ?? "\u2014"} />
          <KVRow
            label="role"
            value={
              <MonoBadge tone="info">{role ?? "\u2014"}</MonoBadge>
            }
          />
          <KVRow
            label="user id"
            value={
              <span
                className="font-mono"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                }}
              >
                {userId ?? "\u2014"}
              </span>
            }
          />
        </div>
        <p
          className="font-mono"
          style={{
            marginTop: 10,
            fontSize: 10,
            color: "var(--text-muted)",
          }}
        >
          contact your administrator to change your role or username.
        </p>
      </WindowPanel>

      {/* Sessions */}
      <WindowPanel title="sessions" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          review and revoke active login sessions across all your devices.
        </p>
        <Link
          to="/settings/sessions"
          className="font-mono inline-flex items-center"
          style={{
            marginTop: 10,
            gap: 6,
            fontSize: 11,
            color: "var(--accent)",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
          }}
        >
          manage active sessions
          <ArrowRight size={12} />
        </Link>
      </WindowPanel>

      {/* Appearance */}
      <WindowPanel title="appearance" tone="muted">
        <p
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.14em",
          }}
        >
          aila ships one design; midnight cloud 8 {"\u00b7"} no theme switch
        </p>
      </WindowPanel>

      {/* Workspace preferences */}
      <WindowPanel title="preferences" tone="muted">
        <p
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-muted)",
            marginBottom: 6,
          }}
        >
          personal preferences for how this console renders on your machine.
          persisted locally; not shared with other operators.
        </p>

        <ControlRow
          htmlFor="pref-density"
          label="density"
          help="Compact tightens row and cell padding on tables and lists."
          control={
            <select
              id="pref-density"
              aria-label="Interface density"
              value={density}
              onChange={(e) => setDensity(e.target.value as Density)}
              style={{ ...CONTROL_STYLE, minWidth: 160 }}
            >
              <option value="comfortable">comfortable</option>
              <option value="compact">compact</option>
            </select>
          }
        />

        <ControlRow
          htmlFor="pref-page-size"
          label="default page size"
          help="How many rows list screens load per page by default."
          control={
            <select
              id="pref-page-size"
              aria-label="Default rows per page"
              value={String(defaultPageSize)}
              onChange={(e) =>
                setDefaultPageSize(Number.parseInt(e.target.value, 10))
              }
              style={{ ...CONTROL_STYLE, minWidth: 100 }}
            >
              {allowedPageSizes.map((n) => (
                <option key={n} value={String(n)}>
                  {n}
                </option>
              ))}
            </select>
          }
        />

        <div
          className="flex items-center justify-between"
          style={{ gap: 16, padding: "10px 0" }}
        >
          <div className="min-w-0 flex flex-col">
            <span style={LABEL_STYLE}>reset preferences</span>
            <p style={SUBLABEL_STYLE}>
              Restores density, page size, and sidebar defaults. Does not
              affect theme or session.
            </p>
          </div>
          <button
            type="button"
            onClick={resetPreferences}
            aria-label="Reset workspace preferences to defaults"
            style={ACTION_BUTTON_STYLE}
          >
            reset
          </button>
        </div>
      </WindowPanel>

      {/* About */}
      <WindowPanel title="about" tone="muted">
        <div className="flex flex-col">
          <KVRow label="application" value="AILA -- AI Lab Assistant" />
          <KVRow
            label="api endpoint"
            value={
              <span
                className="font-mono"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {appEnv.apiBaseUrl}
              </span>
            }
          />
        </div>
      </WindowPanel>
    </div>
  );
}
