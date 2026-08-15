import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import {
  SectionHeader,
  StatBar,
  MonoBadge,
  DataGrid,
  BigStat,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";
import type { PanelContribution } from "@platform/extension-registry/types";

import {
  useSystemDetail,
  useSystemConnectivity,
  useSystemFindings,
  useSystemScans,
  useUpdateSystem,
  useDeleteSystem,
  formatRelativeTime,
  type SystemMutationInput,
  type SeverityLevel,
} from "./api";
import { ConnectivityBadge } from "./ConnectivityBadge";
import { SystemTags } from "./SystemTags";

// ---------------------------------------------------------------------------
// Shared inline styles (mirrors SystemsPage idioms)
// ---------------------------------------------------------------------------

const HEADER_BUTTON: React.CSSProperties = {
  height: 26,
  padding: "0 11px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  borderRadius: 3,
  cursor: "pointer",
};

const ACCENT_BUTTON: React.CSSProperties = {
  ...HEADER_BUTTON,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 15%, transparent)",
  color: "var(--accent)",
};

const WARN_BUTTON: React.CSSProperties = {
  ...HEADER_BUTTON,
  border: "1px solid var(--status-warn)",
  background: "color-mix(in srgb, var(--status-warn) 15%, transparent)",
  color: "var(--status-warn)",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 11,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  borderRadius: 3,
  outline: "none",
};

const METADATA_LABEL: React.CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

const ERROR_BOX: React.CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "8px 12px",
  fontSize: 11,
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeSystemForm(detail: SystemMutationInput): SystemMutationInput {
  return {
    name: detail.name,
    host: detail.host,
    username: detail.username,
    port: detail.port,
    distro: detail.distro,
    description: detail.description,
  };
}

// Load module panel contributions for system.detail slot at module scope.
const moduleSpecs = loadModuleFrontendSpecs();
const systemDetailPanels: PanelContribution[] = moduleSpecs
  .flatMap((spec) => spec.panels ?? [])
  .filter((panel) => panel.slot === "system.detail")
  .sort((a, b) => a.order - b.order);

const SEVERITY_TONES: Array<{ key: SeverityLevel; label: string; color: string }> = [
  { key: "critical", label: "CRITICAL", color: "var(--accent)" },
  { key: "high", label: "HIGH", color: "var(--status-warn)" },
  { key: "medium", label: "MEDIUM", color: "var(--status-info)" },
  { key: "low", label: "LOW", color: "var(--status-ok)" },
];

// ---------------------------------------------------------------------------
// SystemDetailPage
// ---------------------------------------------------------------------------

/**
 * SystemDetailPage -- system-scoped detail rebuilt to the AILA mock language.
 *
 * Preserves every data hook (useSystemDetail, useSystemConnectivity,
 * useSystemFindings, useSystemScans, useUpdateSystem, useDeleteSystem) and
 * every route param behavior. Tabs are replaced by a WindowPanel grid: the
 * overview + connectivity + tags + findings summary + recent scans surfaces
 * all render on one screen, extended by any module-contributed panels.
 */
export function SystemDetailPage() {
  const { role } = useAuthStore();
  const navigate = useNavigate();
  const { systemId = "" } = useParams();

  const parsedSystemId = Number(systemId);
  const isValidSystemId =
    Number.isInteger(parsedSystemId) && parsedSystemId > 0;

  const systemQuery = useSystemDetail(isValidSystemId ? parsedSystemId : null);
  const connectivityQuery = useSystemConnectivity(
    isValidSystemId ? parsedSystemId : null,
  );
  const findingsQuery = useSystemFindings(
    isValidSystemId ? parsedSystemId : null,
    1,
    25,
  );
  const scansQuery = useSystemScans(
    isValidSystemId ? parsedSystemId : null,
    1,
    10,
  );
  const updateSystem = useUpdateSystem(isValidSystemId ? parsedSystemId : null);
  const deleteSystem = useDeleteSystem(isValidSystemId ? parsedSystemId : null);

  const [editDraft, setEditDraft] = useState<SystemMutationInput | null>(null);
  const [showEditForm, setShowEditForm] = useState(false);
  const canOperate = isAllowedRole(role, "operator");

  const system = systemQuery.data;

  useUpdatePageHeader({
    title: system?.name,
    subtitle: undefined,
    status: null,
  });

  const editValue = useMemo(
    () => editDraft ?? (system ? normalizeSystemForm(system) : null),
    [editDraft, system],
  );

  const findings = findingsQuery.data?.items ?? [];
  const scans = scansQuery.data?.items ?? [];

  const severityCounts = useMemo(() => {
    const counts: Record<SeverityLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    for (const f of findings) {
      const sev = (f.severity ?? "").toLowerCase() as SeverityLevel;
      if (sev in counts) counts[sev] += 1;
    }
    return counts;
  }, [findings]);

  const totalFindings = findings.length;
  const kevCount = useMemo(
    () => findings.filter((f) => f.kev).length,
    [findings],
  );

  if (!isValidSystemId) {
    return (
      <div style={{ padding: 20 }}>
        <WindowPanel title="invalid system" tone="warn">
          <div style={ERROR_BOX}>
            Invalid system ID.{" "}
            <Link to="/systems" style={{ color: "var(--accent)" }}>
              Back to systems
            </Link>
          </div>
        </WindowPanel>
      </div>
    );
  }

  if (systemQuery.isError) {
    return (
      <div className="flex flex-col" style={{ padding: 20, gap: 12 }}>
        <SectionHeader
          icon={"\u25a0"}
          title="system detail"
          actions={
            <Link to="/systems">
              <button type="button" style={HEADER_BUTTON}>
                {"\u2190"} systems
              </button>
            </Link>
          }
        />
        <WindowPanel title="load failed" tone="warn">
          <div style={ERROR_BOX}>
            {(systemQuery.error as Error).message}
          </div>
        </WindowPanel>
      </div>
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <h2 className="sr-only">System overview</h2>

      <SectionHeader
        icon={"\u25a0"}
        title={system ? system.name.toLowerCase() : "system"}
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <Link to="/systems">
              <button type="button" style={HEADER_BUTTON}>
                {"\u2190"} systems
              </button>
            </Link>
            {canOperate && system && (
              <button
                type="button"
                style={ACCENT_BUTTON}
                onClick={() => {
                  setEditDraft(normalizeSystemForm(system));
                  setShowEditForm((v) => !v);
                }}
              >
                {showEditForm ? "close edit" : "edit"}
              </button>
            )}
            {canOperate && system && (
              <button
                type="button"
                style={WARN_BUTTON}
                disabled={deleteSystem.isPending}
                onClick={() => {
                  if (
                    !window.confirm(
                      `Delete system ${system.name}? This cannot be undone.`,
                    )
                  )
                    return;
                  deleteSystem.mutate(undefined, {
                    onSuccess: () => void navigate("/systems"),
                  });
                }}
              >
                {deleteSystem.isPending ? "deleting…" : "delete"}
              </button>
            )}
          </div>
        }
      />

      {systemQuery.isLoading && (
        <WindowPanel title="system" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {system && (
        <>
          {/* Top row: overview + connectivity */}
          <div
            className="grid"
            style={{
              gridTemplateColumns: "minmax(0, 1.4fr) minmax(0, 1fr)",
              gap: 12,
            }}
          >
            <WindowPanel title="overview" tone="muted">
              <div
                className="grid"
                style={{
                  gridTemplateColumns: "max-content 1fr",
                  columnGap: 16,
                  rowGap: 6,
                }}
              >
                <span style={METADATA_LABEL}>HOST</span>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-primary)", fontSize: 12 }}
                >
                  {system.host}:{system.port}
                </span>
                <span style={METADATA_LABEL}>USERNAME</span>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-primary)", fontSize: 12 }}
                >
                  {system.username}
                </span>
                <span style={METADATA_LABEL}>DISTRO</span>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-primary)", fontSize: 12 }}
                >
                  {system.distro}
                </span>
                <span style={METADATA_LABEL}>SCAN COUNT</span>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-primary)", fontSize: 12 }}
                >
                  {system.scan_count}
                </span>
                <span style={METADATA_LABEL}>REGISTERED</span>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-muted)", fontSize: 11 }}
                >
                  {formatRelativeTime(system.created_at)}
                </span>
                <span style={METADATA_LABEL}>UPDATED</span>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-muted)", fontSize: 11 }}
                >
                  {formatRelativeTime(system.updated_at)}
                </span>
              </div>
              {system.description && (
                <p
                  className="font-mono"
                  style={{
                    marginTop: 12,
                    paddingTop: 10,
                    borderTop: "1px solid var(--border-faint)",
                    color: "var(--text-muted)",
                    fontSize: 11,
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {system.description}
                </p>
              )}
            </WindowPanel>

            <WindowPanel title="ssh connectivity" tone="muted">
              {connectivityQuery.isLoading ? (
                <LoadingSkeletonGroup lines={2} />
              ) : (
                <div className="flex flex-col" style={{ gap: 8 }}>
                  <ConnectivityBadge
                    status={connectivityQuery.data?.status ?? null}
                  />
                  {connectivityQuery.data?.last_checked && (
                    <div
                      className="font-mono"
                      style={{ fontSize: 10, color: "var(--text-faint)" }}
                    >
                      LAST CHECKED:{" "}
                      {formatRelativeTime(
                        connectivityQuery.data.last_checked,
                      )}
                    </div>
                  )}
                </div>
              )}
            </WindowPanel>
          </div>

          {/* Tags panel (full row) */}
          <SystemTags systemId={parsedSystemId} />

          {/* Findings summary + KEV */}
          <div
            className="grid"
            style={{
              gridTemplateColumns: "minmax(0, 1fr) 220px",
              gap: 12,
            }}
          >
            <WindowPanel title="findings summary" tone="muted">
              {findingsQuery.isLoading ? (
                <LoadingSkeletonGroup lines={4} />
              ) : totalFindings === 0 ? (
                <p
                  className="font-mono"
                  style={{ fontSize: 11, color: "var(--text-muted)" }}
                >
                  no findings recorded for this system.
                </p>
              ) : (
                <div className="flex flex-col" style={{ gap: 8 }}>
                  {SEVERITY_TONES.map(({ key, label, color }) => (
                    <StatBar
                      key={key}
                      label={label}
                      color={color}
                      value={severityCounts[key]}
                      max={totalFindings}
                    />
                  ))}
                </div>
              )}
            </WindowPanel>

            <WindowPanel title="kev" tone={kevCount > 0 ? "warn" : "muted"}>
              <BigStat value={kevCount} sub="known exploited" />
            </WindowPanel>
          </div>

          {/* Recent scans */}
          <WindowPanel title="recent scans" flush tone="muted">
            {scansQuery.isLoading ? (
              <div style={{ padding: 16 }}>
                <LoadingSkeletonGroup lines={4} />
              </div>
            ) : (
              <DataGrid
                columns={[
                  { label: "run", width: "minmax(120px, 1fr)" },
                  { label: "module", width: "110px" },
                  { label: "status", width: "110px" },
                  { label: "findings", width: "80px", align: "right" },
                  { label: "kev", width: "60px", align: "right" },
                  { label: "started", width: "120px", align: "right" },
                ]}
                rows={scans}
                getKey={(s) => s.run_id}
                empty={
                  <div
                    className="font-mono"
                    style={{
                      padding: 22,
                      textAlign: "center",
                      fontSize: 11,
                      color: "var(--text-muted)",
                    }}
                  >
                    no scans recorded for this system yet.
                  </div>
                }
                renderCells={(s) => [
                  <span
                    style={{ color: "var(--accent)", fontSize: 11 }}
                    title={s.query_text}
                  >
                    {s.run_id.slice(0, 8)}
                  </span>,
                  <span
                    style={{ color: "var(--text-primary)", fontSize: 11 }}
                  >
                    {s.module_id}
                  </span>,
                  <MonoBadge
                    tone={
                      s.status === "completed"
                        ? "ok"
                        : s.status === "failed"
                          ? "critical"
                          : s.status === "running"
                            ? "info"
                            : "muted"
                    }
                  >
                    {s.status.toUpperCase()}
                  </MonoBadge>,
                  <span
                    className="font-mono"
                    style={{ color: "var(--text-primary)", fontSize: 11 }}
                  >
                    {s.total_findings ?? "--"}
                  </span>,
                  <span
                    className="font-mono"
                    style={{
                      color:
                        (s.kev_count ?? 0) > 0
                          ? "var(--status-warn)"
                          : "var(--text-faint)",
                      fontSize: 11,
                    }}
                  >
                    {s.kev_count ?? 0}
                  </span>,
                  <span
                    className="font-mono"
                    style={{ color: "var(--text-muted)", fontSize: 10 }}
                    title={s.created_at ?? undefined}
                  >
                    {formatRelativeTime(s.created_at)}
                  </span>,
                ]}
              />
            )}
          </WindowPanel>

          {/* Edit form -- operator+ only */}
          {canOperate && showEditForm && (
            <WindowPanel title="edit system" tone="accent">
              <form
                className="flex flex-col"
                style={{ gap: 10 }}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!editValue) return;
                  updateSystem.mutate(editValue, {
                    onSuccess: () => {
                      setEditDraft(null);
                      setShowEditForm(false);
                    },
                  });
                }}
              >
                <div
                  className="grid"
                  style={{
                    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                    gap: 10,
                  }}
                >
                  <label className="flex flex-col" style={{ gap: 4 }}>
                    <span style={METADATA_LABEL}>NAME</span>
                    <input
                      style={INPUT_STYLE}
                      value={editValue?.name ?? ""}
                      onChange={(e) =>
                        setEditDraft((cur) => ({
                          ...(cur ?? normalizeSystemForm(system)),
                          name: e.target.value,
                        }))
                      }
                    />
                  </label>
                  <label className="flex flex-col" style={{ gap: 4 }}>
                    <span style={METADATA_LABEL}>HOST</span>
                    <input
                      style={INPUT_STYLE}
                      value={editValue?.host ?? ""}
                      onChange={(e) =>
                        setEditDraft((cur) => ({
                          ...(cur ?? normalizeSystemForm(system)),
                          host: e.target.value,
                        }))
                      }
                    />
                  </label>
                  <label className="flex flex-col" style={{ gap: 4 }}>
                    <span style={METADATA_LABEL}>USERNAME</span>
                    <input
                      style={INPUT_STYLE}
                      value={editValue?.username ?? ""}
                      onChange={(e) =>
                        setEditDraft((cur) => ({
                          ...(cur ?? normalizeSystemForm(system)),
                          username: e.target.value,
                        }))
                      }
                    />
                  </label>
                  <label className="flex flex-col" style={{ gap: 4 }}>
                    <span style={METADATA_LABEL}>PORT</span>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      style={INPUT_STYLE}
                      value={editValue?.port ?? 22}
                      onChange={(e) =>
                        setEditDraft((cur) => ({
                          ...(cur ?? normalizeSystemForm(system)),
                          port: Number(e.target.value) || 22,
                        }))
                      }
                    />
                  </label>
                </div>
                <div className="flex items-center" style={{ gap: 8 }}>
                  <button
                    type="submit"
                    disabled={updateSystem.isPending}
                    style={{
                      ...ACCENT_BUTTON,
                      opacity: updateSystem.isPending ? 0.5 : 1,
                    }}
                  >
                    {updateSystem.isPending ? "saving…" : "save changes"}
                  </button>
                  <button
                    type="button"
                    style={HEADER_BUTTON}
                    onClick={() => setEditDraft(normalizeSystemForm(system))}
                  >
                    reset
                  </button>
                </div>
                {updateSystem.isError && (
                  <div style={ERROR_BOX}>
                    {(updateSystem.error as Error).message}
                  </div>
                )}
              </form>
            </WindowPanel>
          )}

          {deleteSystem.isError && (
            <div style={ERROR_BOX}>
              {(deleteSystem.error as Error).message}
            </div>
          )}

          {/* Module-contributed panels (system.detail slot) */}
          {systemDetailPanels.map((panel) => {
            const PanelComponent = panel.render;
            return (
              <WindowPanel
                key={panel.id}
                title={panel.label.toLowerCase()}
                tone="muted"
              >
                <PanelComponent systemId={parsedSystemId} />
              </WindowPanel>
            );
          })}
        </>
      )}
    </div>
  );
}
