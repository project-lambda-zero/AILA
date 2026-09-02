/**
 * VRTargetDetail -- target-first detail body for the `vr:targets` DataPage.
 *
 * Selecting a target row answers three operator questions: what is this
 * target, what happened to its analysis, and (when it failed) why + what to
 * do. The DataPage `sel` row is a snapshot that is never re-synced after the
 * list refetches, so this component fetches a live copy from
 * `GET /vr/targets/{id}` (a superset of `VRTargetSummary`) seeded by the row,
 * and every action invalidates that copy plus the parent list so the pane
 * reflects a re-enqueue without a manual reselect.
 *
 * Sections are independently collapsible panels: each native <button> header
 * carries `aria-expanded` and `aria-controls` pointing at its region panel id
 * (`aria-labelledby` back), keyboard-operable. Stage rows are limited to the stages
 * that apply to the target's kind, mirroring the backend
 * `_applicable_stages_for` split so structural no-op stages never render.
 */
import type { CSSProperties, JSX, ReactNode } from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import type { Investigation } from "../../api/types";
import { css } from "../css";
import { StatusBadge } from "./badges";
import StructuredValue from "./StructuredValue";
import TargetInvestigations from "./TargetInvestigations";

interface StageInfo {
  state?: string;
  attempts?: number;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
  [k: string]: unknown;
}

interface TargetTagRow {
  tag: string;
  source?: string;
}

interface TargetDetail {
  id: string;
  display_name?: string;
  kind?: string;
  status?: string;
  analysis_state?: string;
  analysis_state_message?: string | null;
  analysis_started_at?: string | null;
  analysis_completed_at?: string | null;
  analysis_stages?: Record<string, StageInfo> | null;
  descriptor?: Record<string, unknown>;
  primary_language?: string | null;
  secondary_languages?: string[];
  uploaded_filename?: string | null;
  android_package_name?: string | null;
  apk_overview?: Record<string, unknown> | null;
  workspace_name?: string | null;
  workspace_id?: string;
  tags?: Array<TargetTagRow | string>;
  created_at?: string | null;
  updated_at?: string | null;
}

// The stages a target's kind actually runs. Mirrors the backend
// `_applicable_stages_for` (target_analysis.py): android_apk runs the APK
// pipeline, every other kind runs the legacy ingestion pipeline. The
// inapplicable set is pre-marked DONE-skipped on the row, so listing only the
// applicable stages hides those no-ops.
const CORE_STAGES = ["ingestion", "capability_profile", "function_ranking"];
const APK_STAGES = ["apk_decode", "jadx_decompile", "react_native_extract", "index_decompiled", "static_summary"];

const EM_DASH = "\u2014";

const rootCss = css("grid-column:1/-1;display:flex;flex-direction:column;gap:10px;min-width:0;font-family:var(--font-mono);");
const toolbarCss = css("display:flex;flex-wrap:wrap;gap:6px;align-items:center;");
const kvGrid = css("display:grid;grid-template-columns:minmax(120px,160px) 1fr;gap:5px 12px;font-size:10.5px;align-content:start;min-width:0;");
const kvLabel = css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;");
const kvVal = css("color:var(--text-primary);word-break:break-word;min-width:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap;");
const sectionBox = css("border:1px solid var(--border-soft);border-radius:3px;background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;");
const sectionBody = css("padding:10px 12px;display:flex;flex-direction:column;gap:10px;min-width:0;");
const sectionTitleCss = css("font-size:9.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);");
const metaCss = css("font-size:8.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);");
const stageCardCss = css("border:1px solid var(--border-faint);border-radius:2px;background:var(--surface-sunk);padding:6px 9px;display:flex;flex-direction:column;gap:5px;min-width:0;");
const stageHeadCss = css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;");
const errBoxCss = css("margin:0;padding:6px 8px;border:1px solid var(--status-err,#d64545);border-radius:2px;background:color-mix(in srgb,var(--status-err,#d64545) 8%,transparent);font-family:var(--font-mono);font-size:9.5px;line-height:1.4;color:var(--status-err,#d64545);white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;");
const noticeOkCss = css("padding:6px 9px;border:1px solid var(--status-ok);border-radius:2px;background:color-mix(in srgb,var(--status-ok) 10%,transparent);color:var(--status-ok);font-size:10px;letter-spacing:0.02em;");
const noticeErrCss = css("padding:6px 9px;border:1px solid var(--status-err,#d64545);border-radius:2px;background:color-mix(in srgb,var(--status-err,#d64545) 10%,transparent);color:var(--status-err,#d64545);font-size:10px;letter-spacing:0.02em;word-break:break-word;");
const editBoxCss = css("border:1px solid var(--accent)55;border-radius:3px;background:var(--surface-sunk);padding:11px 12px;display:flex;flex-direction:column;gap:9px;");
const editLabelCss = css("display:flex;flex-direction:column;gap:3px;font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);");
const EDIT_INPUT = "background:var(--surface-card);border:1px solid var(--border);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:5px 7px;letter-spacing:0.02em;outline:none;";

const BTN_BASE =
  "padding:4px 11px;border-radius:2px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;text-align:center;";

function btnStyle(variant: "primary" | "ghost" | "warn", disabled: boolean): CSSProperties {
  const cursor = disabled ? "default" : "cursor:pointer;";
  const dim = disabled ? "opacity:0.45;" : "";
  if (variant === "primary") {
    return css(`${BTN_BASE}border:1px solid var(--accent);background:var(--accent);color:var(--text-on-accent);${cursor}${dim}`);
  }
  const color = variant === "warn" ? "var(--status-warn,#e6b84c)" : "var(--accent)";
  return css(`${BTN_BASE}border:1px solid ${color}66;background:transparent;color:${color};${cursor}${dim}`);
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** analysis_state has no entry in the shared status tone map for ready /
 * ingesting; map it here so ready reads success-green and ingesting reads
 * live rather than both collapsing to muted grey. */
function analysisTone(state: string | undefined): "ok" | "live" | "warn" | "err" | "muted" | "info" {
  switch ((state ?? "").toLowerCase()) {
    case "ready":
      return "ok";
    case "ingesting":
      return "live";
    case "failed":
      return "err";
    case "pending":
      return "info";
    default:
      return "muted";
  }
}

function Section({
  sectionKey,
  title,
  right,
  open,
  onToggle,
  children,
}: {
  sectionKey: string;
  title: string;
  right?: ReactNode;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}): JSX.Element {
  const panelId = `vrtd-section-${sectionKey}`;
  const headerId = `${panelId}-header`;
  return (
    <div style={sectionBox}>
      <button
        type="button"
        id={headerId}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={onToggle}
        style={css(
          `display:flex;align-items:center;gap:8px;width:100%;padding:6px 10px;border:0;border-bottom:${open ? "1px solid var(--border)" : "0"};background:var(--surface-chrome);color:var(--text-primary);font-family:var(--font-mono);cursor:pointer;text-align:left;`,
        )}
      >
        <span style={css(`flex:0 0 auto;font-size:9px;color:var(--text-muted);`)}>{open ? "\u25be" : "\u25b8"}</span>
        <span style={sectionTitleCss}>{title}</span>
        <span style={css("flex:1;")} />
        {right}
      </button>
      {open ? (
        <div id={panelId} role="region" aria-labelledby={headerId} style={sectionBody}>
          {children}
        </div>
      ) : null}
    </div>
  );
}

function KV({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <span style={{ display: "contents" }}>
      <span style={kvLabel}>{label}</span>
      <span style={kvVal}>{children}</span>
    </span>
  );
}

export interface VRTargetDetailProps {
  /** The selected target row (VRTargetSummary shape) from the list query. */
  row: Record<string, unknown>;
  /** Opens the X-Ray for one investigation (registry wires the module key). */
  onOpenXray: (inv: Investigation) => void;
}

export default function VRTargetDetail({ row, onOpenXray }: VRTargetDetailProps): JSX.Element {
  const id = String(row.id ?? "");
  const qc = useQueryClient();

  // Live copy: the DataPage snapshot never re-syncs, so poll the single-target
  // endpoint (superset of the summary) to reflect stage/state changes after an
  // action without a reselect.
  const live = useQuery({
    queryKey: ["vr-target-detail", id],
    queryFn: () => apiFetch<TargetDetail>(`/vr/targets/${encodeURIComponent(id)}`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: 15000,
  });

  const t = useMemo<TargetDetail>(
    () => ({ ...row, ...(live.data ?? {}) }) as unknown as TargetDetail,
    [row, live.data],
  );

  const kind = (t.kind ?? "").toLowerCase();
  const isApk = kind === "android_apk";
  const failed = (t.analysis_state ?? "").toLowerCase() === "failed";

  const [open, setOpen] = useState<Record<string, boolean>>({ status: true });
  const toggle = (key: string): void => setOpen((cur) => ({ ...cur, [key]: !cur[key] }));

  const [notice, setNotice] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [deleted, setDeleted] = useState(false);
  const [editing, setEditing] = useState(false);

  const refresh = (): void => {
    void qc.invalidateQueries({ queryKey: ["vr-target-detail", id] });
    void qc.invalidateQueries({ queryKey: ["datapage"] });
    void qc.invalidateQueries({ queryKey: ["target-investigations"] });
  };

  const act = useMutation({
    mutationFn: (v: { path: string; okText: string }) => apiFetch<unknown>(v.path, { method: "POST" }),
    onSuccess: (_data, v) => {
      setNotice({ kind: "ok", text: v.okText });
      refresh();
    },
    onError: (e) => setNotice({ kind: "err", text: e instanceof Error ? e.message : "request failed" }),
  });

  const del = useMutation({
    mutationFn: () => apiFetch<unknown>(`/vr/targets/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => {
      setDeleted(true);
      void qc.invalidateQueries({ queryKey: ["datapage"] });
    },
    onError: (e) => setNotice({ kind: "err", text: e instanceof Error ? e.message : "delete failed" }),
  });

  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch<unknown>(`/vr/targets/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      setNotice({ kind: "ok", text: "target updated" });
      setEditing(false);
      refresh();
    },
    onError: (e) => setNotice({ kind: "err", text: e instanceof Error ? e.message : "update failed" }),
  });

  const busy = act.isPending || del.isPending || patch.isPending;
  const base = `/vr/targets/${encodeURIComponent(id)}`;

  if (deleted) {
    return (
      <div style={rootCss}>
        <div style={noticeOkCss}>target deleted &mdash; close this panel with the {"\u2715"} above.</div>
      </div>
    );
  }

  const stageOrder = isApk ? APK_STAGES : CORE_STAGES;
  const stages = asRecord(t.analysis_stages) ?? {};
  const relevantStages = stageOrder
    .map((name) => ({ name, info: asRecord(stages[name]) as StageInfo | null }))
    .filter((s): s is { name: string; info: StageInfo } => s.info !== null);

  const tags = (t.tags ?? []).map((tg) => (typeof tg === "string" ? tg : tg.tag)).filter(Boolean);
  const secondary = (t.secondary_languages ?? []).filter(Boolean);
  const apkOverview = asRecord(t.apk_overview);
  const descriptor = asRecord(t.descriptor);

  return (
    <div style={rootCss}>
      {/* Action toolbar -- every applicable target operation, gated on kind + state. */}
      <div style={toolbarCss}>
        <button type="button" disabled={busy} onClick={() => setEditing((v) => !v)} style={btnStyle("ghost", busy)}>
          {editing ? "cancel edit" : "edit"}
        </button>
        <button
          type="button"
          disabled={busy}
          title="stage-level retry of the analysis pipeline"
          onClick={() => act.mutate({ path: `${base}/resume-analysis`, okText: "analysis re-enqueued" })}
          style={btnStyle(failed ? "primary" : "ghost", busy)}
        >
          retry analysis
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => act.mutate({ path: `${base}/analyze`, okText: "re-analysis enqueued" })}
          style={btnStyle("ghost", busy)}
        >
          re-analyze
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => act.mutate({ path: `${base}/rank`, okText: "ranking enqueued" })}
          style={btnStyle("ghost", busy)}
        >
          re-rank
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => act.mutate({ path: `${base}/refresh-source`, okText: "source refresh requested" })}
          style={btnStyle("ghost", busy)}
        >
          refresh source
        </button>
        {isApk ? (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={() => act.mutate({ path: `${base}/apk-static-audit`, okText: "apk static audit dispatched" })}
              style={btnStyle("ghost", busy)}
            >
              apk static audit
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => act.mutate({ path: `${base}/masvs-audit`, okText: "masvs audit dispatched" })}
              style={btnStyle("ghost", busy)}
            >
              masvs audit
            </button>
          </>
        ) : null}
        <span style={css("flex:1;")} />
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            if (window.confirm("Delete this target? This cannot be undone.")) del.mutate();
          }}
          style={btnStyle("warn", busy)}
        >
          delete
        </button>
      </div>

      {notice ? <div style={notice.kind === "ok" ? noticeOkCss : noticeErrCss}>{notice.text}</div> : null}

      {editing ? (
        <EditForm
          t={t}
          pending={patch.isPending}
          onSubmit={(body) => patch.mutate(body)}
          onCancel={() => setEditing(false)}
        />
      ) : null}

      {/* Status & analysis (primary, expanded by default). */}
      <Section
        sectionKey="status"
        title="status & analysis"
        open={open.status ?? true}
        onToggle={() => toggle("status")}
        right={<StatusBadge value={t.analysis_state ?? "\u2014"} tone={analysisTone(t.analysis_state)} />}
      >
        <div style={kvGrid}>
          <KV label="status">
            <StatusBadge value={t.status ?? "\u2014"} />
            <span>{t.status ?? EM_DASH}</span>
          </KV>
          <KV label="analysis state">
            <StatusBadge value={t.analysis_state ?? "\u2014"} tone={analysisTone(t.analysis_state)} />
            <span>{t.analysis_state ?? EM_DASH}</span>
          </KV>
          <KV label="analysis started">{t.analysis_started_at ?? EM_DASH}</KV>
          <KV label="analysis completed">{t.analysis_completed_at ?? EM_DASH}</KV>
        </div>

        {t.analysis_state_message ? (
          <pre style={failed ? errBoxCss : css("margin:0;padding:6px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:9.5px;line-height:1.4;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;")}>
            {t.analysis_state_message}
          </pre>
        ) : null}

        <div style={css("display:flex;flex-direction:column;gap:6px;")}>
          <div style={metaCss}>stages ({relevantStages.length})</div>
          {relevantStages.length === 0 ? (
            <div style={css("font-size:10px;color:var(--text-faint);")}>no stage records for this target.</div>
          ) : (
            relevantStages.map(({ name, info }) => {
              const stageFailed = (info.state ?? "").toLowerCase() === "failed";
              return (
                <div key={name} style={stageCardCss}>
                  <div style={stageHeadCss}>
                    <span style={css("font-size:10px;letter-spacing:0.06em;color:var(--text-primary);")}>{name.replace(/_/g, " ")}</span>
                    <StatusBadge value={info.state ?? "\u2014"} />
                    {typeof info.attempts === "number" ? <span style={metaCss}>{info.attempts} attempt{info.attempts === 1 ? "" : "s"}</span> : null}
                  </div>
                  {info.started_at || info.completed_at ? (
                    <div style={metaCss}>
                      started {info.started_at ?? EM_DASH} {"\u00b7"} completed {info.completed_at ?? EM_DASH}
                    </div>
                  ) : null}
                  {stageFailed && info.error ? <pre style={errBoxCss}>{info.error}</pre> : null}
                </div>
              );
            })
          )}
        </div>
      </Section>

      {/* Details -- kind-specific descriptor + languages + provenance. */}
      <Section sectionKey="details" title="details" open={open.details ?? false} onToggle={() => toggle("details")}>
        <div style={kvGrid}>
          <KV label="kind">{t.kind ?? EM_DASH}</KV>
          <KV label="workspace">{t.workspace_name ?? EM_DASH}</KV>
          <KV label="primary language">{t.primary_language ?? EM_DASH}</KV>
          <KV label="secondary languages">{secondary.length ? secondary.join(", ") : EM_DASH}</KV>
          {t.uploaded_filename ? <KV label="uploaded file">{t.uploaded_filename}</KV> : null}
          {isApk && t.android_package_name ? <KV label="package">{t.android_package_name}</KV> : null}
          <KV label="tags">{tags.length ? tags.join(", ") : EM_DASH}</KV>
          <KV label="created">{t.created_at ?? EM_DASH}</KV>
          <KV label="updated">{t.updated_at ?? EM_DASH}</KV>
        </div>
        <div style={css("display:flex;flex-direction:column;gap:5px;")}>
          <div style={metaCss}>descriptor</div>
          {descriptor && Object.keys(descriptor).length ? (
            <StructuredValue value={descriptor} />
          ) : (
            <span style={css("font-size:10px;color:var(--text-faint);")}>no descriptor recorded.</span>
          )}
        </div>
      </Section>

      {/* APK overview -- android_apk only, absent (no empty card) otherwise. */}
      {isApk && apkOverview && Object.keys(apkOverview).length ? (
        <Section sectionKey="apk" title="apk overview" open={open.apk ?? false} onToggle={() => toggle("apk")}>
          <StructuredValue value={apkOverview} />
        </Section>
      ) : null}

      {/* Investigations scoped to this target. */}
      <Section sectionKey="investigations" title="investigations" open={open.investigations ?? false} onToggle={() => toggle("investigations")}>
        <TargetInvestigations targetId={id} endpoint="/vr/investigations" onOpenXray={onOpenXray} />
      </Section>
    </div>
  );
}

function EditForm({
  t,
  pending,
  onSubmit,
  onCancel,
}: {
  t: TargetDetail;
  pending: boolean;
  onSubmit: (body: Record<string, unknown>) => void;
  onCancel: () => void;
}): JSX.Element {
  const [displayName, setDisplayName] = useState(t.display_name ?? "");
  const [primary, setPrimary] = useState(t.primary_language ?? "");
  const [secondary, setSecondary] = useState((t.secondary_languages ?? []).join(", "));
  const [status, setStatus] = useState((t.status ?? "active").toLowerCase());
  const [tags, setTags] = useState(
    (t.tags ?? []).map((tg) => (typeof tg === "string" ? tg : tg.tag)).filter(Boolean).join(", "),
  );

  const trimmedName = displayName.trim();
  const canSubmit = trimmedName.length > 0 && !pending;

  const submit = (): void => {
    if (!canSubmit) return;
    onSubmit({
      display_name: trimmedName,
      primary_language: primary.trim() || null,
      secondary_languages: secondary.split(",").map((s) => s.trim()).filter(Boolean),
      status,
      tags: tags.split(",").map((s) => s.trim()).filter(Boolean),
    });
  };

  return (
    <div style={editBoxCss}>
      <label style={editLabelCss}>
        display name
        <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} style={css(EDIT_INPUT)} />
      </label>
      <label style={editLabelCss}>
        primary language
        <input value={primary} onChange={(e) => setPrimary(e.target.value)} placeholder="auto-detected when blank" style={css(EDIT_INPUT)} />
      </label>
      <label style={editLabelCss}>
        secondary languages (comma-separated)
        <input value={secondary} onChange={(e) => setSecondary(e.target.value)} style={css(EDIT_INPUT)} />
      </label>
      <label style={editLabelCss}>
        status
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={css(EDIT_INPUT)}>
          <option value="active">active</option>
          <option value="archived">archived</option>
          <option value="quarantined">quarantined</option>
        </select>
      </label>
      <label style={editLabelCss}>
        tags (comma-separated)
        <input value={tags} onChange={(e) => setTags(e.target.value)} style={css(EDIT_INPUT)} />
      </label>
      <div style={css("display:flex;gap:6px;align-items:center;")}>
        <button type="button" disabled={!canSubmit} onClick={submit} style={btnStyle("primary", !canSubmit)}>
          {pending ? "saving\u2026" : "save"}
        </button>
        <button type="button" disabled={pending} onClick={onCancel} style={btnStyle("ghost", pending)}>
          cancel
        </button>
        {trimmedName.length === 0 ? <span style={css("font-size:9px;color:var(--status-warn,#e6b84c);")}>name is required</span> : null}
      </div>
    </div>
  );
}
