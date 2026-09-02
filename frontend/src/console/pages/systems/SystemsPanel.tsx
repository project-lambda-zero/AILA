/**
 * Systems registry panel + system detail panel. Re-homed from the
 * vulnerability module into the platform-owned admin/systems page
 * (system-registry-platform.md req 11): the SSH host registry is not
 * vulnerability-scoped, so it lives once at admin:systems and reads from
 * the platform /systems router directly.
 *
 * SystemsSection renders standalone: no visible gating (its own page owns
 * layout), no auto-open create plumbing (its own "+ register system" button
 * is the sole entry). The wizard registry's tag-vocabulary entry opens the
 * page with section "systems:tags"; SystemsRegistryPage passes that down as
 * initialVocabOpen, so the vocab modal raises on mount (or when the section
 * lands on an already-open window). Adds a free-text role filter, a
 * "refresh connectivity"
 * button that forces a live SSH probe pass (probe=true) over the current
 * page, and a role column + last-checked_at hint next to the connectivity
 * chip. Every other affordance (detail, tags, heartbeat, create/edit) is
 * carried over unchanged.
 */
import { useEffect, useState } from "react";
import type { JSX } from "react";

import { useAuth } from "../../../api/auth";
import { ApiError } from "../../../api/client";
import { apiErrDetail } from "../../../api/parse";
import {
  useAssignSystemTag,
  useDeleteSystem,
  useDeleteSystemTag,
  useSystem,
  useSystemConnectivity,
  useSystemFindings,
  useSystemHeartbeat,
  useSystemScans,
  useSystems,
  useSystemTags,
  useTagVocabulary,
  type SystemEnriched,
} from "../../../api/systems";
import { css } from "../../css";

import SystemForm from "./SystemForm";
import TagVocabularyModal from "./TagVocabularyModal";
import {
  SectionTitle,
  connChipStyle,
  normSev,
  sevChipStyle,
  statusChipStyle,
} from "../vulnerability/helpers";
import { H } from "../vulnerability/palette";

/** Console role ladder for gating tag controls: admins manage the vocabulary
 * and pick keys from a select; operators+ assign (free-text for non-admins)
 * and remove tags; readers get neither. Unknown roles fail closed at -1. */
const ROLE_RANK: Record<string, number> = { reader: 0, operator: 1, admin: 2 };
const roleRank = (role: string | undefined): number =>
  role != null ? ROLE_RANK[role] ?? -1 : -1;

/* =============================== SYSTEMS ================================= */

function SystemsSection({ initialVocabOpen = false }: { initialVocabOpen?: boolean }): JSX.Element {
  const [roleFilter, setRoleFilter] = useState<string>("");
  // `probe` toggles a live-heartbeat pass on the list endpoint. Setting it
  // true changes the react-query key, so the query refetches with probe=true;
  // once the fetch settles we reset it so subsequent refetches (react-query's
  // 15s stale window) don't keep asking the backend to walk every host.
  const [probe, setProbe] = useState<boolean>(false);
  const systemsQ = useSystems(1, 200, roleFilter.trim() || undefined, probe);
  const [formMode, setFormMode] = useState<"create" | { edit: SystemEnriched } | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const role = useAuth((s) => s.user?.role);
  const isAdmin = roleRank(role) >= ROLE_RANK.admin;
  const [vocabOpen, setVocabOpen] = useState<boolean>(false);

  // Wizard-registry entry (tag-vocabulary, chat picker) opens this page with
  // section "systems:tags"; raise the modal when that section lands, whether
  // on a fresh mount or an in-place section update on an open window.
  useEffect(() => {
    if (initialVocabOpen) setVocabOpen(true);
  }, [initialVocabOpen]);

  useEffect(() => {
    if (probe && !systemsQ.isFetching) setProbe(false);
  }, [probe, systemsQ.isFetching]);

  const items = systemsQ.data?.items ?? [];
  const selected = items.find((s) => s.id === selectedId) ?? null;

  const rightAction = (
    <div style={css("display:flex;gap:8px;")}>
      <button
        type="button"
        onClick={() => setProbe(true)}
        disabled={probe || systemsQ.isFetching}
        style={css(
          "padding:0 13px;height:28px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:3px;cursor:pointer;",
        )}
      >
        {probe || (systemsQ.isFetching && probe) ? "probing \u2026" : "refresh connectivity"}
      </button>
      {isAdmin ? (
        <button
          type="button"
          onClick={() => setVocabOpen(true)}
          style={css(
            "padding:0 13px;height:28px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:3px;cursor:pointer;",
          )}
        >
          manage tags
        </button>
      ) : null}
      <button
        type="button"
        onClick={() => setFormMode("create")}
        style={css(
          "padding:0 13px;height:28px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:pointer;box-shadow:0 0 12px " + H.accent30 + ";",
        )}
      >
        {"+ register system"}
      </button>
    </div>
  );

  const gridCols = "160px 150px 110px 90px 130px 90px 80px 60px";

  return (
    <section style={css("position:relative;flex:1;min-height:0;overflow:auto;padding:16px 18px;")}>
      <SectionTitle glyph={"\u25a4"} label="Systems Registry" right={rightAction} />

      <div style={css("margin-top:12px;display:flex;align-items:center;gap:8px;")}>
        <label style={css("display:flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>
          <span>filter by role</span>
          <input
            type="text"
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            placeholder="e.g. vuln-scan"
            style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:5px 8px;color:var(--text-primary);font-family:var(--font-mono);font-size:10.5px;border-radius:2px;min-width:180px;")}
          />
        </label>
        {roleFilter.trim() ? (
          <button
            type="button"
            onClick={() => setRoleFilter("")}
            style={css("padding:0 8px;height:24px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;")}
          >
            clear
          </button>
        ) : null}
      </div>

      <div style={css("margin-top:14px;display:flex;gap:12px;")}>
        <div style={css("flex:1;min-width:0;")}>
          <div style={css("display:grid;grid-template-columns:" + gridCols + ";gap:10px;padding:8px 12px;background:var(--surface-sunk);border:1px solid var(--border-soft);border-bottom:0;border-radius:4px 4px 0 0;font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
            <span>name</span>
            <span>host</span>
            <span>role</span>
            <span>distro</span>
            <span>connectivity</span>
            <span>last scan</span>
            <span>top sev</span>
            <span></span>
          </div>
          <div style={css("border:1px solid var(--border-soft);border-radius:0 0 4px 4px;overflow:hidden;")}>
            {systemsQ.isLoading ? (
              <div style={css("padding:22px;text-align:center;font-size:11px;color:var(--text-faint);")}>loading {"\u2026"}</div>
            ) : systemsQ.isError ? (
              <div style={css("padding:22px;text-align:center;font-size:11px;color:var(--status-warn);")}>failed to load systems.</div>
            ) : items.length === 0 ? (
              <div style={css("padding:26px;text-align:center;font-size:11px;color:var(--text-muted);")}>
                no systems registered {"\u2014"} click "register system" to add one.
              </div>
            ) : items.map((s) => {
              const sev = normSev(s.top_severity);
              const isSel = selectedId === s.id;
              const lastChecked = s.last_checked_at ? s.last_checked_at.slice(0, 19).replace("T", " ") : null;
              return (
                <div
                  key={s.id}
                  onClick={() => setSelectedId(s.id)}
                  style={css(
                    "display:grid;grid-template-columns:" + gridCols + ";gap:10px;padding:8px 12px;border-bottom:1px solid var(--border-faint);cursor:pointer;background:" +
                    (isSel ? H.accent1c : "var(--surface-card)") + ";",
                  )}
                >
                  <span style={css("font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;align-self:center;")}>{s.name}</span>
                  <span style={css("font-size:10.5px;color:var(--text-muted);font-family:var(--font-mono);align-self:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{s.host}</span>
                  <span style={css("font-size:10px;color:" + (s.role ? "var(--text-primary)" : "var(--text-faint)") + ";font-family:var(--font-mono);align-self:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{s.role || "\u2014"}</span>
                  <span style={css("font-size:10px;color:var(--text-muted);align-self:center;")}>{s.distro}</span>
                  <span style={css("align-self:center;display:flex;flex-direction:column;gap:2px;min-width:0;")}>
                    <span style={connChipStyle(s.connectivity_status)}>{s.connectivity_status ?? "unknown"}</span>
                    {lastChecked ? (
                      <span style={css("font-size:9px;color:var(--text-faint);font-family:var(--font-mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{lastChecked}</span>
                    ) : null}
                  </span>
                  <span style={css("font-size:10px;color:var(--text-muted);align-self:center;")}>{(s.last_scan_at ?? "\u2014").slice(0, 10) || "\u2014"}</span>
                  <span style={css("align-self:center;")}>{sev ? <span style={sevChipStyle(sev)}>{sev}</span> : <span style={css("font-size:10px;color:var(--text-faint);")}>{"\u2014"}</span>}</span>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); setFormMode({ edit: s }); }}
                    style={css("align-self:center;padding:0 8px;height:22px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;")}
                  >
                    edit
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {selected ? (
          <div style={css("flex:0 0 320px;border:1px solid var(--border);background:var(--surface-card);border-radius:4px;box-shadow:var(--bevel-raised);padding:12px 14px;display:flex;flex-direction:column;gap:11px;max-height:calc(100vh - 200px);overflow:auto;")}>
            <SystemDetailPanel id={selected.id} row={selected} onClose={() => setSelectedId(null)} onEdit={() => setFormMode({ edit: selected })} onOpenVocabulary={() => setVocabOpen(true)} />
          </div>
        ) : null}
      </div>

      {formMode !== null ? (
        <SystemForm
          mode={formMode}
          onClose={() => setFormMode(null)}
          onDone={(row) => { if (!row) setSelectedId(null); else setSelectedId(row.id); }}
        />
      ) : null}

      {vocabOpen ? <TagVocabularyModal onClose={() => setVocabOpen(false)} /> : null}
    </section>
  );
}

interface SystemDetailPanelProps {
  id: number;
  row: SystemEnriched;
  onClose: () => void;
  onEdit: () => void;
  /** Open the admin tag-vocabulary editor -- surfaced from the 422 affordance
   *  when an admin assigns a key that is not yet in the vocabulary. */
  onOpenVocabulary: () => void;
}

function SystemDetailPanel(props: SystemDetailPanelProps): JSX.Element {
  const detailQ = useSystem(props.id);
  const connQ = useSystemConnectivity(props.id);
  const hbQ = useSystemHeartbeat(props.id);
  const findingsQ = useSystemFindings(props.id, 1, 10);
  const scansQ = useSystemScans(props.id, 1, 6);
  const del = useDeleteSystem();
  const [confirmDelete, setConfirmDelete] = useState<boolean>(false);

  const role = useAuth((s) => s.user?.role);
  const isAdmin = roleRank(role) >= ROLE_RANK.admin;
  const canAssign = roleRank(role) >= ROLE_RANK.operator;
  const tagsQ = useSystemTags(props.id, canAssign);
  // Admins list the vocabulary to pick keys from a select; operators assign
  // free-text and learn of an unknown key via the 422 (they cannot GET the
  // admin-only vocabulary).
  const vocabQ = useTagVocabulary(isAdmin);
  const assign = useAssignSystemTag(props.id);
  const delTag = useDeleteSystemTag(props.id);
  const [newKey, setNewKey] = useState<string>("");
  const [newValue, setNewValue] = useState<string>("");
  const [assignError, setAssignError] = useState<string | null>(null);
  const [assign422, setAssign422] = useState<boolean>(false);

  const detail = detailQ.data;

  const doDelete = (): void => {
    del.mutate(props.id, { onSuccess: () => props.onClose() });
  };

  const doAssign = (): void => {
    const key = newKey.trim();
    if (!key) {
      setAssignError("tag key is required");
      setAssign422(false);
      return;
    }
    setAssignError(null);
    setAssign422(false);
    assign.mutate(
      { tag_key: key, tag_value: newValue.trim() },
      {
        onSuccess: () => { setNewKey(""); setNewValue(""); },
        onError: (e) => {
          setAssignError(apiErrDetail(e));
          setAssign422(e instanceof ApiError && e.status === 422);
        },
      },
    );
  };

  return (
    <>
      <div style={css("display:flex;align-items:center;gap:8px;")}>
        <span style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>
          {"system \u00b7 " + props.row.name}
        </span>
        <span style={css("flex:1;")} />
        <button type="button" onClick={props.onClose} style={css("width:22px;height:22px;display:flex;align-items:center;justify-content:center;background:transparent;border:0;color:var(--text-muted);cursor:pointer;")}>
          {"\u2715"}
        </button>
      </div>

      <div style={css("display:grid;grid-template-columns:88px 1fr;gap:6px 10px;font-size:11px;")}>
        <span style={css("color:var(--text-faint);letter-spacing:0.06em;")}>host</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{props.row.host}</span>
        <span style={css("color:var(--text-faint);letter-spacing:0.06em;")}>ssh</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{props.row.username + "@" + props.row.host + ":" + (detail?.port ?? props.row.port)}</span>
        <span style={css("color:var(--text-faint);letter-spacing:0.06em;")}>distro</span>
        <span style={css("color:var(--text-primary);")}>{props.row.distro}</span>
        {props.row.description ? (
          <>
            <span style={css("color:var(--text-faint);letter-spacing:0.06em;")}>notes</span>
            <span style={css("color:var(--text-primary);white-space:pre-wrap;")}>{props.row.description}</span>
          </>
        ) : null}
        <span style={css("color:var(--text-faint);letter-spacing:0.06em;")}>scan count</span>
        <span style={css("color:var(--text-primary);")}>{detail?.scan_count ?? "\u2014"}</span>
      </div>

      <div style={css("display:flex;gap:6px;")}>
        <button type="button" onClick={props.onEdit} style={css("padding:0 12px;height:26px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--accent);background:" + H.accent1c + ";border:1px solid " + H.accent59 + ";border-radius:2px;cursor:pointer;")}>
          edit
        </button>
        {confirmDelete ? (
          <>
            <button type="button" onClick={doDelete} disabled={del.isPending} style={css("padding:0 12px;height:26px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#ff5f87;background:#ff5f871c;border:1px solid #ff5f8759;border-radius:2px;cursor:pointer;")}>
              {del.isPending ? "deleting \u2026" : "confirm"}
            </button>
            <button type="button" onClick={() => setConfirmDelete(false)} style={css("padding:0 12px;height:26px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;")}>
              cancel
            </button>
          </>
        ) : (
          <button type="button" onClick={() => setConfirmDelete(true)} style={css("padding:0 12px;height:26px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#ff5f87;background:transparent;border:1px solid #ff5f8759;border-radius:2px;cursor:pointer;")}>
            delete
          </button>
        )}
      </div>

      {canAssign ? (
        <div style={css("border-top:1px solid var(--border-soft);padding-top:9px;")}>
          <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>tags</div>
          <div style={css("margin-top:6px;display:flex;flex-wrap:wrap;gap:5px;")}>
            {tagsQ.isLoading ? (
              <span style={css("font-size:10px;color:var(--text-faint);")}>loading {"\u2026"}</span>
            ) : tagsQ.isError ? (
              <span style={css("font-size:10px;color:var(--status-warn);")}>could not load tags.</span>
            ) : (tagsQ.data ?? []).length === 0 ? (
              <span style={css("font-size:10px;color:var(--text-faint);")}>no tags assigned.</span>
            ) : (tagsQ.data ?? []).map((t) => (
              <span key={t.id} style={css("display:inline-flex;align-items:center;gap:5px;font-family:var(--font-mono);font-size:10px;color:var(--accent);background:" + H.accent1c + ";border:1px solid " + H.accent59 + ";border-radius:2px;padding:2px 6px;")}>
                {t.tag_key + (t.tag_value ? "=" + t.tag_value : "")}
                <button
                  type="button"
                  title="remove tag"
                  onClick={() => delTag.mutate(t.id)}
                  disabled={delTag.isPending}
                  style={css("background:transparent;border:0;color:var(--text-muted);cursor:pointer;font-size:11px;line-height:1;padding:0;")}
                >
                  {"\u2715"}
                </button>
              </span>
            ))}
          </div>
          <div style={css("margin-top:8px;display:flex;gap:6px;align-items:center;")}>
            {isAdmin ? (
              <select
                value={newKey}
                onChange={(e) => { setNewKey(e.target.value); setAssignError(null); }}
                style={css("flex:1;min-width:0;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:5px 7px;color:var(--text-primary);font-family:var(--font-mono);font-size:10px;border-radius:2px;")}
              >
                <option value="">select tag key {"\u2026"}</option>
                {(vocabQ.data ?? []).map((v) => <option key={v.id} value={v.tag_key}>{v.tag_key}</option>)}
              </select>
            ) : (
              <input
                type="text"
                value={newKey}
                onChange={(e) => { setNewKey(e.target.value); setAssignError(null); }}
                placeholder="tag key"
                style={css("flex:1;min-width:0;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:5px 7px;color:var(--text-primary);font-family:var(--font-mono);font-size:10px;border-radius:2px;")}
              />
            )}
            <input
              type="text"
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder="value (optional)"
              style={css("width:110px;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:5px 7px;color:var(--text-primary);font-family:var(--font-mono);font-size:10px;border-radius:2px;")}
            />
            <button
              type="button"
              onClick={doAssign}
              disabled={assign.isPending || newKey.trim() === ""}
              style={css("padding:0 10px;height:26px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--accent);background:" + H.accent1c + ";border:1px solid " + H.accent59 + ";border-radius:2px;cursor:pointer;")}
            >
              {assign.isPending ? "\u2026" : "assign"}
            </button>
          </div>
          {assignError ? (
            <div style={css("margin-top:6px;font-size:10.5px;color:var(--status-warn);display:flex;flex-wrap:wrap;align-items:center;gap:8px;")}>
              <span>{assignError}</span>
              {isAdmin && assign422 ? (
                <button
                  type="button"
                  onClick={props.onOpenVocabulary}
                  style={css("padding:0 8px;height:22px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--accent);background:transparent;border:1px solid " + H.accent59 + ";border-radius:2px;cursor:pointer;")}
                >
                  manage vocabulary
                </button>
              ) : null}
            </div>
          ) : null}
          {delTag.isError ? (
            <div style={css("margin-top:6px;font-size:10.5px;color:var(--status-warn);")}>remove failed {"\u2014"} {apiErrDetail(delTag.error)}</div>
          ) : null}
        </div>
      ) : null}

      <div style={css("border-top:1px solid var(--border-soft);padding-top:9px;")}>
        <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>ssh heartbeat</div>
        <div style={css("margin-top:6px;display:grid;grid-template-columns:88px 1fr;gap:5px 10px;font-size:10.5px;")}>
          <span style={css("color:var(--text-faint);")}>connectivity</span>
          <span style={connChipStyle(connQ.data?.status ?? null)}>{connQ.data?.status ?? (connQ.isLoading ? "loading" : "unknown")}</span>
          <span style={css("color:var(--text-faint);")}>last probe</span>
          <span style={css("color:var(--text-muted);")}>{connQ.data?.last_checked ?? "\u2014"}</span>
          <span style={css("color:var(--text-faint);")}>live</span>
          <span style={css("color:" + (hbQ.data?.reachable ? "var(--mint,#97dbbe)" : "var(--status-warn)") + ";")}>
            {hbQ.isLoading ? "probing \u2026" : hbQ.data ? (hbQ.data.reachable ? "reachable" : "unreachable") : (hbQ.isError ? "probe failed" : "\u2014")}
          </span>
          {hbQ.data?.latency_ms !== null && hbQ.data?.latency_ms !== undefined ? (
            <>
              <span style={css("color:var(--text-faint);")}>latency</span>
              <span style={css("color:var(--text-primary);")}>{hbQ.data.latency_ms.toFixed(0) + " ms"}</span>
            </>
          ) : null}
          {hbQ.data?.error ? (
            <>
              <span style={css("color:var(--text-faint);")}>error</span>
              <span style={css("color:var(--status-warn);white-space:pre-wrap;")}>{hbQ.data.error}</span>
            </>
          ) : null}
        </div>
      </div>

      <div style={css("border-top:1px solid var(--border-soft);padding-top:9px;")}>
        <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
          recent findings {findingsQ.data ? "(" + findingsQ.data.total + ")" : ""}
        </div>
        <div style={css("margin-top:6px;display:flex;flex-direction:column;gap:3px;")}>
          {findingsQ.isLoading ? (
            <span style={css("font-size:10px;color:var(--text-faint);")}>loading {"\u2026"}</span>
          ) : (findingsQ.data?.items ?? []).length === 0 ? (
            <span style={css("font-size:10px;color:var(--text-faint);")}>no findings on this host.</span>
          ) : (findingsQ.data?.items ?? []).slice(0, 6).map((f) => {
            const sev = normSev(f.severity);
            return (
              <div key={String(f.id ?? f.cve_id)} style={css("display:grid;grid-template-columns:110px 1fr 60px;gap:6px;font-size:10px;")}>
                <span style={css("color:var(--accent);font-family:var(--font-mono);")}>{f.cve_id ?? "\u2014"}</span>
                <span style={css("color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{f.package ?? "\u2014"}</span>
                <span>{sev ? <span style={sevChipStyle(sev)}>{sev}</span> : null}</span>
              </div>
            );
          })}
        </div>
      </div>

      <div style={css("border-top:1px solid var(--border-soft);padding-top:9px;")}>
        <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
          recent scans {scansQ.data ? "(" + scansQ.data.total + ")" : ""}
        </div>
        <div style={css("margin-top:6px;display:flex;flex-direction:column;gap:3px;")}>
          {scansQ.isLoading ? (
            <span style={css("font-size:10px;color:var(--text-faint);")}>loading {"\u2026"}</span>
          ) : (scansQ.data?.items ?? []).length === 0 ? (
            <span style={css("font-size:10px;color:var(--text-faint);")}>no scans against this host.</span>
          ) : (scansQ.data?.items ?? []).slice(0, 5).map((sc, i) => (
            <div key={sc.run_id ?? i} style={css("display:grid;grid-template-columns:1fr 68px;gap:6px;font-size:10px;")}>
              <span style={css("color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--font-mono);")}>
                {sc.run_id ?? "\u2014"}
              </span>
              <span style={statusChipStyle(sc.status ?? "\u2014")}>{sc.status ?? "\u2014"}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

export default SystemsSection;
