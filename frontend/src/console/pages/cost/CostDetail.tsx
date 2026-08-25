/**
 * `admin:cost` detail segment (req 47): filterable, paginated LLM interaction
 * log with a per-run drill-in side panel. The draft filter state is local so
 * an operator can compose several filter changes before applying; the applied
 * `props.filters` drives the actual `/admin/llm-log` fetch (and resets
 * pagination on identity change). A module `<select>` is populated from a
 * bounded discovery fetch (200 recent rows) and, on pick, expands to the
 * exact task_type list that module owns, so filtering stays server-side.
 */
import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, JSX, KeyboardEvent } from "react";

import type { LlmLogEntry, LlmLogQuery } from "../../../api/cost";
import { useLlmLog, useRunBreakdown } from "../../../api/cost";
import { css } from "../../css";
import {
  apiErrMessage,
  btnGhost,
  btnPrimary,
  chipFaint,
  EMPTY_DETAIL_FILTERS,
  emptyNote,
  fmtInt,
  fmtUsd,
  inputStyle,
  label,
  moduleOf,
  pad,
  panelBox,
  panelTitle,
  dot,
  scroll,
  stack,
  td,
  th,
  warnText,
} from "./kit";
import type { CostDetailProps, DetailFilters } from "./kit";

const PAGE_LIMIT = 50;
const SIDE_PANEL_WIDTH = 330;

const rootRow = css(
  "display:flex;gap:12px;min-height:0;flex:1;align-items:stretch;",
);
const filterGrid = css(
  "display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:9px 12px;",
);
const filterFoot = css(
  "display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding-top:10px;",
);
const filterNote = css(
  "font-family:var(--font-mono);font-size:9.5px;color:var(--text-faint);letter-spacing:0.03em;",
);
const table = css(
  "width:100%;border-collapse:separate;border-spacing:0;",
);
const rowBase = css("cursor:pointer;");
const rowActive = css(
  "background:color-mix(in srgb,var(--accent) 12%,transparent);",
);
const runCell = css(
  "font-family:var(--font-mono);font-size:10.5px;color:var(--text-muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;",
);
const pagerBar = css(
  "display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 12px;border-top:1px solid var(--border);background:var(--surface-chrome);",
);
const pagerText = css(
  "font-family:var(--font-mono);font-size:10px;color:var(--text-muted);letter-spacing:0.04em;",
);
const sidePanel = css(
  `flex:0 0 ${SIDE_PANEL_WIDTH}px;max-width:${SIDE_PANEL_WIDTH}px;`,
);
const sideHead = css(
  "display:flex;align-items:center;justify-content:space-between;gap:8px;",
);
const sideKV = css(
  "display:flex;justify-content:space-between;gap:12px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);padding:4px 0;border-bottom:1px solid var(--border-faint);",
);
const sideKVKey = css(
  "color:var(--text-faint);text-transform:uppercase;letter-spacing:0.08em;font-size:9.5px;",
);
const modelList = css(
  "display:flex;flex-direction:column;gap:6px;margin-top:10px;",
);
const modelRow = css(
  "display:grid;grid-template-columns:1fr auto auto auto;gap:8px;align-items:center;font-family:var(--font-mono);font-size:10.5px;color:var(--text-primary);padding:5px 7px;border:1px solid var(--border-faint);border-radius:2px;",
);
const modelName = css(
  "overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
);
const modelMeta = css(
  "font-family:var(--font-mono);font-size:9.5px;color:var(--text-muted);white-space:nowrap;",
);
const closeBtn = css(
  "padding:3px 8px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);

interface ModuleDiscovery {
  modules: string[];
  taskTypesByModule: Record<string, string[]>;
}

function splitCommaOr(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function buildQuery(f: DetailFilters, offset: number): LlmLogQuery {
  const model = splitCommaOr(f.model);
  const status = splitCommaOr(f.status);
  return {
    limit: PAGE_LIMIT,
    offset,
    model: model.length ? model : undefined,
    task_type: f.taskType.length ? f.taskType : undefined,
    status: status.length ? status : undefined,
    user_id: f.userId || undefined,
    timestamp_since: f.since ? `${f.since}T00:00:00` : undefined,
    timestamp_until: f.until ? `${f.until}T23:59:59` : undefined,
    cost_usd_min: f.costMin || undefined,
    cost_usd_max: f.costMax || undefined,
  };
}

function truncRun(runId: string): string {
  if (runId.length <= 12) return runId;
  return `${runId.slice(0, 8)}\u2026${runId.slice(-4)}`;
}

export default function CostDetail(props: CostDetailProps): JSX.Element {
  const { filters, onFilters } = props;

  const [draft, setDraft] = useState<DetailFilters>(filters);
  const [offset, setOffset] = useState<number>(0);
  const [selectedRun, setSelectedRun] = useState<string | null>(null);
  const [moduleSel, setModuleSel] = useState<string>("");

  useEffect(() => {
    setDraft(filters);
    setOffset(0);
  }, [filters]);

  const disc = useLlmLog({ limit: 200 });
  const discovery = useMemo<ModuleDiscovery>(() => {
    const items = disc.data?.items ?? [];
    const byMod: Record<string, Set<string>> = {};
    for (const it of items) {
      const mod = moduleOf(it.task_type);
      if (!byMod[mod]) byMod[mod] = new Set();
      byMod[mod].add(it.task_type);
    }
    const modules = Object.keys(byMod).sort();
    const taskTypesByModule: Record<string, string[]> = {};
    for (const m of modules) {
      taskTypesByModule[m] = Array.from(byMod[m]).sort();
    }
    return { modules, taskTypesByModule };
  }, [disc.data]);

  const effective = useMemo(() => buildQuery(filters, offset), [filters, offset]);
  const log = useLlmLog(effective);
  const breakdown = useRunBreakdown(selectedRun);

  const total = log.data?.total ?? 0;
  const items: LlmLogEntry[] = log.data?.items ?? [];
  const totalCost = log.data?.total_cost_usd ?? 0;

  const canPrev = offset > 0;
  const canNext = offset + items.length < total;

  return (
    <div style={{ ...stack, flex: 1, minHeight: 0 }}>
      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span>filters</span>
        </div>
        <div style={pad}>
          <div style={filterGrid}>
            <label style={label}>
              <span>model</span>
              <input
                style={inputStyle}
                type="text"
                placeholder="claude-*, gpt-4o (comma OR)"
                value={draft.model}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, model: e.target.value })
                }
              />
            </label>
            <label style={label}>
              <span>task_type</span>
              <input
                style={inputStyle}
                type="text"
                placeholder="task_type list (comma OR)"
                value={draft.taskType.join(", ")}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, taskType: splitCommaOr(e.target.value) })
                }
              />
            </label>
            <label style={label}>
              <span>module</span>
              <select
                style={inputStyle}
                value={moduleSel}
                onChange={(e: ChangeEvent<HTMLSelectElement>) => {
                  const m = e.target.value;
                  setModuleSel(m);
                  if (m && discovery.taskTypesByModule[m]) {
                    setDraft({ ...draft, taskType: discovery.taskTypesByModule[m] });
                  }
                }}
              >
                <option value="">{"\u2014 module \u2014"}</option>
                {discovery.modules.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>
            <label style={label}>
              <span>user</span>
              <input
                style={inputStyle}
                type="text"
                placeholder="user_id"
                value={draft.userId}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, userId: e.target.value })
                }
              />
            </label>
            <label style={label}>
              <span>status</span>
              <input
                style={inputStyle}
                type="text"
                placeholder="ok, error (comma OR)"
                value={draft.status}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, status: e.target.value })
                }
              />
            </label>
            <label style={label}>
              <span>since</span>
              <input
                style={inputStyle}
                type="date"
                value={draft.since}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, since: e.target.value })
                }
              />
            </label>
            <label style={label}>
              <span>until</span>
              <input
                style={inputStyle}
                type="date"
                value={draft.until}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, until: e.target.value })
                }
              />
            </label>
            <label style={label}>
              <span>cost min ($)</span>
              <input
                style={inputStyle}
                type="number"
                step="0.0001"
                min="0"
                value={draft.costMin}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, costMin: e.target.value })
                }
              />
            </label>
            <label style={label}>
              <span>cost max ($)</span>
              <input
                style={inputStyle}
                type="number"
                step="0.0001"
                min="0"
                value={draft.costMax}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setDraft({ ...draft, costMax: e.target.value })
                }
              />
            </label>
          </div>
          <div style={filterFoot}>
            <button
              type="button"
              style={btnPrimary}
              onClick={() => onFilters(draft)}
            >
              apply
            </button>
            <button
              type="button"
              style={btnGhost}
              onClick={() => {
                setModuleSel("");
                onFilters(EMPTY_DETAIL_FILTERS);
              }}
            >
              reset
            </button>
            <span style={chipFaint}>
              module options: top of {fmtInt(disc.data?.items.length ?? 0)} recent calls
            </span>
            <span style={filterNote}>
              module list derived from recent activity (200-row window).
            </span>
          </div>
        </div>
      </div>

      <div style={rootRow}>
        <div style={{ ...panelBox, flex: 1, minWidth: 0 }}>
          <div style={panelTitle}>
            <span style={dot} />
            <span>interaction log</span>
          </div>
          {log.isLoading ? (
            <div style={emptyNote}>loading interaction log{"\u2026"}</div>
          ) : log.isError ? (
            <div style={{ ...emptyNote, ...warnText }}>
              {apiErrMessage(log.error)}
            </div>
          ) : items.length === 0 ? (
            <div style={emptyNote}>no LLM calls match these filters</div>
          ) : (
            <>
              <div style={scroll}>
                <table style={table}>
                  <thead>
                    <tr>
                      <th style={th}>when</th>
                      <th style={th}>model</th>
                      <th style={th}>task_type</th>
                      <th style={th}>cost</th>
                      <th style={th}>status</th>
                      <th style={th}>user</th>
                      <th style={th}>run</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((row) => {
                      const active = selectedRun === row.run_id;
                      const trStyle = active
                        ? { ...rowBase, ...rowActive }
                        : rowBase;
                      return (
                        <tr
                          key={row.id}
                          role="button"
                          tabIndex={0}
                          aria-pressed={active}
                          style={trStyle}
                          onClick={() => setSelectedRun(row.run_id)}
                          onKeyDown={(e: KeyboardEvent<HTMLTableRowElement>) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              setSelectedRun(row.run_id);
                            }
                          }}
                        >
                          <td style={td}>
                            {new Date(row.timestamp).toLocaleString()}
                          </td>
                          <td style={td}>{row.model}</td>
                          <td style={td}>{row.task_type}</td>
                          <td style={td}>{fmtUsd(row.cost_usd)}</td>
                          <td style={td}>{row.status}</td>
                          <td style={td}>{row.user_id ?? "\u2014"}</td>
                          <td style={{ ...td, ...runCell }}>
                            {truncRun(row.run_id)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div style={pagerBar}>
                <span style={pagerText}>
                  showing {offset + 1}
                  {"\u2013"}
                  {offset + items.length} of {fmtInt(total)} {"\u00b7"}{" "}
                  {fmtUsd(totalCost)}
                </span>
                <span style={{ display: "flex", gap: 8 }}>
                  <button
                    type="button"
                    style={btnGhost}
                    disabled={!canPrev}
                    onClick={() => setOffset(Math.max(0, offset - PAGE_LIMIT))}
                  >
                    prev
                  </button>
                  <button
                    type="button"
                    style={btnGhost}
                    disabled={!canNext}
                    onClick={() => setOffset(offset + PAGE_LIMIT)}
                  >
                    next
                  </button>
                </span>
              </div>
            </>
          )}
        </div>

        {selectedRun && (
          <div style={{ ...panelBox, ...sidePanel }}>
            <div style={panelTitle}>
              <span style={dot} />
              <span style={{ ...sideHead, flex: 1 }}>
                <span>
                  run {truncRun(selectedRun)}
                </span>
                <button
                  type="button"
                  style={closeBtn}
                  onClick={() => setSelectedRun(null)}
                  aria-label="close"
                >
                  close
                </button>
              </span>
            </div>
            {breakdown.isLoading ? (
              <div style={emptyNote}>loading run breakdown{"\u2026"}</div>
            ) : breakdown.isError ? (
              <div style={{ ...emptyNote, ...warnText }}>
                {apiErrMessage(breakdown.error)}
              </div>
            ) : !breakdown.data ? (
              <div style={emptyNote}>no breakdown for this run</div>
            ) : (
              <div style={{ ...scroll, ...pad }}>
                <div style={sideKV}>
                  <span style={sideKVKey}>total cost</span>
                  <span>{fmtUsd(breakdown.data.total_cost_usd)}</span>
                </div>
                <div style={sideKV}>
                  <span style={sideKVKey}>total tokens</span>
                  <span>{fmtInt(breakdown.data.total_tokens)}</span>
                </div>
                <div style={sideKV}>
                  <span style={sideKVKey}>cache hit rate</span>
                  <span>
                    {(breakdown.data.cache_hit_rate * 100).toFixed(1)}%
                  </span>
                </div>
                <div style={sideKV}>
                  <span style={sideKVKey}>cache read tokens</span>
                  <span>{fmtInt(breakdown.data.cache_read_tokens)}</span>
                </div>
                <div style={sideKV}>
                  <span style={sideKVKey}>cache write tokens</span>
                  <span>{fmtInt(breakdown.data.cache_write_tokens)}</span>
                </div>
                {breakdown.data.models.length === 0 ? (
                  <div style={{ ...emptyNote, padding: "16px 4px" }}>
                    no per-model rows for this run
                  </div>
                ) : (
                  <div style={modelList}>
                    {breakdown.data.models.map((m) => (
                      <div key={m.model_id} style={modelRow}>
                        <span style={modelName} title={m.model_id}>
                          {m.model_id}
                        </span>
                        <span style={modelMeta}>{fmtUsd(m.cost_usd)}</span>
                        <span style={modelMeta}>
                          {fmtInt(m.call_count)} call{m.call_count === 1 ? "" : "s"}
                        </span>
                        <span style={modelMeta}>
                          {fmtInt(m.total_tokens)} tok
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
