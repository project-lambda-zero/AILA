/**
 * Floating viewer for one LLM interaction log row.
 *
 * The list endpoint (/admin/llm-log) ships opaque previews plus row-level
 * cost/latency. The full transcript lives behind /admin/llm-log/{id}/content,
 * which resolves in three steps:
 *   1. Paired audit seal for the (run_id, model_id) pair -> `audit_seal`,
 *      returns the full prompt + response bodies.
 *   2. Row previews when the seal path is unavailable -> `preview`, both
 *      strings capped by the backend's _make_preview ceiling.
 *   3. No stored body of either shape -> `missing`.
 *
 * When source != "audit_seal" the backend also returns `config_flag`, the
 * ConfigRegistry key an operator flips to make future rows carry the full
 * body. The banner names that flag verbatim so the fix is a copy-paste.
 */
import type { JSX, ReactNode } from "react";

import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { css } from "../css";
import { LlmChatTranscript } from "./LlmLogEntry";

/** Response shape of GET /admin/llm-log/{id}/content (envelope unwrapped by
 * apiFetch). Fields mirror the backend LLMLogContent contract 1:1. */
export interface LlmLogContent {
  prompt_content: string | null;
  response_content: string | null;
  source: "audit_seal" | "preview" | "missing";
  task_type: string;
  config_flag: string | null;
}

/** react-query hook for one row's stored bodies. Cached per id for 30s so
 * fullscreen/minimize toggles don't re-request. */
export function useLlmLogContent(id: string | null) {
  return useQuery({
    queryKey: ["admin-llm-log-content", id ?? ""],
    queryFn: () => apiFetch<LlmLogContent>(`/admin/llm-log/${encodeURIComponent(id ?? "")}/content`),
    enabled: Boolean(id),
    staleTime: 30_000,
    retry: false,
  });
}

/** Read a scalar field from a row without leaking `unknown` into JSX. */
function scalar(row: Record<string, unknown>, key: string): string {
  const v = row[key];
  if (v === null || v === undefined) return "\u2014";
  if (typeof v === "string") return v === "" ? "\u2014" : v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "\u2014";
}

function num(row: Record<string, unknown>, key: string): number | null {
  const v = row[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Format a USD cost with enough precision to read individual model calls
 * (which fall well under a cent) without a trailing string of zeros. */
function formatCost(n: number | null): string {
  if (n === null) return "\u2014";
  if (n === 0) return "$0";
  if (Math.abs(n) < 0.01) return `$${n.toFixed(6)}`;
  return `$${n.toFixed(4)}`;
}

function formatMs(n: number | null): string {
  if (n === null) return "\u2014";
  if (n >= 1000) return `${(n / 1000).toFixed(2)}s`;
  return `${Math.round(n)}ms`;
}

/** One chip in the row-summary strip. Label + value in the same monospace
 * cadence as the DataPage detail grid. */
function Chip({ label, value }: { label: string; value: ReactNode }): JSX.Element {
  return (
    <span style={chipWrap}>
      <span style={chipLabel}>{label}</span>
      <span style={chipValue}>{value}</span>
    </span>
  );
}

/** Banner shown when the returned bodies come from row previews or from
 * neither source. Names the exact ConfigRegistry flag operators flip to
 * make the seal store full bodies for this task_type next time. */
function SourceBanner({ source, taskType, configFlag }: { source: LlmLogContent["source"]; taskType: string; configFlag: string | null }): JSX.Element | null {
  if (source === "audit_seal") return null;
  const flag = configFlag ?? `llm_seal_store_content_${taskType || "<task_type>"}`;
  const message =
    source === "missing"
      ? `no stored body or preview exists for this call; enable \`${flag}=true\` in config so future calls of task_type "${taskType || "?"}" persist the full transcript`
      : `stored full bodies are disabled for task_type "${taskType || "?"}"; enable \`${flag}=true\` in config to see the full transcript. showing the row preview instead.`;
  return <div style={source === "missing" ? bannerMissing : bannerPreview}>{message}</div>;
}

/** Two-pane viewer. The row summary sits above; the panes below stack on
 * narrow widths (container query on the outer wrap) and split 50/50
 * otherwise. `LlmChatTranscript` picks the chat-bubble shape when the body
 * parses as a role/content array and falls back to a mono block otherwise,
 * so structured-output responses still read honestly. */
export function LlmLogViewer({ row }: { row: Record<string, unknown> }): JSX.Element {
  const rec = row;
  const idRaw = rec["id"];
  const id = typeof idRaw === "string" || typeof idRaw === "number" ? String(idRaw) : null;
  const q = useLlmLogContent(id);

  const chips: ReactNode = (
    <div style={chipStrip}>
      <Chip label="model" value={scalar(rec, "model")} />
      <Chip label="persona" value={scalar(rec, "task_type")} />
      <Chip label="in" value={num(rec, "input_tokens")?.toLocaleString() ?? "\u2014"} />
      <Chip label="out" value={num(rec, "output_tokens")?.toLocaleString() ?? "\u2014"} />
      <Chip label="cost" value={formatCost(num(rec, "cost_usd"))} />
      <Chip label="latency" value={formatMs(num(rec, "duration_ms"))} />
      <Chip label="status" value={scalar(rec, "status")} />
    </div>
  );

  let paneBody: ReactNode;
  if (!id) {
    paneBody = <div style={emptyNote}>this row has no id; cannot fetch stored content.</div>;
  } else if (q.isLoading) {
    paneBody = <div style={emptyNote}>loading{"\u2026"}</div>;
  } else if (q.isError) {
    paneBody = (
      <div style={emptyNote}>
        could not load /admin/llm-log/{id}/content{q.error instanceof Error ? ` \u2014 ${q.error.message}` : ""}
      </div>
    );
  } else {
    const data: LlmLogContent | undefined = q.data;
    if (!data) {
      paneBody = <div style={emptyNote}>empty response.</div>;
    } else {
      paneBody = (
        <div style={paneStackWrap}>
          <SourceBanner source={data.source} taskType={data.task_type} configFlag={data.config_flag} />
          <div style={paneSplit}>
            <section style={pane}>
              <header style={paneHeader}>prompt</header>
              <div style={paneBodyBox}>
                <LlmChatTranscript value={data.prompt_content} />
              </div>
            </section>
            <section style={pane}>
              <header style={paneHeader}>response</header>
              <div style={paneBodyBox}>
                <LlmChatTranscript value={data.response_content} />
              </div>
            </section>
          </div>
        </div>
      );
    }
  }

  return (
    <div style={wrap}>
      {chips}
      <div style={scrollArea}>{paneBody}</div>
    </div>
  );
}

const wrap = css("flex:1;min-height:0;display:flex;flex-direction:column;background:var(--surface-page);");
const chipStrip = css(
  "flex:0 0 auto;display:flex;flex-wrap:wrap;gap:6px 12px;padding:10px 14px;border-bottom:1px solid var(--border);background:var(--surface-chrome);",
);
const chipWrap = css("display:inline-flex;align-items:baseline;gap:5px;min-width:0;");
const chipLabel = css(
  "font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);",
);
const chipValue = css(
  "font-family:var(--font-mono);font-size:11px;color:var(--text-primary);font-variant-numeric:tabular-nums;",
);
const scrollArea = css("flex:1;min-height:0;overflow:auto;padding:12px 14px;");
const emptyNote = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const paneStackWrap = css("display:flex;flex-direction:column;gap:10px;min-height:0;");
// Two panes side by side above ~720px, stacked below. `flex-wrap` on the
// row gives the responsive stack without a media query: min-width:280px
// forces a break when the container can't fit both at that width.
const paneSplit = css(
  "display:flex;flex-wrap:wrap;gap:10px;min-height:0;align-items:stretch;",
);
const pane = css(
  "flex:1 1 320px;min-width:280px;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;",
);
const paneHeader = css(
  "flex:0 0 auto;display:flex;align-items:center;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const paneBodyBox = css("flex:1;min-height:0;overflow:auto;padding:10px 12px;");
const bannerPreview = css(
  "border:1px solid #ffb85f;border-radius:2px;padding:8px 10px;background:color-mix(in srgb,#ffb85f 12%,transparent);color:#ffb85f;font-family:var(--font-mono);font-size:10.5px;line-height:1.5;letter-spacing:0.02em;",
);
const bannerMissing = css(
  "border:1px solid var(--border);border-radius:2px;padding:8px 10px;background:var(--surface-sunk);color:var(--text-muted);font-family:var(--font-mono);font-size:10.5px;line-height:1.5;letter-spacing:0.02em;",
);

export default LlmLogViewer;
