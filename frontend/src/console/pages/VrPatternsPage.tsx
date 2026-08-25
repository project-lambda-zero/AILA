import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { ChangeEvent, FormEvent, JSX } from "react";

import { apiFetch } from "../../api/client";
import { fetchFieldOptions } from "../../api/mutations";
import type { FieldOption } from "../../api/mutations";
import { asRecord } from "../../api/parse";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { StatusBadge } from "./badges";
import { PAGE_CONFIGS } from "./configs";
import DataPage from "./DataPage";

const CTL =
  "padding:4px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;";
const LABEL = "font-size:10px;letter-spacing:0.04em;color:var(--text-faint);text-transform:uppercase;";

/** One `/vr/patterns/applicable` result: the pattern plus its retrieval score
 * and the signals that matched it. */
interface Ranked {
  pattern: Record<string, unknown>;
  score: number;
  matched_by: string[];
}

function toRanked(raw: unknown): Ranked[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((r) => {
    const rec = asRecord(r) ?? {};
    return {
      pattern: asRecord(rec["pattern"]) ?? {},
      score: typeof rec["score"] === "number" ? (rec["score"] as number) : 0,
      matched_by: Array.isArray(rec["matched_by"]) ? (rec["matched_by"] as unknown[]).map((m) => String(m)) : [],
    };
  });
}

/** Modal tool over `GET /vr/patterns/applicable`: the operator picks a
 * workspace + free-text question (plus optional target_kind / primary_language
 * / k) and sees the ranked patterns the retrieval gate would surface to an
 * agent. Read-only -- it never mutates a pattern. */
function ApplicablePreview({ onClose }: { onClose: () => void }): JSX.Element {
  const wsQ = useQuery<FieldOption[]>({
    queryKey: ["vr-workspaces-options"],
    queryFn: () => fetchFieldOptions({ endpoint: "/vr/workspaces", valueField: "id", labelField: "name" }),
    retry: false,
    refetchOnWindowFocus: false,
  });
  const workspaces = wsQ.data ?? [];

  const [workspaceId, setWorkspaceId] = useState("");
  const [query, setQuery] = useState("");
  const [targetKind, setTargetKind] = useState("");
  const [primaryLanguage, setPrimaryLanguage] = useState("");
  const [k, setK] = useState("5");
  const [results, setResults] = useState<Ranked[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canRun = workspaceId !== "" && query.trim() !== "" && !running;

  const run = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    if (!canRun) return;
    setRunning(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("workspace_id", workspaceId);
      params.set("query", query.trim());
      if (targetKind.trim() !== "") params.set("target_kind", targetKind.trim());
      if (primaryLanguage.trim() !== "") params.set("primary_language", primaryLanguage.trim());
      params.set("k", k.trim() === "" ? "5" : k.trim());
      const raw = await apiFetch<unknown>(`/vr/patterns/applicable?${params.toString()}`);
      setResults(toRanked(raw));
    } catch (err) {
      setError(err instanceof Error ? err.message : "request failed");
      setResults(null);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="applicable patterns preview"
      onClick={onClose}
      style={css("position:fixed;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:32px;z-index:60;")}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={css("background:var(--surface-page);border:1px solid var(--border-soft);border-radius:3px;width:min(720px,94vw);max-height:85vh;display:flex;flex-direction:column;overflow:hidden;")}
      >
        <div style={css("display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--border-soft);")}>
          <span style={css("font-family:var(--font-display);font-size:13px;color:var(--text-primary);letter-spacing:0.02em;")}>
            applicable patterns preview
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="close"
            style={css("border:0;background:transparent;color:var(--text-muted);font-size:14px;cursor:pointer;")}
          >
            {"\u2715"}
          </button>
        </div>

        <form onSubmit={run} style={css("display:flex;flex-direction:column;gap:8px;padding:12px 14px;border-bottom:1px solid var(--border-soft);")}>
          <p style={css("margin:0;font-size:10.5px;color:var(--text-muted);line-height:1.5;")}>
            simulate the retrieval gate an agent hits: only active patterns in the workspace/team/global scope chain are ranked and returned.
          </p>
          <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:8px;")}>
            <label style={css("display:flex;flex-direction:column;gap:3px;")}>
              <span style={css(LABEL)}>workspace *</span>
              <select
                value={workspaceId}
                onChange={(e: ChangeEvent<HTMLSelectElement>) => setWorkspaceId(e.target.value)}
                style={css(CTL + "cursor:pointer;")}
              >
                <option value="">{wsQ.isLoading ? "loading\u2026" : "select a workspace"}</option>
                {workspaces.map((w) => (
                  <option key={w.value} value={w.value}>{w.label}</option>
                ))}
              </select>
            </label>
            <label style={css("display:flex;flex-direction:column;gap:3px;")}>
              <span style={css(LABEL)}>results (k)</span>
              <input
                type="number"
                min={1}
                max={20}
                value={k}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setK(e.target.value)}
                style={css(CTL)}
              />
            </label>
          </div>
          <label style={css("display:flex;flex-direction:column;gap:3px;")}>
            <span style={css(LABEL)}>question *</span>
            <input
              type="text"
              value={query}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
              placeholder="e.g. how do I fuzz a wasm parser for OOB reads"
              style={css(CTL)}
            />
          </label>
          <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:8px;")}>
            <label style={css("display:flex;flex-direction:column;gap:3px;")}>
              <span style={css(LABEL)}>target kind</span>
              <input
                type="text"
                value={targetKind}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setTargetKind(e.target.value)}
                placeholder="optional"
                style={css(CTL)}
              />
            </label>
            <label style={css("display:flex;flex-direction:column;gap:3px;")}>
              <span style={css(LABEL)}>primary language</span>
              <input
                type="text"
                value={primaryLanguage}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setPrimaryLanguage(e.target.value)}
                placeholder="optional"
                style={css(CTL)}
              />
            </label>
          </div>
          <div style={css("display:flex;justify-content:flex-end;")}>
            <button
              type="submit"
              disabled={!canRun}
              style={css(`padding:4px 12px;border:1px solid var(--accent)66;border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:${canRun ? "pointer" : "not-allowed"};opacity:${canRun ? 1 : 0.5};`)}
            >
              {running ? "running\u2026" : "preview"}
            </button>
          </div>
        </form>

        <div style={css("flex:1;min-height:0;overflow:auto;padding:12px 14px;display:flex;flex-direction:column;gap:8px;")}>
          {error ? (
            <div style={css("font-family:var(--font-mono);font-size:11px;color:#ffb85f;")}>failed: {error}</div>
          ) : null}
          {results === null ? (
            <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>
              choose a workspace and question, then run a preview.
            </div>
          ) : results.length === 0 ? (
            <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>
              no applicable patterns for this query.
            </div>
          ) : (
            <>
              <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
                {results.length} ranked
              </div>
              {results.map((r, i) => {
                const p = r.pattern;
                const id = String(p["id"] ?? i);
                return (
                  <div key={id} style={css("border:1px solid var(--border-soft);border-radius:2px;padding:8px 10px;display:flex;flex-direction:column;gap:4px;")}>
                    <div style={css("display:flex;align-items:center;justify-content:space-between;gap:8px;")}>
                      <span style={css("font-size:11.5px;color:var(--text-primary);line-height:1.4;")}>{String(p["summary"] ?? "\u2014")}</span>
                      <span style={css("font-family:var(--font-mono);font-variant-numeric:tabular-nums;font-size:11px;color:var(--accent);")}>{r.score.toFixed(3)}</span>
                    </div>
                    <div style={css("display:flex;align-items:center;gap:6px;flex-wrap:wrap;")}>
                      <StatusBadge value={String(p["kind"] ?? "\u2014").replace(/_/g, " ")} tone="muted" />
                      <StatusBadge value={String(p["status"] ?? "\u2014")} tone={String(p["status"] ?? "") === "active" ? "ok" : "muted"} />
                      <StatusBadge value={String(p["scope"] ?? "\u2014")} tone="muted" />
                      {r.matched_by.length > 0 ? (
                        <span style={css("font-size:10px;color:var(--text-faint);font-family:var(--font-mono);")}>
                          matched by {r.matched_by.join(", ")}
                        </span>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/** Bespoke wrapper for the VR patterns page: the declarative DataPage (list +
 * detail + edit + delete + promote/archive actions + kind/status/scope
 * filters) plus a "preview applicable" toolbar control that opens the
 * retrieval-simulation overlay. */
export default function VrPatternsPage(p: ModulePageProps): JSX.Element {
  const [previewOpen, setPreviewOpen] = useState(false);
  return (
    <>
      <DataPage
        config={PAGE_CONFIGS["vr:patterns"]}
        configKey="vr:patterns"
        {...p}
        toolbarExtra={
          <button
            type="button"
            onClick={() => setPreviewOpen(true)}
            style={css("padding:4px 10px;border:1px solid var(--accent)66;border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
          >
            preview applicable
          </button>
        }
      />
      {previewOpen ? <ApplicablePreview onClose={() => setPreviewOpen(false)} /> : null}
    </>
  );
}
