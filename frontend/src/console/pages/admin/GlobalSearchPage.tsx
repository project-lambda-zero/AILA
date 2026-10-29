/** Global search console over GET /search: query systems, sessions, and
 * module findings in one box, group the results by entity type, and hand each
 * group off to the existing window for that entity (systems registry,
 * sessions list, module findings page). */
import { useState } from "react";
import type { JSX } from "react";

import { useGlobalSearch } from "../../../api/admin";
import type { SearchResult } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { ActButton, actionRow, fieldStyle, formLabel } from "../xray/actions";
import { AdminWindow, FAINT, MONO, QueryState, Section, SubmitButton } from "./kit";

/** Entity types the backend emits today (search.py): system rows, session
 * rows, and per-module findings. Anything unrecognized renders without a
 * link rather than guessing a window. */
const TYPE_LABELS = {
  system: "systems",
  session: "sessions",
  finding: "findings",
} as const satisfies Record<string, string>;

type KnownType = keyof typeof TYPE_LABELS;

function isKnownType(t: string): t is KnownType {
  return t in TYPE_LABELS;
}

export default function GlobalSearchPage(props: ModulePageProps): JSX.Element {
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const search = useGlobalSearch(q, []);

  const openResult = (r: SearchResult): void => {
    if (!props.onOpenPage) return;
    if (r.entity_type === "system") props.onOpenPage("admin", "systems", "systems");
    else if (r.entity_type === "session") props.onOpenPage("admin", "sessions", "sessions");
    else if (r.entity_type === "finding" && r.module_id) props.onOpenPage(r.module_id, "findings", `${r.module_id} findings`);
  };

  const results = search.data?.results ?? [];
  const grouped = new Map<string, SearchResult[]>();
  for (const r of results) {
    const list = grouped.get(r.entity_type) ?? [];
    list.push(r);
    grouped.set(r.entity_type, list);
  }

  return (
    <AdminWindow page={props}>
      <form
        style={actionRow}
        onSubmit={(e) => {
          e.preventDefault();
          setQ(draft.trim());
        }}
      >
        <span style={formLabel}>query</span>
        <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="search systems, sessions, findings" maxLength={200} style={{ ...fieldStyle, width: 380 }} />
        <SubmitButton label="search" disabled={draft.trim() === ""} pending={search.isFetching} />
      </form>

      {q === "" ? (
        <div style={css(FAINT + "font-size:11px;")}>Search across platform entities. Results group by type; click a result to open its window.</div>
      ) : (
        <>
          <QueryState loading={search.isLoading} error={search.error} empty={results.length === 0} emptyText={`no results for "${q}"`} />
          {search.data ? (
            <span style={css(FAINT + MONO + "font-size:11px;")}>
              {search.data.total} result{search.data.total === 1 ? "" : "s"}
            </span>
          ) : null}
          {[...grouped.entries()].map(([type, rows]) => (
            <Section key={type} title={`${isKnownType(type) ? TYPE_LABELS[type] : type} (${rows.length})`}>
              <div style={css("display:flex;flex-direction:column;gap:2px;")}>
                {rows.map((r) => (
                  <button
                    key={`${r.entity_type}:${r.entity_id}`}
                    type="button"
                    onClick={() => openResult(r)}
                    style={css(
                      `display:flex;align-items:baseline;gap:10px;width:100%;text-align:left;border:0;border-bottom:1px solid var(--border-soft);background:transparent;padding:6px 4px;cursor:${isKnownType(r.entity_type) ? "pointer" : "default"};min-width:0;`,
                    )}
                  >
                    <span style={css(MONO + "font-size:11px;color:var(--text-primary);flex:0 0 auto;")}>{r.title || r.entity_id}</span>
                    {r.snippet ? <span style={css("font-size:11px;color:var(--text-muted);min-width:0;word-break:break-word;")}>{r.snippet}</span> : null}
                    <span style={css("flex:1;")} />
                    {r.module_id ? <span style={css(FAINT + MONO + "font-size:11px;flex:0 0 auto;")}>{r.module_id}</span> : null}
                  </button>
                ))}
              </div>
            </Section>
          ))}
          <div style={actionRow}>
            <span style={css(FAINT + "font-size:11px;")}>First 100 results shown; narrow the query for more precision.</span>
          </div>
        </>
      )}
    </AdminWindow>
  );
}
