/** Global search console over GET /search: query systems, sessions, module
 * findings, malware targets, and VR investigations in one box, group the
 * results by entity type, and open each result in the existing window for that
 * record (systems registry, sessions list, findings page, malware target
 * detail, VR x-ray). */
import { useState } from "react";
import type { JSX } from "react";

import { useGlobalSearch } from "../../../api/admin";
import type { SearchResult } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { actionRow, fieldStyle, formLabel } from "../xray/actions";
import { AdminWindow, FAINT, MONO, QueryState, Section, SubmitButton } from "./kit";

/** Entity types the backend emits (search.py): system rows, session rows,
 * per-module findings, malware targets (module_id `malware`), and VR
 * investigations (module_id `vr`). Anything unrecognized renders without a
 * link rather than guessing a window. */
const TYPE_LABELS = {
  system: "systems",
  session: "sessions",
  finding: "findings",
  target: "targets",
  investigation: "investigations",
} as const satisfies Record<string, string>;

type KnownType = keyof typeof TYPE_LABELS;

function isKnownType(t: string): t is KnownType {
  return t in TYPE_LABELS;
}

/** Window a search hit opens: the registered page, its window label, and the
 * record id the window is bound to (null when the page is not record-bound). */
interface OpenRoute {
  moduleKey: string;
  section: string;
  label: string;
  investigationId: string | null;
}

/** Existing window for a hit, or null when the hit has no owning window.
 * Module-owned hits open only when their `module_id` names the owning module,
 * so a hit without `module_id` renders without a link. */
function routeFor(r: SearchResult): OpenRoute | null {
  if (r.entity_type === "system") return { moduleKey: "admin", section: "systems", label: "systems", investigationId: null };
  if (r.entity_type === "session") return { moduleKey: "admin", section: "sessions", label: "sessions", investigationId: null };
  if (r.entity_type === "finding" && r.module_id) return { moduleKey: r.module_id, section: "findings", label: `${r.module_id} findings`, investigationId: null };
  if (r.entity_type === "target" && r.module_id === "malware") return { moduleKey: "malware", section: "targets", label: r.title || r.entity_id, investigationId: r.entity_id };
  if (r.entity_type === "investigation" && r.module_id === "vr") return { moduleKey: "vr", section: "xray", label: "x-ray", investigationId: r.entity_id };
  return null;
}

export default function GlobalSearchPage(props: ModulePageProps): JSX.Element {
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const search = useGlobalSearch(q, []);

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
                {rows.map((r) => {
                  const route = routeFor(r);
                  return (
                    <button
                      key={`${r.entity_type}:${r.entity_id}`}
                      type="button"
                      disabled={route === null}
                      onClick={() => {
                        if (route) props.onOpenPage?.(route.moduleKey, route.section, route.label, route.investigationId);
                      }}
                      style={css(
                        `display:flex;align-items:baseline;gap:10px;width:100%;text-align:left;border:0;border-bottom:1px solid var(--border-soft);background:transparent;padding:6px 4px;cursor:${route ? "pointer" : "default"};min-width:0;`,
                      )}
                    >
                      <span style={css(MONO + "font-size:11px;color:var(--text-primary);flex:0 0 auto;")}>{r.title || r.entity_id}</span>
                      {r.snippet ? <span style={css("font-size:11px;color:var(--text-muted);min-width:0;word-break:break-word;")}>{r.snippet}</span> : null}
                      <span style={css("flex:1;")} />
                      {r.module_id ? <span style={css(FAINT + MONO + "font-size:11px;flex:0 0 auto;")}>{r.module_id}</span> : null}
                    </button>
                  );
                })}
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
