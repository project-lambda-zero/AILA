/** Step 1 for the automation wizard: the live action registry catalog,
 * grouped by owning module. */

import { useMemo } from "react";
import type { JSX } from "react";

import type { AutomationActionInfo } from "../../../api/automation";
import { css } from "../../css";
import { helpText } from "../../wizards";

const sectionLabel = css(
  "font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);",
);

export function ActionCatalog({
  actions,
  loading,
  selectedId,
  onPick,
}: {
  actions: AutomationActionInfo[];
  loading: boolean;
  selectedId: string;
  onPick: (id: string) => void;
}): JSX.Element {
  const grouped = useMemo(() => {
    const buckets: Record<string, AutomationActionInfo[]> = {};
    for (const a of actions) {
      const key = a.module_id || "platform";
      if (!buckets[key]) buckets[key] = [];
      buckets[key].push(a);
    }
    return Object.entries(buckets).sort(([a], [b]) => a.localeCompare(b));
  }, [actions]);

  if (loading) {
    return <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading action catalog\u2026"}</span>;
  }
  if (actions.length === 0) {
    return (
      <span style={css("font-size:11px;color:var(--status-warn);")}>
        {"no actions registered -- nothing to schedule"}
      </span>
    );
  }
  return (
    <div style={css("display:flex;flex-direction:column;gap:16px;")}>
      <p style={helpText}>
        {
          "an action is a platform-registered operation a module exposes for scheduling. the catalog below reflects the live AutomationRegistry; pick one to bind it to a target and a cron."
        }
      </p>
      {grouped.map(([module, rows]) => (
        <div key={module} style={css("display:flex;flex-direction:column;gap:8px;")}>
          <span style={sectionLabel}>{`module \u00b7 ${module}`}</span>
          <div style={css("display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;")}>
            {rows.map((a) => {
              const active = a.action_id === selectedId;
              const border = active ? "var(--accent)" : "var(--border-soft)";
              const bg = active
                ? "color-mix(in srgb,var(--accent) 10%,transparent)"
                : "var(--surface-sunk)";
              return (
                <button
                  key={a.action_id}
                  type="button"
                  onClick={() => onPick(a.action_id)}
                  style={css(
                    `text-align:left;padding:10px 12px;border:1px solid ${border};background:${bg};border-radius:3px;cursor:pointer;display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono);`,
                  )}
                >
                  <span style={css("font-size:11.5px;color:var(--text-primary);letter-spacing:0.04em;")}>
                    {a.action_id}
                  </span>
                  <span style={css("font-size:11px;color:var(--text-muted);letter-spacing:0.02em;line-height:1.45;")}>
                    {a.description}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
