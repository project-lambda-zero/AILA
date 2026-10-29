/** Automation action detail body (the "schedule this action" affordance in
 * the /automation/actions catalog detail panel). */

import type { JSX } from "react";

import { css } from "../../css";

export function AutomationActionDetail({
  row,
  onSchedule,
}: {
  row: Record<string, unknown>;
  onSchedule: (actionId: string) => void;
}): JSX.Element {
  const actionId = String(row["action_id"] ?? "");
  const moduleId = String(row["module_id"] ?? "");
  const description = String(row["description"] ?? "");
  const schema = row["param_schema"];
  const declaresArgs = schema && typeof schema === "object";
  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <button
        type="button"
        onClick={() => onSchedule(actionId)}
        disabled={actionId === ""}
        style={css(
          `align-self:flex-start;padding:0 14px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:${
            actionId === "" ? "not-allowed" : "pointer"
          };`,
        )}
      >
        {"schedule this action \u25b8"}
      </button>
      <div style={css("display:grid;grid-template-columns:120px 1fr;gap:5px 12px;font-size:11.5px;")}>
        <span style={css("color:var(--text-faint);")}>action</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{actionId}</span>
        <span style={css("color:var(--text-faint);")}>module</span>
        <span style={css("color:var(--text-primary);")}>{moduleId}</span>
        <span style={css("color:var(--text-faint);")}>description</span>
        <span style={css("color:var(--text-primary);word-break:break-word;")}>{description}</span>
        <span style={css("color:var(--text-faint);")}>arguments</span>
        <span style={css("color:var(--text-primary);")}>
          {declaresArgs ? "typed schema declared -- wizard will render a typed form" : "none declared -- wizard falls back to a keyval editor"}
        </span>
      </div>
    </div>
  );
}
