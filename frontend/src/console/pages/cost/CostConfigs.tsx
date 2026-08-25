/**
 * Cost page -- configs segment (req 47).
 *
 * Inline editors for the cost-family ConfigRegistry keys. Rows are grouped
 * into four families (budget ceilings, per-model pricing, per-task token cap,
 * estimate fallback). Env-overridden rows are read-only with a chip pointing
 * at the env key that owns the live value.
 */
import { useMemo, useState } from "react";
import type { ChangeEvent, CSSProperties, JSX } from "react";

import { useCostConfig, useUpdateCostConfig } from "../../../api/cost";
import type { CostConfigRow } from "../../../api/cost";
import {
  apiErrMessage,
  btnPrimary,
  btnPrimaryDisabled,
  chipFaint,
  chipOk,
  chipWarn,
  dot,
  emptyNote,
  inputDisabled,
  inputStyle,
  okText,
  pad,
  panelBox,
  panelTitle,
  prose,
  scroll,
  stack,
  warnText,
} from "./kit";

/* ------------------------------ family spec ------------------------------ */

interface FamilySpec {
  id: string;
  title: string;
  blurb: string;
  match: (key: string) => boolean;
}

const FAMILIES: FamilySpec[] = [
  {
    id: "budget",
    title: "budget ceilings",
    blurb:
      "Per-team monthly LLM spend ceiling (USD). The budget-alert path reads the same value.",
    match: (k) => k.startsWith("llm_monthly_budget_usd_"),
  },
  {
    id: "pricing",
    title: "per-model pricing",
    blurb:
      "Cost per 1K prompt / completion tokens for each model.",
    match: (k) =>
      k.startsWith("llm_cost_per_1k_prompt_") ||
      k.startsWith("llm_cost_per_1k_completion_"),
  },
  {
    id: "tokencap",
    title: "per-task token cap",
    blurb:
      "Max total tokens allowed per task type; the _default key is the fallback cap.",
    match: (k) => k.startsWith("llm_budget_max_total_tokens_"),
  },
  {
    id: "fallback",
    title: "estimate fallback",
    blurb:
      "Token count + price per 1K used for a pre-scan estimate when a team has no history.",
    match: (k) => k.startsWith("llm_cost_estimate_fallback_"),
  },
];

/* -------------------------------- styles --------------------------------- */

const familyHeader: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 4,
  paddingBottom: 6,
  borderBottom: "1px solid var(--border-faint)",
};
const familyTitle: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 10.5,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-primary)",
};
const familyBlurb: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 10.5,
  color: "var(--text-muted)",
  lineHeight: 1.5,
};
const rowGrid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(240px,1.4fr) minmax(160px,1fr) auto auto",
  gap: 10,
  alignItems: "center",
  padding: "8px 0",
  borderBottom: "1px solid var(--border-faint)",
};
const rowKey: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  color: "var(--text-primary)",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
const rowChips: CSSProperties = {
  display: "flex",
  gap: 6,
  alignItems: "center",
  flexWrap: "wrap",
};
const rowStatus: CSSProperties = {
  gridColumn: "1 / -1",
  paddingTop: 4,
};
const rowEnvNote: CSSProperties = {
  gridColumn: "1 / -1",
  paddingTop: 4,
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  color: "var(--text-faint)",
  lineHeight: 1.5,
};
const familyBlock: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 4,
};

/* --------------------------------- row ----------------------------------- */

function ConfigRowEditor(props: {
  row: CostConfigRow;
  draft: string;
  onDraft: (v: string) => void;
  onSave: () => void;
  saving: boolean;
  saved: boolean;
  errorMsg: string | null;
}): JSX.Element {
  const { row, draft, onDraft, onSave, saving, saved, errorMsg } = props;
  const overridden = row.overridden_by_env;
  const dirty = draft !== row.effective_value;
  const canSave = dirty && !overridden && !saving;
  const sourceChip: CSSProperties =
    row.effective_source === "db" ? chipOk : chipFaint;

  let control: JSX.Element;
  if (overridden) {
    control = (
      <input
        type="text"
        value={row.effective_value}
        readOnly
        disabled
        style={inputDisabled}
      />
    );
  } else if (row.value_type === "bool") {
    control = (
      <select
        value={draft}
        onChange={(e: ChangeEvent<HTMLSelectElement>) => onDraft(e.target.value)}
        style={inputStyle}
      >
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    );
  } else if (row.value_type === "int" || row.value_type === "float") {
    control = (
      <input
        type="number"
        value={draft}
        step={row.value_type === "float" ? "any" : 1}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onDraft(e.target.value)}
        style={inputStyle}
      />
    );
  } else {
    control = (
      <input
        type="text"
        value={draft}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onDraft(e.target.value)}
        style={inputStyle}
      />
    );
  }

  return (
    <div style={rowGrid}>
      <div style={rowKey} title={row.key}>{row.key}</div>
      {control}
      <div style={rowChips}>
        <span style={sourceChip}>{row.effective_source}</span>
        {overridden ? <span style={chipWarn}>env override</span> : null}
      </div>
      <button
        type="button"
        onClick={onSave}
        disabled={!canSave}
        style={canSave ? btnPrimary : btnPrimaryDisabled}
      >
        {saving ? "saving\u2026" : "save"}
      </button>
      {overridden ? (
        <div style={rowEnvNote}>
          Live value comes from env var <code>{row.env_key}</code>. Edits here
          will not take effect until it is unset.
        </div>
      ) : null}
      {errorMsg ? (
        <div style={{ ...warnText, ...rowStatus }}>{errorMsg}</div>
      ) : saved && !dirty ? (
        <div style={{ ...okText, ...rowStatus }}>saved</div>
      ) : null}
    </div>
  );
}

/* ------------------------------- segment --------------------------------- */

export default function CostConfigs(): JSX.Element {
  const query = useCostConfig();
  const mut = useUpdateCostConfig();

  const rows = useMemo<CostConfigRow[]>(() => query.data ?? [], [query.data]);

  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [inFlightKey, setInFlightKey] = useState<string | null>(null);
  const [savedKeys, setSavedKeys] = useState<Record<string, true>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});

  const grouped = useMemo(() => {
    const out: Record<string, CostConfigRow[]> = {};
    for (const fam of FAMILIES) out[fam.id] = [];
    for (const row of rows) {
      const fam = FAMILIES.find((f) => f.match(row.key));
      if (fam) out[fam.id].push(row);
    }
    for (const fam of FAMILIES) {
      out[fam.id].sort((a, b) => a.key.localeCompare(b.key));
    }
    return out;
  }, [rows]);

  const draftFor = (row: CostConfigRow): string =>
    Object.prototype.hasOwnProperty.call(drafts, row.key)
      ? drafts[row.key]
      : row.effective_value;

  const handleSave = (row: CostConfigRow): void => {
    const value = draftFor(row);
    setInFlightKey(row.key);
    setErrors((prev) => {
      const next = { ...prev };
      delete next[row.key];
      return next;
    });
    setSavedKeys((prev) => {
      const next = { ...prev };
      delete next[row.key];
      return next;
    });
    mut.mutate(
      { key: row.key, value, value_type: row.value_type },
      {
        onSuccess: () => {
          setInFlightKey((k) => (k === row.key ? null : k));
          setDrafts((prev) => {
            const next = { ...prev };
            delete next[row.key];
            return next;
          });
          setSavedKeys((prev) => ({ ...prev, [row.key]: true }));
        },
        onError: (err) => {
          setInFlightKey((k) => (k === row.key ? null : k));
          setErrors((prev) => ({ ...prev, [row.key]: apiErrMessage(err) }));
        },
      },
    );
  };

  let body: JSX.Element;
  if (query.isLoading) {
    body = <div style={emptyNote}>loading config\u2026</div>;
  } else if (query.error) {
    body = <div style={emptyNote}>{apiErrMessage(query.error)}</div>;
  } else {
    body = (
      <div style={{ ...pad, ...stack, gap: 22 }}>
        {FAMILIES.map((fam) => {
          const items = grouped[fam.id];
          return (
            <section key={fam.id} style={familyBlock}>
              <header style={familyHeader}>
                <div style={familyTitle}>{fam.title}</div>
                <div style={familyBlurb}>{fam.blurb}</div>
              </header>
              {items.length === 0 ? (
                <div style={{ ...prose, padding: "10px 0" }}>
                  No keys currently configured in this family. {fam.blurb}
                </div>
              ) : (
                items.map((row) => (
                  <ConfigRowEditor
                    key={row.key}
                    row={row}
                    draft={draftFor(row)}
                    onDraft={(v) =>
                      setDrafts((prev) => ({ ...prev, [row.key]: v }))
                    }
                    onSave={() => handleSave(row)}
                    saving={inFlightKey === row.key}
                    saved={Boolean(savedKeys[row.key])}
                    errorMsg={errors[row.key] ?? null}
                  />
                ))
              )}
            </section>
          );
        })}
      </div>
    );
  }

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span>cost configuration</span>
      </div>
      <div style={scroll}>{body}</div>
    </div>
  );
}
