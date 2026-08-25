/**
 * AutomationWizard -- the bespoke create surface for admin automation
 * schedules. Opens as a registry window (`admin:new-automation`) from the
 * "+" button on the `admin:automation` list and from the "schedule this
 * action" button on the `admin:automation-actions` catalog detail. Drives
 * `POST /automation/schedules` (routers/automation.py) over five steps:
 *
 *   1. pick an action from the live registry, grouped by module
 *   2. pick a target from the caller's own systems (/systems)
 *   3. schedule (preset picker + custom-cron + live "next 3 runs" preview)
 *   4. arguments (typed form when the action's `param_schema` declares
 *      `properties`; keyval fallback otherwise -- today every action
 *      returns null and the fallback is what the operator sees)
 *   5. review + submit, then show the created schedule
 *
 * `investigationId` (the shell's generic prefill slot) carries an optional
 * pre-selected `action_id`: when set, step 1 is pre-filled and the wizard
 * opens on step 2. Every field maps 1:1 to the AutomationScheduleCreate
 * contract; there is no fabricated payload.
 */

import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import type { ApiError } from "../../api/client";
import type {
  AutomationActionInfo,
  AutomationSchedule,
  AutomationScheduleCreate,
} from "../../api/automation";
import { useAutomationActions, useCreateAutomationSchedule } from "../../api/automation";
import { useSystems } from "../../api/systems";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import {
  CRON_PRESETS,
  WEEKDAY_NAMES,
  formatFireTime,
  humanizeCron,
  nextRuns,
} from "./cronPreview";

/* -------------------------------------------------------------------------- *
 * shared style helpers -- mirror NdayProjectForm / UploadForm inline vars
 * -------------------------------------------------------------------------- */

const panelBoxRaw =
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));";
const panelTitle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const sectionLabel = css(
  "font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);",
);
const labelStyle = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);
const fieldCol = css("display:flex;flex-direction:column;gap:4px;");
const inputStyleRaw =
  "background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;border-radius:2px;";
const inputStyle = css(inputStyleRaw);
const selectStyle = inputStyle;
const helpText = css(
  "font-size:10.5px;color:var(--text-faint);line-height:1.5;",
);

/* -------------------------------------------------------------------------- *
 * step chrome
 * -------------------------------------------------------------------------- */

const STEPS: Array<{ id: number; label: string }> = [
  { id: 1, label: "action" },
  { id: 2, label: "target" },
  { id: 3, label: "schedule" },
  { id: 4, label: "arguments" },
  { id: 5, label: "review" },
];

function StepStrip({ current, furthest }: { current: number; furthest: number }): JSX.Element {
  return (
    <div style={css("display:flex;gap:6px;align-items:stretch;")}>
      {STEPS.map((s) => {
        const active = s.id === current;
        const done = s.id < furthest;
        const color = active ? "var(--accent)" : done ? "var(--text-muted)" : "var(--text-faint)";
        const border = active ? "var(--accent)" : "var(--border-soft)";
        return (
          <div
            key={s.id}
            style={css(
              `flex:1;padding:6px 10px;border:1px solid ${border};border-radius:2px;background:${
                active ? "color-mix(in srgb,var(--accent) 8%,transparent)" : "transparent"
              };display:flex;flex-direction:column;gap:2px;`,
            )}
          >
            <span style={css(`font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:${color};`)}>
              {`step ${s.id}`}
            </span>
            <span
              style={css(
                `font-size:11.5px;color:${active ? "var(--text-primary)" : color};letter-spacing:0.04em;text-transform:lowercase;`,
              )}
            >
              {s.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* -------------------------------------------------------------------------- *
 * step 1 -- action catalog
 * -------------------------------------------------------------------------- */

function ActionCatalog({
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
                  <span style={css("font-size:10.5px;color:var(--text-muted);letter-spacing:0.02em;line-height:1.45;")}>
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

/* -------------------------------------------------------------------------- *
 * step 3 -- schedule picker
 * -------------------------------------------------------------------------- */

interface ScheduleState {
  presetId: string;
  hour: number;
  minute: number;
  weekday: number;
  dayOfMonth: number;
  customExpr: string;
}

const initialSchedule: ScheduleState = {
  presetId: "daily",
  hour: 9,
  minute: 0,
  weekday: 1,
  dayOfMonth: 1,
  customExpr: "0 9 * * *",
};

function cronFromSchedule(st: ScheduleState): string {
  if (st.presetId === "custom") return st.customExpr.trim();
  const preset = CRON_PRESETS.find((p) => p.id === st.presetId);
  if (!preset) return "";
  return preset.build({
    hour: st.hour,
    minute: st.minute,
    weekday: st.weekday,
    dayOfMonth: st.dayOfMonth,
  });
}

function SchedulePicker({
  st,
  onChange,
}: {
  st: ScheduleState;
  onChange: (patch: Partial<ScheduleState>) => void;
}): JSX.Element {
  const preset = CRON_PRESETS.find((p) => p.id === st.presetId) ?? null;
  const expr = cronFromSchedule(st);
  const preview = nextRuns(expr, 3);
  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <p style={helpText}>
        {
          "pick a preset or supply a raw cron string. the preview below shows the next three fire times computed by the same 5-field parser the backend uses (croniter). schedules run in utc."
        }
      </p>
      <label style={fieldCol}>
        <span style={labelStyle}>preset</span>
        <select
          value={st.presetId}
          onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange({ presetId: e.target.value })}
          style={selectStyle}
        >
          {CRON_PRESETS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
          <option value="custom">custom cron (5 fields, utc)</option>
        </select>
      </label>
      {preset && (preset.needsTime || preset.needsWeekday || preset.needsDayOfMonth) ? (
        <div style={css("display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;")}>
          {preset.needsTime ? (
            <label style={fieldCol}>
              <span style={labelStyle}>time (utc)</span>
              <input
                type="time"
                value={`${String(st.hour).padStart(2, "0")}:${String(st.minute).padStart(2, "0")}`}
                onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                  const [h, m] = e.target.value.split(":");
                  onChange({ hour: Number(h) || 0, minute: Number(m) || 0 });
                }}
                style={inputStyle}
              />
            </label>
          ) : null}
          {preset.needsWeekday ? (
            <label style={fieldCol}>
              <span style={labelStyle}>weekday</span>
              <select
                value={st.weekday}
                onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange({ weekday: Number(e.target.value) })}
                style={selectStyle}
              >
                {WEEKDAY_NAMES.map((n, i) => (
                  <option key={n} value={i}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          {preset.needsDayOfMonth ? (
            <label style={fieldCol}>
              <span style={labelStyle}>day of month (1-28)</span>
              <input
                type="number"
                min={1}
                max={28}
                value={st.dayOfMonth}
                onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                  const n = Number(e.target.value);
                  onChange({ dayOfMonth: Number.isFinite(n) ? Math.max(1, Math.min(28, n)) : 1 });
                }}
                style={inputStyle}
              />
            </label>
          ) : null}
        </div>
      ) : null}
      {st.presetId === "custom" ? (
        <label style={fieldCol}>
          <span style={labelStyle}>custom cron (minute hour dom month dow)</span>
          <input
            style={inputStyle}
            value={st.customExpr}
            placeholder="0 9 * * 1-5"
            onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange({ customExpr: e.target.value })}
          />
          <span style={helpText}>
            {
              "the server (croniter) is still the validator. this preview understands the common shapes; anything more exotic still submits and the server will accept or reject it on POST."
            }
          </span>
        </label>
      ) : null}
      <div
        style={css(
          "padding:9px 11px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:flex;flex-direction:column;gap:6px;",
        )}
      >
        <span style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
          {"resolved schedule"}
        </span>
        <div style={css("display:grid;grid-template-columns:110px 1fr;gap:4px 12px;font-size:11.5px;")}>
          <span style={css("color:var(--text-faint);")}>cron</span>
          <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{expr || "\u2014"}</span>
          <span style={css("color:var(--text-faint);")}>in plain english</span>
          <span style={css("color:var(--text-primary);")}>{expr ? humanizeCron(expr) : "\u2014"}</span>
          <span style={css("color:var(--text-faint);")}>next 3 runs</span>
          <span style={css("color:var(--text-primary);display:flex;flex-direction:column;gap:2px;")}>
            {preview.length > 0
              ? preview.map((d) => <span key={d.toISOString()}>{formatFireTime(d)}</span>)
              : <span style={css("color:var(--status-warn);")}>{"no fire time in the next 370 days -- check the expression"}</span>}
          </span>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- *
 * step 4 -- argument editors
 * -------------------------------------------------------------------------- */

/** Minimal shape we read from `param_schema.properties[name]`. Anything the
 * server does not send is treated as absent (the wizard is forward-compatible
 * with the JSON-Schema-ish extensions the registry might add later). */
interface ParamPropSchema {
  type?: string;
  description?: string;
  enum?: unknown[];
  default?: unknown;
}

interface ParsedParamSchema {
  props: Array<[string, ParamPropSchema]>;
  required: string[];
}

function parseParamSchema(raw: Record<string, unknown> | null | undefined): ParsedParamSchema | null {
  if (!raw || typeof raw !== "object") return null;
  const propsRaw = raw["properties"];
  if (!propsRaw || typeof propsRaw !== "object") return null;
  const entries = Object.entries(propsRaw as Record<string, unknown>).filter(
    (e): e is [string, ParamPropSchema] => e[1] != null && typeof e[1] === "object",
  );
  if (entries.length === 0) return null;
  const required = Array.isArray(raw["required"])
    ? (raw["required"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  return { props: entries, required };
}

function TypedArgsForm({
  schema,
  values,
  onChange,
}: {
  schema: ParsedParamSchema;
  values: Record<string, unknown>;
  onChange: (name: string, value: unknown) => void;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"this action declares a typed argument set. required fields are marked; every value is sent verbatim to the runner."}
      </p>
      {schema.props.map(([name, spec]) => {
        const isRequired = schema.required.includes(name);
        const cur = values[name];
        const displayed = cur === undefined ? spec.default : cur;
        const labelSuffix = isRequired ? " (required)" : "";
        const desc = spec.description ?? "";
        const enumOpts = Array.isArray(spec.enum) ? spec.enum.map(String) : null;
        let control: ReactNode;
        if (enumOpts) {
          control = (
            <select
              value={displayed === undefined || displayed === null ? "" : String(displayed)}
              onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange(name, e.target.value)}
              style={selectStyle}
            >
              <option value="">{"\u2014 select \u2014"}</option>
              {enumOpts.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          );
        } else if (spec.type === "boolean") {
          control = (
            <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
              <input
                type="checkbox"
                checked={Boolean(displayed)}
                onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(name, e.target.checked)}
              />
              {"enabled"}
            </label>
          );
        } else if (spec.type === "integer" || spec.type === "number") {
          control = (
            <input
              type="number"
              step={spec.type === "integer" ? 1 : "any"}
              value={displayed === undefined || displayed === null ? "" : String(displayed)}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                const raw = e.target.value;
                if (raw === "") {
                  onChange(name, undefined);
                  return;
                }
                const n = spec.type === "integer" ? parseInt(raw, 10) : Number(raw);
                onChange(name, Number.isFinite(n) ? n : raw);
              }}
              style={inputStyle}
            />
          );
        } else {
          control = (
            <input
              type="text"
              value={displayed === undefined || displayed === null ? "" : String(displayed)}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(name, e.target.value)}
              style={inputStyle}
            />
          );
        }
        return (
          <label key={name} style={fieldCol}>
            <span style={labelStyle}>{`${name}${labelSuffix}`}</span>
            {control}
            {desc ? <span style={helpText}>{desc}</span> : null}
          </label>
        );
      })}
    </div>
  );
}

/* -------------------------------------------------------------------------- *
 * step 4 fallback -- keyval editor
 * -------------------------------------------------------------------------- */

interface KVRow {
  key: string;
  value: string;
}

function KeyvalEditor({
  rows,
  onChange,
}: {
  rows: KVRow[];
  onChange: (rows: KVRow[]) => void;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"this action does not declare typed arguments. any keys/values entered below are passed verbatim to the action at run time."}
      </p>
      <div style={css("display:flex;flex-direction:column;gap:6px;")}>
        {rows.map((row, i) => (
          <div key={i} style={css("display:grid;grid-template-columns:1fr 1fr auto;gap:6px;")}>
            <input
              placeholder="key"
              value={row.key}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                const next = rows.slice();
                next[i] = { ...next[i], key: e.target.value };
                onChange(next);
              }}
              style={inputStyle}
            />
            <input
              placeholder="value"
              value={row.value}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                const next = rows.slice();
                next[i] = { ...next[i], value: e.target.value };
                onChange(next);
              }}
              style={inputStyle}
            />
            <button
              type="button"
              onClick={(): void => onChange(rows.filter((_, j) => j !== i))}
              style={css(
                "padding:0 10px;border:1px solid var(--border-soft);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
              )}
            >
              remove
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={(): void => onChange([...rows, { key: "", value: "" }])}
        style={css(
          "align-self:flex-start;padding:4px 10px;border:1px solid var(--accent);background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
        )}
      >
        {"+ add pair"}
      </button>
    </div>
  );
}

function kvRowsToKwargs(rows: KVRow[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const row of rows) {
    const key = row.key.trim();
    if (key === "") continue;
    out[key] = row.value;
  }
  return out;
}

/* -------------------------------------------------------------------------- *
 * component
 * -------------------------------------------------------------------------- */

export default function AutomationWizard(props: ModulePageProps): JSX.Element {
  const {
    investigationId,
    onBack,
    onMinimize,
    isFullscreen,
    onToggleFullscreen,
    windowId,
    title: windowTitle,
    isFocused,
    onFocus,
  } = props;

  const prefillActionId = (investigationId ?? "").trim();

  const actionsQ = useAutomationActions();
  const systemsQ = useSystems(1, 200);
  const createSchedule = useCreateAutomationSchedule();

  const actionRows = actionsQ.data ?? [];
  const systemRows = systemsQ.data?.items ?? [];

  const [step, setStep] = useState<number>(prefillActionId ? 2 : 1);
  const [furthest, setFurthest] = useState<number>(prefillActionId ? 2 : 1);
  const [actionId, setActionId] = useState<string>(prefillActionId);
  const [targetName, setTargetName] = useState<string>("");
  const [enabled, setEnabled] = useState<boolean>(true);
  const [schedule, setSchedule] = useState<ScheduleState>(initialSchedule);
  const [typedArgs, setTypedArgs] = useState<Record<string, unknown>>({});
  const [kvRows, setKvRows] = useState<KVRow[]>([]);
  const [created, setCreated] = useState<AutomationSchedule | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedAction = useMemo(
    () => actionRows.find((a) => a.action_id === actionId) ?? null,
    [actionRows, actionId],
  );
  const parsedSchema = useMemo(
    () => parseParamSchema(selectedAction?.param_schema ?? null),
    [selectedAction],
  );

  // Reset typed-args + kv rows when the operator switches action, so a schema
  // shape from action A never leaks into a POST for action B.
  useEffect(() => {
    setTypedArgs({});
    setKvRows([]);
  }, [actionId]);

  // The system picker defaults to the first row once the fetch lands, so
  // step 2 has a sensible pre-filled value the operator can override.
  useEffect(() => {
    if (targetName === "" && systemRows.length > 0) {
      setTargetName(systemRows[0].name);
    }
  }, [systemRows, targetName]);

  const cronExpr = cronFromSchedule(schedule);
  const cronRuns = nextRuns(cronExpr, 3);

  const stepBlocker = (n: number): string | null => {
    if (n === 1) {
      if (actionId.trim() === "") return "pick an action from the catalog to continue.";
      return null;
    }
    if (n === 2) {
      if (targetName.trim() === "") return "pick a target system so the schedule binds to something the server accepts.";
      return null;
    }
    if (n === 3) {
      if (cronExpr.trim() === "") return "supply a cron expression (choose a preset or type a custom one).";
      if (cronRuns.length === 0) return "the cron expression does not produce a fire time in the next 370 days; adjust it.";
      return null;
    }
    if (n === 4 && parsedSchema) {
      for (const req of parsedSchema.required) {
        const cur = typedArgs[req];
        if (cur === undefined || cur === null || String(cur).trim() === "") {
          return `required argument \`${req}\` is empty.`;
        }
      }
      return null;
    }
    return null;
  };

  const blocker = stepBlocker(step);
  const canAdvance = blocker === null;

  const goNext = (): void => {
    if (!canAdvance) return;
    const nx = Math.min(step + 1, 5);
    setStep(nx);
    if (nx > furthest) setFurthest(nx);
  };
  const goBack = (): void => setStep(Math.max(step - 1, 1));

  const kwargsForSubmit = useMemo<Record<string, unknown>>(() => {
    if (parsedSchema) {
      const out: Record<string, unknown> = {};
      for (const [name, spec] of parsedSchema.props) {
        const cur = typedArgs[name];
        const val = cur === undefined ? spec.default : cur;
        if (val === undefined) continue;
        out[name] = val;
      }
      return out;
    }
    return kvRowsToKwargs(kvRows);
  }, [parsedSchema, typedArgs, kvRows]);

  const canSubmit =
    step === 5 &&
    !created &&
    !createSchedule.isPending &&
    actionId.trim() !== "" &&
    targetName.trim() !== "" &&
    cronExpr.trim() !== "";

  async function onSubmit(): Promise<void> {
    if (!canSubmit) return;
    setError(null);
    const body: AutomationScheduleCreate = {
      action_id: actionId.trim(),
      target_name: targetName.trim(),
      cron_expression: cronExpr.trim(),
      enabled,
    };
    if (Object.keys(kwargsForSubmit).length > 0) {
      body.action_kwargs = kwargsForSubmit;
    }
    try {
      const result = await createSchedule.mutateAsync(body);
      setCreated(result);
    } catch (err) {
      const msg =
        err && typeof err === "object" && "message" in err
          ? String((err as ApiError).message || "").slice(0, 400)
          : "unknown error";
      setError(msg);
    }
  }

  /* ---- per-step body ---------------------------------------------------- */

  const step1 = (
    <ActionCatalog
      actions={actionRows}
      loading={actionsQ.isLoading}
      selectedId={actionId}
      onPick={(id) => {
        setActionId(id);
        if (furthest < 1) setFurthest(1);
      }}
    />
  );

  const step2 = (() => {
    if (systemsQ.isLoading) {
      return <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading systems\u2026"}</span>;
    }
    if (systemRows.length === 0) {
      return (
        <span style={css("font-size:11px;color:var(--status-warn);")}>
          {"no systems registered -- add one from admin \u00b7 systems first, then return here."}
        </span>
      );
    }
    return (
      <div style={css("display:flex;flex-direction:column;gap:12px;")}>
        <p style={helpText}>
          {"the target is the system the action runs against. picking a row fills `target_name` with that system's registered name so the server-side ownership check succeeds; the server rejects unowned names with 403."}
        </p>
        <label style={fieldCol}>
          <span style={labelStyle}>target system</span>
          <select
            value={targetName}
            onChange={(e: ChangeEvent<HTMLSelectElement>): void => setTargetName(e.target.value)}
            style={selectStyle}
          >
            {systemRows.map((s) => (
              <option key={s.id} value={s.name}>
                {`${s.name} \u2014 ${s.host}${s.distro ? ` (${s.distro})` : ""}`}
              </option>
            ))}
          </select>
        </label>
      </div>
    );
  })();

  const step3 = (
    <SchedulePicker
      st={schedule}
      onChange={(patch) => setSchedule((s) => ({ ...s, ...patch }))}
    />
  );

  const step4 = parsedSchema ? (
    <TypedArgsForm
      schema={parsedSchema}
      values={typedArgs}
      onChange={(name, value) => setTypedArgs((s) => ({ ...s, [name]: value }))}
    />
  ) : (
    <KeyvalEditor rows={kvRows} onChange={setKvRows} />
  );

  const step5 = (() => {
    const humanCron = cronExpr ? humanizeCron(cronExpr) : "\u2014";
    const kwargsPreview = Object.keys(kwargsForSubmit).length > 0
      ? JSON.stringify(kwargsForSubmit, null, 2)
      : "(none)";
    return (
      <div style={css("display:flex;flex-direction:column;gap:12px;")}>
        <p style={helpText}>
          {"review the schedule below; step 5 submits `POST /automation/schedules`. the server re-validates action_id, cron_expression, and target ownership."}
        </p>
        <div
          style={css(
            "padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:grid;grid-template-columns:130px 1fr;gap:6px 12px;font-size:11.5px;",
          )}
        >
          <span style={css("color:var(--text-faint);")}>action</span>
          <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{actionId}</span>
          {selectedAction ? (
            <>
              <span style={css("color:var(--text-faint);")}>module</span>
              <span style={css("color:var(--text-primary);")}>{selectedAction.module_id}</span>
              <span style={css("color:var(--text-faint);")}>description</span>
              <span style={css("color:var(--text-primary);")}>{selectedAction.description}</span>
            </>
          ) : null}
          <span style={css("color:var(--text-faint);")}>target</span>
          <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{targetName}</span>
          <span style={css("color:var(--text-faint);")}>cron</span>
          <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{cronExpr || "\u2014"}</span>
          <span style={css("color:var(--text-faint);")}>plain english</span>
          <span style={css("color:var(--text-primary);")}>{humanCron}</span>
          <span style={css("color:var(--text-faint);")}>next runs</span>
          <span style={css("color:var(--text-primary);display:flex;flex-direction:column;gap:2px;")}>
            {cronRuns.length > 0
              ? cronRuns.map((d) => <span key={d.toISOString()}>{formatFireTime(d)}</span>)
              : <span style={css("color:var(--status-warn);")}>{"no fire time in the next 370 days"}</span>}
          </span>
          <span style={css("color:var(--text-faint);")}>arguments</span>
          <pre
            style={css(
              "margin:0;color:var(--text-primary);font-family:var(--font-mono);font-size:10.5px;white-space:pre-wrap;word-break:break-word;",
            )}
          >
            {kwargsPreview}
          </pre>
          <span style={css("color:var(--text-faint);")}>enabled</span>
          <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setEnabled(e.target.checked)}
            />
            {enabled ? "yes -- the runner will pick this up on its next tick" : "no -- created but paused"}
          </label>
        </div>
      </div>
    );
  })();

  const stepBody: Record<number, ReactNode> = {
    1: step1,
    2: step2,
    3: step3,
    4: step4,
    5: step5,
  };

  /* ---- created panel ---------------------------------------------------- */

  const createdPanel = created ? (
    <div
      style={css(
        "display:flex;flex-direction:column;gap:12px;padding:14px;border:1px solid var(--status-ok);border-radius:3px;background:color-mix(in srgb,var(--status-ok) 8%,transparent);",
      )}
    >
      <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--status-ok);")}>
        {"schedule created"}
      </div>
      <div style={css("display:grid;grid-template-columns:130px 1fr;gap:5px 12px;font-size:11.5px;")}>
        <span style={css("color:var(--text-faint);")}>id</span>
        <span style={css("color:var(--text-primary);word-break:break-all;")}>{String(created.id)}</span>
        <span style={css("color:var(--text-faint);")}>action</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.action_id}</span>
        <span style={css("color:var(--text-faint);")}>target</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.target_name}</span>
        <span style={css("color:var(--text-faint);")}>cron</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.cron_expression}</span>
        <span style={css("color:var(--text-faint);")}>plain english</span>
        <span style={css("color:var(--text-primary);")}>{humanizeCron(created.cron_expression)}</span>
        <span style={css("color:var(--text-faint);")}>enabled</span>
        <span style={css("color:var(--text-primary);")}>{created.enabled ? "yes" : "no"}</span>
      </div>
    </div>
  ) : null;

  /* ---- render ----------------------------------------------------------- */

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--accent)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        {"admin \u00b7 new automation"}
      </span>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          textTransform: "none",
          letterSpacing: "0.03em",
          color: "var(--text-muted)",
        }}
      >
        POST /automation/schedules
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={windowTitle}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <main style={{ flex: 1, minHeight: 0, display: "flex", padding: 12 }}>
        <div style={css(`flex:1;${panelBoxRaw}`)}>
          <div style={panelTitle}>
            <span style={dot} />
            <span style={css("color:var(--text-primary);")}>
              {created ? "created" : `step ${step} of 5 \u00b7 ${STEPS[step - 1].label}`}
            </span>
            <span style={css("flex:1;")} />
            <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
              automation
            </span>
          </div>
          <div
            style={css(
              "flex:1;min-height:0;overflow:auto;padding:14px;display:flex;flex-direction:column;gap:16px;max-width:820px;",
            )}
          >
            {created ? (
              createdPanel
            ) : (
              <>
                <StepStrip current={step} furthest={furthest} />
                {stepBody[step]}
                {blocker ? (
                  <div
                    style={css(
                      "padding:8px 10px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);",
                    )}
                  >
                    {blocker}
                  </div>
                ) : null}
              </>
            )}

            {error ? (
              <div
                style={css(
                  "padding:8px 10px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);white-space:pre-wrap;word-break:break-word;",
                )}
              >
                {error}
              </div>
            ) : null}

            <div
              style={css(
                "display:flex;align-items:center;gap:9px;padding-top:10px;border-top:1px solid var(--border-soft);",
              )}
            >
              <button
                type="button"
                onClick={onBack}
                style={css(
                  "padding:0 12px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:3px;cursor:pointer;",
                )}
              >
                {created ? "close" : "cancel"}
              </button>
              {!created && step > 1 ? (
                <button
                  type="button"
                  onClick={goBack}
                  style={css(
                    "padding:0 12px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:3px;cursor:pointer;",
                  )}
                >
                  {"\u25c2 back"}
                </button>
              ) : null}
              <span style={css("flex:1;")} />
              {createSchedule.isPending ? (
                <span style={css("font-size:11px;color:var(--accent);letter-spacing:0.06em;")}>{"submitting\u2026"}</span>
              ) : null}
              {!created && step < 5 ? (
                <button
                  type="button"
                  onClick={goNext}
                  disabled={!canAdvance}
                  style={css(
                    `padding:0 16px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:${
                      canAdvance ? "pointer" : "not-allowed"
                    };opacity:${canAdvance ? 1 : 0.5};`,
                  )}
                >
                  {"next \u25b8"}
                </button>
              ) : null}
              {!created && step === 5 ? (
                <button
                  type="button"
                  onClick={(): void => void onSubmit()}
                  disabled={!canSubmit}
                  style={css(
                    `padding:0 16px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:${
                      canSubmit ? "pointer" : "not-allowed"
                    };opacity:${canSubmit ? 1 : 0.5};`,
                  )}
                >
                  {"create schedule \u25b8"}
                </button>
              ) : null}
            </div>
          </div>
        </div>
      </main>
    </ConsoleWindow>
  );
}

/* -------------------------------------------------------------------------- *
 * Automation action detail body (the "schedule this action" affordance in
 * the /automation/actions catalog detail panel).
 * -------------------------------------------------------------------------- */

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
