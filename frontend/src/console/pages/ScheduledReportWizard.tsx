/**
 * ScheduledReportWizard -- the bespoke create surface for admin scheduled
 * reports, plus the detail-panel body the `admin:scheduled-reports` DataPage
 * uses in place of its generic grid. Both live here so the scheduled-reports
 * slice owns its whole bespoke frontend in one file.
 *
 * The wizard opens as a registry window and drives `POST /scheduled-reports`
 * (routers/scheduled_reports.py) over five steps:
 *
 *   1. name the report + pick a report kind from the live catalog
 *      (GET /scheduled-reports/kinds -- today exactly one kind, fleet_health,
 *      but the step renders whatever the registry returns)
 *   2. configure the kind's options (typed form when `config_schema` is
 *      declared, key/value editor otherwise)
 *   3. recipients (one valid email per chip)
 *   4. schedule (preset picker + custom-cron + live "next 3 runs" preview)
 *   5. review + submit, then show the created report
 *
 * The detail body shows a row's `last_run_at` and trigger + task-status
 * surface for manual runs, then a 140px/1fr field grid mirroring DataPage.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, JSX, KeyboardEvent, ReactNode } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { ApiError, apiFetch } from "../../api/client";
import type {
  ScheduledReportCreate,
  ScheduledReportKind,
  ScheduledReportKindOption,
  ScheduledReportRow,
  ScheduledReportTriggerResponse,
} from "../../api/scheduledReports";
import {
  TASK_TERMINAL,
  useCreateScheduledReport,
  useScheduledReportKinds,
  useScheduledReportTask,
} from "../../api/scheduledReports";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { WizardShell, type WizardFieldIssue, type WizardStepDef } from "../wizards";
import {
  CRON_PRESETS,
  WEEKDAY_NAMES,
  formatFireTime,
  humanizeCron,
  nextRuns,
} from "./cronPreview";
import { StructuredValue } from "./StructuredValue";

/* -------------------------------------------------------------------------- *
 * shared style helpers -- mirror AutomationWizard / NdayProjectForm inline vars
 * -------------------------------------------------------------------------- */

const labelStyle = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);
const fieldCol = css("display:flex;flex-direction:column;gap:4px;");
const inputStyleRaw =
  "background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;border-radius:2px;";
const inputStyle = css(inputStyleRaw);
const selectStyle = inputStyle;
const helpText = css("font-size:10.5px;color:var(--text-faint);line-height:1.5;");

/* -------------------------------------------------------------------------- *
 * step chrome -- the five steps as WizardStepDefs the shared WizardShell reads
 * for its `step N of M` strip, purpose line, and progress segments.
 * -------------------------------------------------------------------------- */

const WIZARD_STEPS: WizardStepDef[] = [
  { id: "kind", title: "pick kind", purpose: "name the report and choose which report kind it generates." },
  { id: "options", title: "options", purpose: "configure the kind's options; kinds without declared options take a raw key/value editor." },
  { id: "recipients", title: "recipients", purpose: "recipients receive the generated report on every fire -- one valid email per chip." },
  { id: "schedule", title: "set schedule", purpose: "choose when it fires -- a preset or a raw cron, in utc; the server validates on submit." },
  { id: "review", title: "review", purpose: "confirm the report, then submit it to the scheduler." },
];

/* -------------------------------------------------------------------------- *
 * step 1 -- report kind catalog
 * -------------------------------------------------------------------------- */

function KindCatalog({
  kinds,
  loading,
  error,
  selectedType,
  onPick,
}: {
  kinds: ScheduledReportKind[];
  loading: boolean;
  error: string | null;
  selectedType: string;
  onPick: (reportType: string) => void;
}): JSX.Element {
  if (loading) {
    return <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading report kinds\u2026"}</span>;
  }
  if (error) {
    return <span style={css("font-size:11px;color:var(--status-warn);")}>{error}</span>;
  }
  return (
    <div style={css("display:flex;flex-direction:column;gap:16px;")}>
      <p style={helpText}>
        {
          "a report kind is a server-side generator the scheduler can run on a cron. the catalog below reflects the live registry; pick one and configure its options on the next step."
        }
      </p>
      <div style={css("display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;")}>
        {kinds.map((k) => {
          const active = k.report_type === selectedType;
          const border = active ? "var(--accent)" : "var(--border-soft)";
          const bg = active
            ? "color-mix(in srgb,var(--accent) 10%,transparent)"
            : "var(--surface-sunk)";
          return (
            <button
              key={k.report_type}
              type="button"
              onClick={() => onPick(k.report_type)}
              style={css(
                `text-align:left;padding:10px 12px;border:1px solid ${border};background:${bg};border-radius:3px;cursor:pointer;display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono);`,
              )}
            >
              <span style={css("font-size:11.5px;color:var(--text-primary);letter-spacing:0.04em;")}>
                {k.name}
              </span>
              <span style={css("font-size:9.5px;color:var(--text-faint);letter-spacing:0.06em;")}>
                {k.report_type}
              </span>
              <span style={css("font-size:10.5px;color:var(--text-muted);letter-spacing:0.02em;line-height:1.45;")}>
                {k.description}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- *
 * step 2 -- typed options + key/value fallback
 * -------------------------------------------------------------------------- */

/** Seed one option's initial value from its declared default. A boolean
 * defaults to false, a select with no default to its first option, and a
 * string (or a select with no options) to "". */
function optionInitialValue(opt: ScheduledReportKindOption): string | boolean {
  if (opt.type === "boolean") return opt.default === true;
  if (opt.type === "select" && Array.isArray(opt.options) && opt.options.length > 0) {
    return typeof opt.default === "string" ? opt.default : opt.options[0];
  }
  return typeof opt.default === "string" ? opt.default : "";
}

function TypedOptionsForm({
  schema,
  values,
  onChange,
}: {
  schema: ScheduledReportKindOption[];
  values: Record<string, string | boolean>;
  onChange: (key: string, value: string | boolean) => void;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"configure the kind's options; required fields are marked. values are sent verbatim in the report's config_json."}
      </p>
      {schema.map((opt) => {
        const cur = values[opt.key];
        const labelSuffix = opt.required ? " (required)" : "";
        let control: ReactNode;
        if (opt.type === "boolean") {
          control = (
            <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
              <input
                type="checkbox"
                checked={cur === true}
                onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(opt.key, e.target.checked)}
              />
              {"enabled"}
            </label>
          );
        } else if (opt.type === "select" && Array.isArray(opt.options) && opt.options.length > 0) {
          control = (
            <select
              value={typeof cur === "string" ? cur : ""}
              onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange(opt.key, e.target.value)}
              style={selectStyle}
            >
              {opt.options.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          );
        } else {
          control = (
            <input
              type="text"
              value={typeof cur === "string" ? cur : ""}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(opt.key, e.target.value)}
              style={inputStyle}
            />
          );
        }
        return (
          <label key={opt.key} style={fieldCol}>
            <span style={labelStyle}>{`${opt.label}${labelSuffix}`}</span>
            {control}
          </label>
        );
      })}
    </div>
  );
}

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
        {"this kind does not declare typed options. any keys/values entered below are passed verbatim in the report's config_json."}
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

/** Collapse key/value rows into an object, dropping rows with empty keys. */
function kvObjectFromRows(rows: KVRow[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const row of rows) {
    const key = row.key.trim();
    if (key === "") continue;
    out[key] = row.value;
  }
  return out;
}

/* -------------------------------------------------------------------------- *
 * step 3 -- schedule picker (mirrors AutomationWizard verbatim)
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
 * step 3 -- recipient chips editor
 * -------------------------------------------------------------------------- */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function RecipientsEditor({
  recipients,
  onChange,
}: {
  recipients: string[];
  onChange: (recipients: string[]) => void;
}): JSX.Element {
  const [draft, setDraft] = useState<string>("");
  const [invalid, setInvalid] = useState<boolean>(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const add = (): void => {
    const v = draft.trim();
    if (v === "") return;
    if (!EMAIL_RE.test(v)) {
      setInvalid(true);
      inputRef.current?.focus();
      return;
    }
    onChange([...recipients, v]);
    setDraft("");
    setInvalid(false);
  };

  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"recipients receive the generated report on every fire. each address must be a valid email; invalid entries stay in the input."}
      </p>
      <div style={css("display:flex;gap:6px;align-items:center;")}>
        <input
          ref={inputRef}
          style={css(inputStyleRaw + "flex:1;min-width:0;")}
          value={draft}
          placeholder="ops@example.com"
          onChange={(e: ChangeEvent<HTMLInputElement>): void => {
            setDraft(e.target.value);
            if (invalid) setInvalid(false);
          }}
          onKeyDown={(e: KeyboardEvent<HTMLInputElement>): void => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <button
          type="button"
          onClick={add}
          style={css(
            "padding:0 12px;height:32px;border:1px solid var(--accent);background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
          )}
        >
          add
        </button>
      </div>
      {invalid ? (
        <span style={css("font-size:10.5px;color:var(--status-warn);")}>{"not a valid email"}</span>
      ) : null}
      {recipients.length > 0 ? (
        <div style={css("display:flex;flex-wrap:wrap;gap:6px;")}>
          {recipients.map((r) => (
            <span
              key={r}
              style={css(
                "display:inline-flex;align-items:center;gap:6px;padding:2px 4px 2px 8px;border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:10px;color:var(--text-primary);background:var(--surface-sunk);",
              )}
            >
              {r}
              <button
                type="button"
                aria-label={`remove ${r}`}
                onClick={(): void => onChange(recipients.filter((x) => x !== r))}
                style={css(
                  "padding:0 4px;border:none;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;cursor:pointer;line-height:1;",
                )}
              >
                {"\u2715"}
              </button>
            </span>
          ))}
        </div>
      ) : null}
      <span style={helpText}>{"recipients receive the generated report on every fire."}</span>
    </div>
  );
}

/* -------------------------------------------------------------------------- *
 * helpers
 * -------------------------------------------------------------------------- */

function apiErrMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message || `HTTP ${err.status}`;
  if (err instanceof Error) return err.message;
  return String(err);
}

/* -------------------------------------------------------------------------- *
 * component -- the five-step wizard
 * -------------------------------------------------------------------------- */

export default function ScheduledReportWizard(props: ModulePageProps): JSX.Element {
  const {
    onBack,
    onMinimize,
    isFullscreen,
    onToggleFullscreen,
    windowId,
    title: windowTitle,
    isFocused,
    onFocus,
  } = props;

  const kindsQ = useScheduledReportKinds();
  const createReport = useCreateScheduledReport();

  const kindsRows = kindsQ.data ?? [];
  const kindsErr = kindsQ.error ? apiErrMessage(kindsQ.error) : null;

  const [step, setStep] = useState<number>(1);
  const [name, setName] = useState<string>("");
  const [reportType, setReportType] = useState<string>("");
  const [typedOptions, setTypedOptions] = useState<Record<string, string | boolean>>({});
  const [kvRows, setKvRows] = useState<KVRow[]>([]);
  const [recipients, setRecipients] = useState<string[]>([]);
  const [schedule, setSchedule] = useState<ScheduleState>(initialSchedule);
  const [isActive, setIsActive] = useState<boolean>(true);
  const [created, setCreated] = useState<ScheduledReportRow | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedKind = useMemo(
    () => kindsRows.find((k) => k.report_type === reportType) ?? null,
    [kindsRows, reportType],
  );

  // Seed the typed options from the selected kind's schema (defaults / first
  // option) and reset the key/value rows whenever the kind changes, so option
  // values from kind A never leak into a POST for kind B.
  useEffect(() => {
    const schema = selectedKind?.config_schema ?? [];
    const next: Record<string, string | boolean> = {};
    for (const opt of schema) next[opt.key] = optionInitialValue(opt);
    setTypedOptions(next);
    setKvRows([]);
  }, [selectedKind]);

  const cronExpr = cronFromSchedule(schedule);
  const cronRuns = nextRuns(cronExpr, 3);

  // Per-step validation as the WizardShell contract wants it: an empty list
  // enables the shell's primary control; a non-empty list disables it AND the
  // shell renders each issue by label + reason (no silent disables).
  const stepIssues = (n: number): WizardFieldIssue[] => {
    if (n === 1) {
      const out: WizardFieldIssue[] = [];
      if (name.trim() === "") out.push({ label: "report name", reason: "required" });
      if (kindsQ.isLoading) out.push({ label: "report kinds", reason: "loading catalog" });
      if (reportType.trim() === "") out.push({ label: "report kind", reason: "pick one to continue" });
      return out;
    }
    if (n === 2 && selectedKind && selectedKind.config_schema.length > 0) {
      const out: WizardFieldIssue[] = [];
      for (const opt of selectedKind.config_schema) {
        if (!opt.required) continue;
        const cur = typedOptions[opt.key];
        if (cur === undefined || String(cur).trim() === "") {
          out.push({ label: opt.label, reason: "required" });
        }
      }
      return out;
    }
    if (n === 3) {
      return recipients.length === 0
        ? [{ label: "recipients", reason: "add at least one email" }]
        : [];
    }
    if (n === 4) {
      if (cronExpr.trim() === "") {
        return [{ label: "schedule", reason: "invalid cron or no fire time in the horizon" }];
      }
      if (nextRuns(cronExpr, 1).length === 0) {
        return [{ label: "schedule", reason: "invalid cron or no fire time in the horizon" }];
      }
      return [];
    }
    return [];
  };

  const issues = stepIssues(step);
  const canAdvance = issues.length === 0;

  const goNext = (): void => {
    if (!canAdvance) return;
    setStep(Math.min(step + 1, 5));
  };
  const goBack = (): void => setStep(Math.max(step - 1, 1));

  const configForSubmit = useMemo<Record<string, unknown>>(() => {
    if (selectedKind && selectedKind.config_schema.length > 0) {
      const out: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(typedOptions)) out[key] = val;
      return out;
    }
    return kvObjectFromRows(kvRows);
  }, [selectedKind, typedOptions, kvRows]);

  const canSubmit =
    step === 5 &&
    !created &&
    !createReport.isPending &&
    name.trim() !== "" &&
    reportType.trim() !== "" &&
    cronExpr.trim() !== "" &&
    recipients.length > 0;

  async function onSubmit(): Promise<void> {
    if (!canSubmit) return;
    setError(null);
    const body: ScheduledReportCreate = {
      name: name.trim(),
      report_type: reportType.trim(),
      cron_expression: cronExpr.trim(),
      recipient_emails_json: JSON.stringify(recipients),
      config_json: JSON.stringify(configForSubmit),
      is_active: isActive,
    };
    try {
      const result = await createReport.mutateAsync(body);
      setCreated(result);
    } catch (err) {
      setError(apiErrMessage(err));
    }
  }

  /* ---- per-step body ---------------------------------------------------- */

  const step1 = (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <label style={fieldCol}>
        <span style={labelStyle}>report name</span>
        <input
          style={inputStyle}
          value={name}
          placeholder="fleet weekly summary"
          onChange={(e: ChangeEvent<HTMLInputElement>): void => setName(e.target.value)}
        />
      </label>
      <KindCatalog
        kinds={kindsRows}
        loading={kindsQ.isLoading}
        error={kindsErr}
        selectedType={reportType}
        onPick={(t) => setReportType(t)}
      />
    </div>
  );

  const step2 = selectedKind && selectedKind.config_schema.length > 0 ? (
    <TypedOptionsForm
      schema={selectedKind.config_schema}
      values={typedOptions}
      onChange={(key, value) => setTypedOptions((s) => ({ ...s, [key]: value }))}
    />
  ) : (
    <KeyvalEditor rows={kvRows} onChange={setKvRows} />
  );

  const step3 = (
    <RecipientsEditor recipients={recipients} onChange={setRecipients} />
  );

  const step4 = (
    <SchedulePicker st={schedule} onChange={(patch) => setSchedule((s) => ({ ...s, ...patch }))} />
  );

  const step5 = (() => {
    const humanCron = cronExpr ? humanizeCron(cronExpr) : "\u2014";
    const optionLines: Array<[string, string]> =
      selectedKind && selectedKind.config_schema.length > 0
        ? Object.entries(typedOptions).map(([k, v]) => [k, String(v)] as [string, string])
        : Object.entries(kvObjectFromRows(kvRows)).map(([k, v]) => [k, String(v)] as [string, string]);
    return (
      <div style={css("display:flex;flex-direction:column;gap:12px;")}>
        <p style={helpText}>
          {"review the report below; step 5 submits `POST /scheduled-reports`. the server re-validates the cron and stores the recipient + config payloads as serialized JSON."}
        </p>
        <div
          style={css(
            "padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11.5px;",
          )}
        >
          <span style={css("color:var(--text-faint);")}>name</span>
          <span style={css("color:var(--text-primary);")}>{name}</span>
          <span style={css("color:var(--text-faint);")}>report kind</span>
          <span style={css("color:var(--text-primary);")}>
            {selectedKind ? (
              <>
                {selectedKind.name}{" "}
                <span style={css("color:var(--text-faint);font-family:var(--font-mono);")}>{selectedKind.report_type}</span>
              </>
            ) : (
              "\u2014"
            )}
          </span>
          <span style={css("color:var(--text-faint);")}>options</span>
          <span style={css("color:var(--text-primary);display:flex;flex-direction:column;gap:2px;font-family:var(--font-mono);font-size:10.5px;")}>
            {optionLines.length > 0
              ? optionLines.map(([k, v]) => <span key={k}>{`${k} = ${v}`}</span>)
              : <span style={css("color:var(--text-faint);font-family:var(--font-mono);")}>{"(none)"}</span>}
          </span>
          <span style={css("color:var(--text-faint);")}>recipients</span>
          <span style={css("color:var(--text-primary);display:flex;flex-wrap:wrap;gap:4px;")}>
            {recipients.map((r) => (
              <span
                key={r}
                style={css(
                  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-size:9.5px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
                )}
              >
                {r}
              </span>
            ))}
          </span>
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
          <span style={css("color:var(--text-faint);")}>active</span>
          <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
            <input
              type="checkbox"
              checked={isActive}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setIsActive(e.target.checked)}
            />
            {isActive ? "yes -- the scheduler will pick this up on its next tick" : "no -- created but paused"}
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
        {"report created"}
      </div>
      <div style={css("display:grid;grid-template-columns:130px 1fr;gap:5px 12px;font-size:11.5px;")}>
        <span style={css("color:var(--text-faint);")}>id</span>
        <span style={css("color:var(--text-primary);word-break:break-all;")}>{String(created.id)}</span>
        <span style={css("color:var(--text-faint);")}>name</span>
        <span style={css("color:var(--text-primary);")}>{created.name}</span>
        <span style={css("color:var(--text-faint);")}>report type</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.report_type}</span>
        <span style={css("color:var(--text-faint);")}>cron</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.cron_expression}</span>
        <span style={css("color:var(--text-faint);")}>plain english</span>
        <span style={css("color:var(--text-primary);")}>{humanizeCron(created.cron_expression)}</span>
        <span style={css("color:var(--text-faint);")}>recipients</span>
        <span style={css("color:var(--text-primary);")}>{recipients.length} address{recipients.length === 1 ? "" : "es"}</span>
        <span style={css("color:var(--text-faint);")}>active</span>
        <span style={css("color:var(--text-primary);")}>{created.is_active ? "yes" : "no"}</span>
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
        {"admin \u00b7 new scheduled report"}
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
        POST /scheduled-reports
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
      {created ? (
        <main
          style={{
            flex: 1,
            minHeight: 0,
            display: "flex",
            flexDirection: "column",
            gap: 14,
            overflow: "auto",
            padding: 18,
          }}
        >
          {createdPanel}
          <div>
            <button
              type="button"
              onClick={onBack}
              style={css(
                "padding:0 14px;height:30px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;",
              )}
            >
              close
            </button>
          </div>
        </main>
      ) : (
        <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <div style={{ flex: 1, minHeight: 0 }}>
            <WizardShell
              heading="new scheduled report"
              steps={WIZARD_STEPS}
              current={step - 1}
              issues={issues}
              onBack={goBack}
              onNext={goNext}
              onFinish={(): void => void onSubmit()}
              finishLabel="create report"
              busy={createReport.isPending}
              error={error}
              onRetry={(): void => void onSubmit()}
            >
              {stepBody[step]}
            </WizardShell>
          </div>
        </main>
      )}
    </ConsoleWindow>
  );
}

/* -------------------------------------------------------------------------- *
 * detail body -- the `admin:scheduled-reports` DataPage renders this in place
 * of its generic grid when detailBody is wired. Shows the last run, a manual
 * trigger + live task status, then a 140px/1fr field grid.
 * -------------------------------------------------------------------------- */

const detailChip = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-size:9.5px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
);
const detailLabel = css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;");
const detailValue = css(
  "color:var(--text-primary);word-break:break-word;min-width:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap;",
);

export function ScheduledReportDetail({ row }: { row: Record<string, unknown> }): JSX.Element {
  const id = String(row["id"] ?? "");
  const reportType = String(row["report_type"] ?? "");
  const cronExpr = String(row["cron_expression"] ?? "");
  const isActive = row["is_active"] === true;
  const lastRunAt = row["last_run_at"] ? String(row["last_run_at"]) : null;
  const createdAt = String(row["created_at"] ?? "");
  const updatedAt = String(row["updated_at"] ?? "");

  const qc = useQueryClient();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [manualQueued, setManualQueued] = useState<boolean>(false);
  const [runOutcome, setRunOutcome] = useState<{ ok: boolean; text: string } | null>(null);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  // The caller keys this component per row; also guard in an effect so a new
  // selection never inherits the previous row's trigger/task state.
  useEffect(() => {
    setTaskId(null);
    setManualQueued(false);
    setRunOutcome(null);
    setTriggerError(null);
  }, [id]);

  const triggerMut = useMutation({
    mutationFn: () =>
      apiFetch<ScheduledReportTriggerResponse>(
        `/scheduled-reports/${encodeURIComponent(id)}/trigger`,
        { method: "POST" },
      ),
    onSuccess: (resp) => {
      setTriggerError(null);
      setRunOutcome(null);
      if (resp.task_id === "manual") {
        // No worker attached: the run happens on the next worker cycle, so
        // there is nothing to poll.
        setManualQueued(true);
        setTaskId(null);
        return;
      }
      setManualQueued(false);
      setTaskId(resp.task_id);
    },
    onError: (err) => setTriggerError(apiErrMessage(err)),
  });

  const taskQ = useScheduledReportTask(taskId);

  // When the polled task reaches a terminal state, stop and surface the
  // result; a done run refreshes the row so `last_run_at` updates.
  useEffect(() => {
    const task = taskQ.data;
    if (taskId === null || !task || !TASK_TERMINAL[task.status]) return;
    if (task.status === "done") {
      void qc.invalidateQueries({ queryKey: ["datapage", "/scheduled-reports"] });
      setRunOutcome({ ok: true, text: "run finished -- last_run_at refreshes on the row" });
    } else {
      setRunOutcome({ ok: false, text: `run ${task.status}${task.error ? ` \u2014 ${task.error}` : ""}` });
    }
    setTaskId(null);
  }, [taskQ.data, taskId, qc]);

  const onTrigger = (): void => {
    if (!window.confirm("Trigger this report now?")) return;
    setTriggerError(null);
    setManualQueued(false);
    setRunOutcome(null);
    triggerMut.mutate();
  };

  const pollStatus = taskId !== null ? (taskQ.data?.status ?? "queued") : null;

  /* ---- parsed row fields ------------------------------------------------ */

  const recipientsRaw = String(row["recipient_emails_json"] ?? "");
  let recipientList: string[] | null = null;
  try {
    const parsed: unknown = JSON.parse(recipientsRaw);
    if (Array.isArray(parsed)) recipientList = parsed.map(String);
  } catch {
    recipientList = null;
  }

  const configRaw = row["config_json"];
  let configParsed: unknown = null;
  let configRawStr = "";
  if (configRaw !== undefined && configRaw !== null) {
    configRawStr = String(configRaw);
    try {
      configParsed = JSON.parse(configRawStr);
    } catch {
      configParsed = null;
    }
  }

  /* ---- render ----------------------------------------------------------- */

  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;min-width:0;")}>
      <div
        style={css(
          "padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:flex;flex-direction:column;gap:4px;",
        )}
      >
        <span style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
          last run
        </span>
        <span style={css("font-size:13px;color:var(--text-primary);font-family:var(--font-mono);")}>
          {lastRunAt ?? "never"}
        </span>
      </div>

      <div style={css("display:flex;flex-direction:column;gap:8px;")}>
        <button
          type="button"
          onClick={onTrigger}
          disabled={id === "" || triggerMut.isPending}
          style={css(
            `align-self:flex-start;padding:0 14px;height:30px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:2px;cursor:${
              id === "" || triggerMut.isPending ? "not-allowed" : "pointer"
            };`,
          )}
        >
          {"trigger now"}
        </button>
        {triggerError ? (
          <span style={css("font-size:10.5px;color:var(--status-warn);")}>{triggerError}</span>
        ) : null}
        {manualQueued ? (
          <span style={css("font-size:10.5px;color:var(--text-muted);")}>
            {"queued -- no worker attached; the run happens on the next worker cycle"}
          </span>
        ) : null}
        {pollStatus !== null ? (
          <span style={css("font-size:10.5px;color:var(--text-muted);font-family:var(--font-mono);")}>
            {pollStatus}
          </span>
        ) : null}
        {runOutcome ? (
          <span
            style={css(
              `font-size:10.5px;${runOutcome.ok ? "color:var(--status-ok);" : "color:var(--status-warn);"}`,
            )}
          >
            {runOutcome.text}
          </span>
        ) : null}
      </div>

      <div
        style={css(
          "display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11px;align-content:start;",
        )}
      >
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>name</span>
          <span style={detailValue}>{String(row["name"] ?? "\u2014")}</span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>report type</span>
          <span style={detailValue}>
            <span style={css("font-family:var(--font-mono);")}>{reportType || "\u2014"}</span>
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>recipients</span>
          <span style={detailValue}>
            {recipientList !== null ? (
              recipientList.length > 0 ? (
                recipientList.map((r) => (
                  <span key={r} style={detailChip}>
                    {r}
                  </span>
                ))
              ) : (
                "\u2014"
              )
            ) : (
              recipientsRaw
            )}
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>options</span>
          <span style={detailValue}>
            {configParsed !== null ? (
              <StructuredValue value={configParsed} />
            ) : (
              (configRawStr || "\u2014")
            )}
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>cron</span>
          <span style={detailValue}>
            <span style={css("font-family:var(--font-mono);")}>{cronExpr || "\u2014"}</span>
            {cronExpr ? (
              <span style={css("color:var(--text-faint);font-size:10px;")}>{humanizeCron(cronExpr)}</span>
            ) : null}
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>active</span>
          <span style={detailValue}>{isActive ? "yes" : "no"}</span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>created</span>
          <span style={detailValue}>{createdAt}</span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>updated</span>
          <span style={detailValue}>{updatedAt}</span>
        </span>
      </div>
    </div>
  );
}
