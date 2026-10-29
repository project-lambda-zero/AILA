/** Shared schedule step for the cron-driven wizards: preset picker + custom
 * cron + live "resolved schedule" preview (cron, plain english, next 3 runs).
 * The preview computes with the same 5-field parser the backend uses. */

import type { ChangeEvent, JSX } from "react";

import { css } from "../css";
import { CRON_PRESETS, WEEKDAY_NAMES, formatFireTime, humanizeCron, nextRuns } from "../pages/cronPreview";
import { fieldCol, helpText, inputStyle, labelStyle, selectStyle } from "./fields";

export interface ScheduleState {
  presetId: string;
  hour: number;
  minute: number;
  weekday: number;
  dayOfMonth: number;
  customExpr: string;
}

export const initialSchedule: ScheduleState = {
  presetId: "daily",
  hour: 9,
  minute: 0,
  weekday: 1,
  dayOfMonth: 1,
  customExpr: "0 9 * * *",
};

export function cronFromSchedule(st: ScheduleState): string {
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

export function SchedulePicker({
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
        <span style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
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
