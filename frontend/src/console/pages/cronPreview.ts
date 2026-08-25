/**
 * cronPreview -- small hand-rolled utilities for the 5-field cron dialect
 * the AILA backend accepts (croniter, `POST /automation/schedules`). The
 * frontend uses these for:
 *   - building canonical cron strings from a preset picker (every hour,
 *     daily/weekdays/weekly/monthly at HH:MM);
 *   - previewing the next N fire times of a candidate cron string in the
 *     wizard, so the operator sees what a schedule will actually do before
 *     submitting;
 *   - rendering a plain-language ("every weekday at 09:00 UTC") version of
 *     a schedule row on the list page next to the raw cron.
 *
 * The parser is intentionally small: `*`, `*` / n step, a-b ranges, and
 * comma-separated lists / bare ints. Day-of-week accepts 0-6 with 7 meaning
 * Sunday (croniter behavior). Symbolic month/DOW names (MON..SUN, JAN..DEC)
 * are NOT expanded here -- presets always emit numeric fields so the preview
 * agrees with what the server will store, and the custom-cron escape hatch
 * lets an operator ship anything croniter accepts (the server is still the
 * canonical validator; nextRuns simply returns [] for shapes this parser
 * does not understand). Times are UTC to match the runner side.
 */

export interface CronPreset {
  id: string;
  label: string;
  /** True if the preset needs an HH:MM picker in the UI. */
  needsTime: boolean;
  /** True if the preset needs a day-of-week picker (0=Sun..6=Sat). */
  needsWeekday: boolean;
  /** True if the preset needs a day-of-month picker (1..28). */
  needsDayOfMonth: boolean;
  build: (input: { hour: number; minute: number; weekday: number; dayOfMonth: number }) => string;
}

/** Ordered list of presets rendered in the wizard step 3 picker. `custom`
 * is a sentinel handled outside this catalog (raw cron input). */
export const CRON_PRESETS: CronPreset[] = [
  {
    id: "hourly",
    label: "every hour, on the hour",
    needsTime: false,
    needsWeekday: false,
    needsDayOfMonth: false,
    build: () => "0 * * * *",
  },
  {
    id: "daily",
    label: "every day at HH:MM",
    needsTime: true,
    needsWeekday: false,
    needsDayOfMonth: false,
    build: ({ hour, minute }) => `${minute} ${hour} * * *`,
  },
  {
    id: "weekdays",
    label: "every weekday (mon-fri) at HH:MM",
    needsTime: true,
    needsWeekday: false,
    needsDayOfMonth: false,
    build: ({ hour, minute }) => `${minute} ${hour} * * 1-5`,
  },
  {
    id: "weekly",
    label: "weekly on a chosen weekday at HH:MM",
    needsTime: true,
    needsWeekday: true,
    needsDayOfMonth: false,
    build: ({ hour, minute, weekday }) => `${minute} ${hour} * * ${weekday}`,
  },
  {
    id: "monthly",
    label: "monthly on a chosen day at HH:MM",
    needsTime: true,
    needsWeekday: false,
    needsDayOfMonth: true,
    build: ({ hour, minute, dayOfMonth }) => `${minute} ${hour} ${dayOfMonth} * *`,
  },
];

export const WEEKDAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const;

interface FieldSpec {
  min: number;
  max: number;
}

const FIELDS: FieldSpec[] = [
  { min: 0, max: 59 }, // minute
  { min: 0, max: 23 }, // hour
  { min: 1, max: 31 }, // day of month
  { min: 1, max: 12 }, // month
  { min: 0, max: 6 }, // day of week (7 folded to 0)
];

function parseField(raw: string, spec: FieldSpec, isDow: boolean): Set<number> | null {
  const out = new Set<number>();
  const parts = raw.split(",");
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed === "") return null;
    // step: base/step (base may be `*` or `a-b`).
    let base = trimmed;
    let step = 1;
    const slash = trimmed.indexOf("/");
    if (slash >= 0) {
      base = trimmed.slice(0, slash);
      const stepStr = trimmed.slice(slash + 1);
      const n = Number(stepStr);
      if (!Number.isInteger(n) || n <= 0) return null;
      step = n;
    }
    let lo: number;
    let hi: number;
    if (base === "*") {
      lo = spec.min;
      hi = spec.max;
    } else if (base.includes("-")) {
      const [a, b] = base.split("-");
      const ai = Number(a);
      const bi = Number(b);
      if (!Number.isInteger(ai) || !Number.isInteger(bi)) return null;
      lo = ai;
      hi = bi;
    } else {
      const n = Number(base);
      if (!Number.isInteger(n)) return null;
      lo = n;
      hi = n;
    }
    if (isDow) {
      if (lo === 7) lo = 0;
      if (hi === 7) hi = 0;
    }
    if (lo < spec.min || hi > spec.max || lo > hi) return null;
    for (let v = lo; v <= hi; v += step) out.add(v);
  }
  return out;
}

interface ParsedCron {
  minute: Set<number>;
  hour: Set<number>;
  dom: Set<number>;
  month: Set<number>;
  dow: Set<number>;
  /** True when day-of-month or day-of-week is `*` -- controls whether both
   * constraints AND together or OR together, per Vixie cron semantics
   * (croniter follows the OR rule when both are restricted). */
  domRestricted: boolean;
  dowRestricted: boolean;
}

export function parseCron(expr: string): ParsedCron | null {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return null;
  const minute = parseField(parts[0], FIELDS[0], false);
  const hour = parseField(parts[1], FIELDS[1], false);
  const dom = parseField(parts[2], FIELDS[2], false);
  const month = parseField(parts[3], FIELDS[3], false);
  const dow = parseField(parts[4], FIELDS[4], true);
  if (!minute || !hour || !dom || !month || !dow) return null;
  return {
    minute,
    hour,
    dom,
    month,
    dow,
    domRestricted: parts[2] !== "*",
    dowRestricted: parts[4] !== "*",
  };
}

/** Next `count` fire times (UTC) after `from` (default: now) for the cron
 * `expr`. Returns `[]` if the expression cannot be parsed or no fire time
 * appears in the bounded horizon (~370 days ahead). */
export function nextRuns(expr: string, count: number, from?: Date): Date[] {
  const parsed = parseCron(expr);
  if (!parsed) return [];
  const out: Date[] = [];
  const start = from ? new Date(from.getTime()) : new Date();
  // Advance to the next whole minute in UTC; cron ticks on the minute.
  let cur = new Date(Date.UTC(
    start.getUTCFullYear(),
    start.getUTCMonth(),
    start.getUTCDate(),
    start.getUTCHours(),
    start.getUTCMinutes(),
    0,
    0,
  ));
  cur = new Date(cur.getTime() + 60_000);
  const horizon = cur.getTime() + 370 * 24 * 60 * 60_000;
  while (out.length < count && cur.getTime() < horizon) {
    if (matchesCron(parsed, cur)) {
      out.push(new Date(cur.getTime()));
    }
    cur = new Date(cur.getTime() + 60_000);
  }
  return out;
}

function matchesCron(p: ParsedCron, d: Date): boolean {
  const m = d.getUTCMinutes();
  const h = d.getUTCHours();
  const dom = d.getUTCDate();
  const mon = d.getUTCMonth() + 1;
  const dow = d.getUTCDay();
  if (!p.minute.has(m)) return false;
  if (!p.hour.has(h)) return false;
  if (!p.month.has(mon)) return false;
  // Vixie/croniter: when BOTH dom and dow are restricted, either match
  // is enough (OR); when only one is restricted, that constraint applies
  // and the other is a no-op.
  const domOk = p.dom.has(dom);
  const dowOk = p.dow.has(dow);
  if (p.domRestricted && p.dowRestricted) return domOk || dowOk;
  if (p.domRestricted) return domOk;
  if (p.dowRestricted) return dowOk;
  return true;
}

const WEEKDAY_LONG = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return `${n}${s[(v - 20) % 10] ?? s[v] ?? s[0]}`;
}

/** A short list of shapes that render as plain language. Anything else
 * falls back to the raw cron string so the caller can decide what to show
 * next to it (e.g. "custom cron: 0 9 1,15 * *"). */
export function humanizeCron(expr: string): string {
  const raw = expr.trim();
  const parsed = parseCron(raw);
  if (!parsed) return raw;
  const parts = raw.split(/\s+/);
  const [mF, hF, domF, monF, dowF] = parts;
  // hourly on the hour
  if (mF === "0" && hF === "*" && domF === "*" && monF === "*" && dowF === "*") {
    return "every hour, on the hour (utc)";
  }
  // daily at H:M
  if (parsed.minute.size === 1 && parsed.hour.size === 1 && domF === "*" && monF === "*" && dowF === "*") {
    const m = [...parsed.minute][0];
    const h = [...parsed.hour][0];
    return `every day at ${pad2(h)}:${pad2(m)} utc`;
  }
  // weekdays (mon-fri) at H:M
  if (parsed.minute.size === 1 && parsed.hour.size === 1 && domF === "*" && monF === "*" && dowF === "1-5") {
    const m = [...parsed.minute][0];
    const h = [...parsed.hour][0];
    return `every weekday at ${pad2(h)}:${pad2(m)} utc`;
  }
  // weekly on one weekday at H:M
  if (
    parsed.minute.size === 1 &&
    parsed.hour.size === 1 &&
    domF === "*" &&
    monF === "*" &&
    parsed.dow.size === 1
  ) {
    const m = [...parsed.minute][0];
    const h = [...parsed.hour][0];
    const d = [...parsed.dow][0];
    return `every ${WEEKDAY_LONG[d]} at ${pad2(h)}:${pad2(m)} utc`;
  }
  // monthly on a fixed day at H:M
  if (
    parsed.minute.size === 1 &&
    parsed.hour.size === 1 &&
    parsed.dom.size === 1 &&
    monF === "*" &&
    dowF === "*"
  ) {
    const m = [...parsed.minute][0];
    const h = [...parsed.hour][0];
    const d = [...parsed.dom][0];
    return `monthly on the ${ordinal(d)} at ${pad2(h)}:${pad2(m)} utc`;
  }
  return raw;
}

/** Format a Date as "YYYY-MM-DD HH:MM UTC" for the next-runs preview. */
export function formatFireTime(d: Date): string {
  const y = d.getUTCFullYear();
  const mo = pad2(d.getUTCMonth() + 1);
  const da = pad2(d.getUTCDate());
  const h = pad2(d.getUTCHours());
  const mi = pad2(d.getUTCMinutes());
  return `${y}-${mo}-${da} ${h}:${mi} utc`;
}
