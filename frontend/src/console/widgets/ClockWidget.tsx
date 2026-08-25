/** ClockWidget -- local + UTC wall clock, 1s tick.
 *
 * Pure client-side widget. Accepts WidgetProps for signature parity with the
 * rest of the catalog; nothing is read from them. */

import type { JSX } from "react";
import { useEffect, useState } from "react";

import { css } from "../css";
import type { WidgetProps } from "./types";

const ROOT = css(
  "flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden;" +
  "padding:10px 12px;background:var(--surface-card);" +
  "font-family:var(--font-mono);color:var(--text-primary);gap:6px;" +
  "justify-content:center;",
);

const LABEL = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;" +
  "color:var(--text-faint);",
);

const BIG = css(
  "font-size:22px;font-variant-numeric:tabular-nums;color:var(--text-primary);" +
  "letter-spacing:0.05em;",
);

const MID = css(
  "font-size:12px;font-variant-numeric:tabular-nums;color:var(--text-muted);" +
  "letter-spacing:0.05em;",
);

export default function ClockWidget(_props: WidgetProps): JSX.Element {
  const [now, setNow] = useState<Date>(() => new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  // Zero-pad used at 9 call sites (three per clock line, three lines) with
  // lockstep behavior -- allowed per the tiny-function rule.
  const p = (n: number): string => String(n).padStart(2, "0");

  const localTime = `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
  const localDate = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
  const utcTime = `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())}`;

  return (
    <div style={ROOT}>
      <div>
        <div style={LABEL}>local</div>
        <div style={BIG}>{localTime}</div>
        <div style={MID}>{localDate}</div>
      </div>
      <div>
        <div style={LABEL}>utc</div>
        <div style={MID}>{utcTime}</div>
      </div>
    </div>
  );
}
