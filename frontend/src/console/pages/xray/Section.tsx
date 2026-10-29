import type { JSX, ReactNode } from "react";

import { css } from "../../css";

// A labelled, colour-coded slice of an expanded card. The colour + heading
// let the eye separate reasoning from the tool from the output at a glance.
export function Section({ label, color, children }: { label: string; color: string; children: ReactNode }): JSX.Element {
  return (
    <div style={css(`margin-top:9px;padding:1px 0 3px 10px;border-left:2px solid ${color};`)}>
      <div style={css(`display:flex;align-items:center;gap:6px;margin-bottom:5px;`)}>
        <span style={css(`font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:${color};`)}>{label}</span>
        <span aria-hidden="true" style={css(`flex:1;height:1px;background:color-mix(in srgb,${color} 22%,transparent);`)} />
      </div>
      {children}
    </div>
  );
}
