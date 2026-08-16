import type { CSSProperties } from "react";

/**
 * Parse a CSS declaration string into a React style object so the design page's
 * exact inline styles can be copied verbatim. `css("padding:0 12px;color:red")`
 * -> { padding: "0 12px", color: "red" }. Values stay strings; React applies
 * them as-is. Keeps design fidelity 1:1 with the mock's inline style strings.
 */
export function css(input: string): CSSProperties {
  const out: Record<string, string> = {};
  for (const decl of input.split(";")) {
    const idx = decl.indexOf(":");
    if (idx < 0) continue;
    const prop = decl.slice(0, idx).trim();
    if (!prop) continue;
    const value = decl.slice(idx + 1).trim();
    const key = prop.replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase());
    out[key] = value;
  }
  // Record<string,string> is structurally a CSSProperties bag of string values;
  // React accepts string values for every property. Single boundary cast.
  return out as CSSProperties;
}
