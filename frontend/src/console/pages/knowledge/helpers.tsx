/** Small shared helpers for the knowledge page panels. */

import type { JSX } from "react";

import { css } from "../../css";
import { CODE_LOOK_MAX, monoBlock, proseBlock } from "./styles";

/** Match StructuredValue's code-shape heuristic locally so we can render
 *  content bodies (search hits + entry detail) with the right treatment
 *  without forcing every field into <StructuredValue>. */
export function looksLikeCode(text: string): boolean {
  const head = text.trimStart();
  return (
    text.length > CODE_LOOK_MAX ||
    text.indexOf("\n") !== -1 ||
    head.startsWith("{") ||
    head.startsWith("[") ||
    head.startsWith("```")
  );
}

/** A content body the way an operator wants to read it: a mono block for
 * long / code / JSON-shaped bodies, plain paragraph text otherwise. */
export function ContentBody({ text }: { text: string }): JSX.Element {
  if (text === "") return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  if (looksLikeCode(text)) return <pre style={monoBlock}>{text}</pre>;
  return <div style={proseBlock}>{text}</div>;
}

export function fmtScore(score: number): string {
  if (!Number.isFinite(score)) return "\u2014";
  return score.toFixed(3);
}

export function fmtInt(n: number): string {
  if (!Number.isFinite(n)) return "\u2014";
  return n.toLocaleString();
}

export function ellipsize(text: string, max = 140): string {
  const single = text.replace(/\s+/g, " ").trim();
  return single.length <= max ? single : `${single.slice(0, max - 1)}\u2026`;
}
