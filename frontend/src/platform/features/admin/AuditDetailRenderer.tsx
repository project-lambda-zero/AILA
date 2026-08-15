/**
 * AuditDetailRenderer -- structured renderer for audit event `details` JSON.
 *
 * Rebuilt to the AILA mock language: mono `label / value` grid rows, native
 * `<details>/<summary>` for nested objects, bullet lists for arrays, and a
 * mock-styled copy button for long strings + UUIDs. Only tokens; no shadcn.
 *
 * Rendering rules preserved from the original:
 *   - Top-level primitives render as a `label: value` row.
 *   - Nested objects render inside a native `<details>/<summary>` block.
 *   - Arrays render as bullet lists.
 *   - Long strings (>80 chars) pick up a Copy button.
 *   - IDs/UUIDs render monospace with a Copy button.
 *   - ISO-ish timestamps format to local time.
 *
 * Test contract (LLMLogPage.test uses this indirectly, AuditDetailRenderer
 * tests hit us directly):
 *   - Copy button aria-label pattern: `Copy <keyName>` (e.g. "Copy note").
 *   - `<summary>` for nested object contains the key name.
 *   - Arrays render as `<ul>` + `<li>`.
 *   - `null`/`undefined` details show "No details captured".
 *   - Empty object shows "empty object".
 */
import { useState, useCallback, type CSSProperties } from "react";

import { MonoBadge } from "@/components/aila/mock";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/;
const ID_KEY_RE = /(^|_)id$|(^|_)uuid$/i;
const LONG_STRING_THRESHOLD = 80;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function looksLikeTimestamp(value: string): boolean {
  if (!ISO_DATE_RE.test(value)) return false;
  const parsed = Date.parse(value);
  return !Number.isNaN(parsed);
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function looksLikeId(key: string, value: string): boolean {
  if (UUID_RE.test(value)) return true;
  if (ID_KEY_RE.test(key) && value.length >= 8 && value.length <= 128) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Copy button (mock-styled, no shadcn)
// ---------------------------------------------------------------------------

const COPY_BTN_STYLE: CSSProperties = {
  height: 20,
  padding: "0 7px",
  fontSize: 9,
  letterSpacing: "0.1em",
  borderRadius: 2,
  cursor: "pointer",
  color: "var(--text-muted)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  marginLeft: 4,
};

interface CopyButtonProps {
  value: string;
  label?: string;
}

function CopyButton({ value, label }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard permission denied -- fall through silently.
    }
  }, [value]);

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={label ?? "Copy value"}
      className="font-mono uppercase"
      style={COPY_BTN_STYLE}
    >
      {copied ? "copied" : "copy"}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Scalar value renderer
// ---------------------------------------------------------------------------

interface ScalarProps {
  keyName: string;
  value: string | number | boolean | null;
}

function Scalar({ keyName, value }: ScalarProps) {
  if (value === null) {
    return <MonoBadge tone="muted">null</MonoBadge>;
  }

  if (typeof value === "boolean") {
    return (
      <MonoBadge tone={value ? "info" : "muted"}>
        {String(value)}
      </MonoBadge>
    );
  }

  if (typeof value === "number") {
    return (
      <span
        className="font-mono tabular-nums"
        style={{ color: "var(--text-primary)", fontSize: 11 }}
      >
        {String(value)}
      </span>
    );
  }

  // String branch below.
  const str = value;

  if (looksLikeTimestamp(str)) {
    return (
      <span
        className="font-mono"
        title={str}
        style={{
          color: "var(--text-primary)",
          fontSize: 11,
          whiteSpace: "nowrap",
        }}
      >
        {formatTimestamp(str)}
      </span>
    );
  }

  if (looksLikeId(keyName, str)) {
    return (
      <span className="inline-flex items-center" style={{ gap: 4 }}>
        <span
          className="font-mono truncate"
          title={str}
          style={{
            color: "var(--text-primary)",
            fontSize: 11,
            maxWidth: 360,
          }}
        >
          {str}
        </span>
        <CopyButton value={str} label={`Copy ${keyName}`} />
      </span>
    );
  }

  if (str.length > LONG_STRING_THRESHOLD) {
    return (
      <span
        className="inline-flex items-start"
        style={{ gap: 4, width: "100%" }}
      >
        <span
          className="font-mono"
          style={{
            color: "var(--text-primary)",
            fontSize: 11,
            wordBreak: "break-all",
          }}
        >
          {str}
        </span>
        <CopyButton value={str} label={`Copy ${keyName}`} />
      </span>
    );
  }

  return (
    <span
      className="font-mono"
      style={{
        color: "var(--text-primary)",
        fontSize: 11,
        wordBreak: "break-all",
      }}
    >
      {str}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Recursive node renderer
// ---------------------------------------------------------------------------

interface DetailNodeProps {
  keyName: string;
  value: unknown;
  depth: number;
}

function DetailNode({ keyName, value, depth }: DetailNodeProps) {
  if (isPlainObject(value)) {
    return (
      <details
        open={depth === 0}
        style={{
          borderRadius: 3,
          border: "1px solid var(--border-faint)",
          background:
            "color-mix(in srgb, var(--surface-sunk) 55%, transparent)",
        }}
      >
        <summary
          className="font-mono uppercase"
          style={{
            cursor: "pointer",
            padding: "5px 9px",
            fontSize: 9.5,
            letterSpacing: "0.12em",
            color: "var(--text-muted)",
            userSelect: "none",
          }}
        >
          {keyName}
          <span
            style={{
              marginLeft: 8,
              color: "var(--text-faint)",
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            ({Object.keys(value).length}{" "}
            {Object.keys(value).length === 1 ? "field" : "fields"})
          </span>
        </summary>
        <div style={{ padding: "6px 9px 8px" }}>
          <DetailTable data={value} depth={depth + 1} />
        </div>
      </details>
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return (
        <span
          className="font-mono"
          style={{
            color: "var(--text-faint)",
            fontSize: 11,
            fontStyle: "italic",
          }}
        >
          empty list
        </span>
      );
    }
    return (
      <ul
        style={{
          listStyleType: "disc",
          paddingLeft: 20,
          margin: 0,
          display: "flex",
          flexDirection: "column",
          gap: 4,
        }}
      >
        {value.map((item, idx) => (
          <li
            key={idx}
            className="font-mono"
            style={{ color: "var(--text-primary)", fontSize: 11 }}
          >
            <DetailNode
              keyName={`[${idx}]`}
              value={item}
              depth={depth + 1}
            />
          </li>
        ))}
      </ul>
    );
  }

  // Scalar primitive (string, number, boolean, null, undefined).
  if (value === undefined) {
    return <MonoBadge tone="muted">undefined</MonoBadge>;
  }
  return (
    <Scalar
      keyName={keyName}
      value={value as string | number | boolean | null}
    />
  );
}

// ---------------------------------------------------------------------------
// Table layout -- honest key/value grid
// ---------------------------------------------------------------------------

interface DetailTableProps {
  data: Record<string, unknown>;
  depth: number;
}

function DetailTable({ data, depth }: DetailTableProps) {
  const entries = Object.entries(data);
  if (entries.length === 0) {
    return (
      <p
        className="font-mono"
        style={{
          color: "var(--text-faint)",
          fontSize: 11,
          fontStyle: "italic",
        }}
      >
        empty object
      </p>
    );
  }
  return (
    <dl
      className="grid"
      style={{
        gridTemplateColumns: "minmax(120px, auto) 1fr",
        columnGap: 12,
        rowGap: 6,
        margin: 0,
      }}
    >
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt
            className="font-mono uppercase truncate"
            style={{
              color: "var(--text-muted)",
              fontSize: 9.5,
              letterSpacing: "0.12em",
              alignSelf: "start",
              paddingTop: 2,
            }}
          >
            {key}
          </dt>
          <dd
            className="font-mono"
            style={{
              color: "var(--text-primary)",
              fontSize: 11,
              minWidth: 0,
              margin: 0,
            }}
          >
            <DetailNode keyName={key} value={value} depth={depth} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface AuditDetailRendererProps {
  details: unknown;
}

export function AuditDetailRenderer({ details }: AuditDetailRendererProps) {
  if (details === null || details === undefined) {
    return (
      <p
        className="font-mono"
        style={{
          color: "var(--text-faint)",
          fontSize: 11,
          fontStyle: "italic",
        }}
      >
        No details captured.
      </p>
    );
  }

  if (!isPlainObject(details)) {
    return (
      <div
        className="font-mono"
        style={{ color: "var(--text-primary)", fontSize: 11 }}
      >
        <DetailNode keyName="value" value={details} depth={0} />
      </div>
    );
  }

  return <DetailTable data={details} depth={0} />;
}

export default AuditDetailRenderer;
