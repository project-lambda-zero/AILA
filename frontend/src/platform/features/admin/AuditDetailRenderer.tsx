/**
 * AuditDetailRenderer -- structured renderer for audit event `details` JSON
 * (Plan 176e P1).
 *
 * Replaces the raw JSON dump in AuditLogsPage's detail view. Operator value:
 * rapid scanning of nested keys instead of squinting at `JSON.stringify`.
 *
 * Rendering rules:
 *   - Top-level primitives render as a `label: value` row.
 *   - Nested objects render inside a native `<details>/<summary>` block so
 *     they are keyboard-accessible without extra JS plumbing.
 *   - Arrays render as bullet lists.
 *   - Long strings (>80 chars) pick up a Copy button.
 *   - IDs/UUIDs render monospace with a Copy button.
 *   - ISO-ish timestamps format to local time.
 *
 * Only shared primitives (AilaCard, AilaBadge, shadcn Button, phosphor icons,
 * Tailwind utilities) are used -- no new CSS classes are introduced.
 */
import { useState, useCallback } from "react";
import { Copy, Check } from "@phosphor-icons/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { Button } from "@/components/ui/button";

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
// Copy button
// ---------------------------------------------------------------------------

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
      // Clipboard permission denied -- fall through silently. The button
      // still looks like a button; no hidden success.
    }
  }, [value]);

  return (
    <Button
      type="button"
      size="sm"
      variant="ghost"
      className="h-6 px-1.5 gap-1 font-mono text-[10px] text-text-muted"
      onClick={handleCopy}
      aria-label={label ?? "Copy value"}
    >
      {copied ? (
        <>
          <Check className="h-3 w-3" />
          copied
        </>
      ) : (
        <>
          <Copy className="h-3 w-3" />
          copy
        </>
      )}
    </Button>
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
    return (
      <AilaBadge severity="neutral" size="sm">
        null
      </AilaBadge>
    );
  }

  if (typeof value === "boolean") {
    return (
      <AilaBadge severity={value ? "info" : "neutral"} size="sm">
        {String(value)}
      </AilaBadge>
    );
  }

  if (typeof value === "number") {
    return (
      <span className="font-mono text-xs text-text tabular-nums">
        {String(value)}
      </span>
    );
  }

  // String branch below.
  const str = value;

  if (looksLikeTimestamp(str)) {
    return (
      <span
        className="font-mono text-xs text-text whitespace-nowrap"
        title={str}
      >
        {formatTimestamp(str)}
      </span>
    );
  }

  if (looksLikeId(keyName, str)) {
    return (
      <span className="inline-flex items-center gap-1">
        <span
          className="font-mono text-xs text-text truncate max-w-[360px]"
          title={str}
        >
          {str}
        </span>
        <CopyButton value={str} label={`Copy ${keyName}`} />
      </span>
    );
  }

  if (str.length > LONG_STRING_THRESHOLD) {
    return (
      <span className="inline-flex items-start gap-1 w-full">
        <span className="font-mono text-xs text-text break-all">
          {str}
        </span>
        <CopyButton value={str} label={`Copy ${keyName}`} />
      </span>
    );
  }

  return (
    <span className="font-mono text-xs text-text break-all">
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
        className="group rounded-[4px] border border-border bg-surface/40"
        open={depth === 0}
      >
        <summary className="cursor-pointer px-2 py-1 font-mono text-xs text-text-muted uppercase tracking-wider select-none">
          {keyName}
          <span className="ml-2 text-text-muted/60 normal-case tracking-normal">
            ({Object.keys(value).length}{" "}
            {Object.keys(value).length === 1 ? "field" : "fields"})
          </span>
        </summary>
        <div className="px-2 pb-2">
          <DetailTable data={value} depth={depth + 1} />
        </div>
      </details>
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return (
        <span className="font-mono text-xs text-text-muted italic">
          empty list
        </span>
      );
    }
    return (
      <ul className="list-disc pl-5 space-y-1">
        {value.map((item, idx) => (
          <li key={idx} className="font-mono text-xs text-text">
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
    return (
      <AilaBadge severity="neutral" size="sm">
        undefined
      </AilaBadge>
    );
  }
  return (
    <Scalar
      keyName={keyName}
      value={value as string | number | boolean | null}
    />
  );
}

// ---------------------------------------------------------------------------
// Table layout
// ---------------------------------------------------------------------------

interface DetailTableProps {
  data: Record<string, unknown>;
  depth: number;
}

function DetailTable({ data, depth }: DetailTableProps) {
  const entries = Object.entries(data);
  if (entries.length === 0) {
    return (
      <p className="font-mono text-xs text-text-muted italic">empty object</p>
    );
  }
  return (
    <dl className="grid grid-cols-[minmax(120px,auto)_1fr] gap-x-3 gap-y-1.5">
      {entries.map(([key, value]) => (
        <div
          key={key}
          className="contents"
        >
          <dt className="font-mono text-xs text-text-muted uppercase tracking-wider truncate">
            {key}
          </dt>
          <dd className="font-mono text-xs text-text min-w-0">
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
      <p className="font-mono text-xs text-text-muted italic">
        No details captured.
      </p>
    );
  }

  if (!isPlainObject(details)) {
    // Render a single-row pseudo-table so primitive or array payloads still
    // benefit from the same rules (copy, timestamps, severity badges).
    return (
      <div className="font-mono text-xs text-text">
        <DetailNode keyName="value" value={details} depth={0} />
      </div>
    );
  }

  return <DetailTable data={details} depth={0} />;
}

export default AuditDetailRenderer;
