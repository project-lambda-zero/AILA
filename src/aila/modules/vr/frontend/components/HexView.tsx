/** Compact hex dump viewer for §1.6 minimised-input panel.
 *
 *  Renders 16 bytes per row in 3 columns: offset / hex / ascii. Long
 *  inputs are truncated with a "show all" toggle to keep DOM cheap.
 *  When `data` is null/empty an empty-state message is rendered. */
import { useState } from "react";

const ROW_BYTES = 16;
const TRUNCATE_AT = 4096; // bytes -- above this we hide unless explicit

export function HexView({
  data,
  filename,
}: {
  data: Uint8Array | string | null | undefined;
  filename?: string | null;
}) {
  const [showAll, setShowAll] = useState(false);

  if (!data || (typeof data === "string" ? data.length === 0 : data.byteLength === 0)) {
    return (
      <p className="text-xs text-text-muted">No reproducer bytes available.</p>
    );
  }

  // Normalize input to Uint8Array. String inputs are treated as UTF-8 text.
  const bytes =
    typeof data === "string"
      ? new TextEncoder().encode(data)
      : data;

  const truncated = bytes.byteLength > TRUNCATE_AT && !showAll;
  const view = truncated ? bytes.subarray(0, TRUNCATE_AT) : bytes;

  const rows: Array<{ offset: number; hex: string[]; ascii: string }> = [];
  for (let i = 0; i < view.byteLength; i += ROW_BYTES) {
    const slice = view.subarray(i, i + ROW_BYTES);
    const hex = Array.from(slice).map((b) =>
      b.toString(16).padStart(2, "0"),
    );
    const ascii = Array.from(slice)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    rows.push({ offset: i, hex, ascii });
  }

  function downloadBytes() {
    const blob = new Blob([new Uint8Array(bytes)], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename ?? "reproducer.bin";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap text-3xs text-text-muted font-mono">
        <span>
          {bytes.byteLength.toLocaleString()} bytes
          {filename && <span className="ml-2">· {filename}</span>}
        </span>
        <button
          type="button"
          onClick={downloadBytes}
          className="px-2 py-0.5 text-3xs font-mono rounded bg-surface border border-border-default hover:bg-surface-hover"
        >
          Download
        </button>
      </div>
      <pre className="text-3xs font-mono p-3 rounded bg-surface border border-border-default overflow-x-auto max-h-96 overflow-y-auto leading-relaxed">
        {rows.map((row) => (
          <div key={row.offset}>
            <span className="text-text-muted">
              {row.offset.toString(16).padStart(8, "0")}
            </span>
            {"  "}
            <span className="text-foreground">
              {row.hex.join(" ").padEnd(ROW_BYTES * 3 - 1, " ")}
            </span>
            {"   "}
            <span className="text-text-muted">{row.ascii}</span>
          </div>
        ))}
      </pre>
      {truncated && (
        <button
          type="button"
          onClick={() => setShowAll(true)}
          className="text-3xs font-mono px-2 py-0.5 rounded bg-surface border border-border-default hover:bg-surface-hover"
        >
          Show all {bytes.byteLength.toLocaleString()} bytes
        </button>
      )}
    </div>
  );
}
