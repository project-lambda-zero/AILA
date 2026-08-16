/** Compact hex dump viewer for §1.6 minimised-input panel.
 *
 *  Renders 16 bytes per row in 3 columns: offset / hex / ascii. Long
 *  inputs are truncated with a "show all" toggle to keep DOM cheap.
 *  When `data` is null/empty an empty-state message is rendered. */
import { useState, type CSSProperties } from "react";

const ROW_BYTES = 16;
const TRUNCATE_AT = 4096; // bytes -- above this we hide unless explicit

const CTRL_BTN: CSSProperties = {
  height: 22,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

const PRE_STYLE: CSSProperties = {
  margin: 0,
  padding: 12,
  fontSize: 11,
  lineHeight: 1.5,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  overflow: "auto",
  maxHeight: 400,
  whiteSpace: "pre",
  fontFamily: "var(--font-mono)",
};

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
      <div
        className="font-mono"
        style={{
          padding: 34,
          textAlign: "center",
          fontSize: 11.5,
          color: "var(--text-muted)",
          letterSpacing: "0.04em",
        }}
      >
        no reproducer bytes available.
      </div>
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
    <div className="flex flex-col" style={{ gap: 8 }}>
      <div
        className="font-mono uppercase"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 8,
          fontSize: 10,
          letterSpacing: "0.08em",
          color: "var(--text-muted)",
        }}
      >
        <span>
          {bytes.byteLength.toLocaleString()} bytes
          {filename && (
            <span style={{ marginLeft: 8 }}>{"\u00b7 "}{filename}</span>
          )}
        </span>
        <button
          type="button"
          onClick={downloadBytes}
          className="font-mono uppercase"
          style={CTRL_BTN}
        >
          download
        </button>
      </div>
      <pre className="font-mono" style={PRE_STYLE}>
        {rows.map((row) => (
          <div key={row.offset}>
            <span style={{ color: "var(--text-muted)" }}>
              {row.offset.toString(16).padStart(8, "0")}
            </span>
            {"  "}
            <span style={{ color: "var(--text-primary)" }}>
              {row.hex.join(" ").padEnd(ROW_BYTES * 3 - 1, " ")}
            </span>
            {"   "}
            <span style={{ color: "var(--text-muted)" }}>{row.ascii}</span>
          </div>
        ))}
      </pre>
      {truncated && (
        <button
          type="button"
          onClick={() => setShowAll(true)}
          className="font-mono uppercase"
          style={{ ...CTRL_BTN, alignSelf: "flex-start" }}
        >
          show all {bytes.byteLength.toLocaleString()} bytes
        </button>
      )}
    </div>
  );
}
