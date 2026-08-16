import { useMemo, useState, type CSSProperties } from "react";

/** Detect language from file path or content heuristics. */
function detectLanguage(path: string, content: string): string {
  // Strip line range suffixes like ":6928-6958" and escape sequences like "\\base\\"
  const cleaned = path.replace(/:\d+(-\d+)?$/, "").replace(/\\\\/g, "/");
  const ext = cleaned.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    c: "c", h: "c", cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp",
    go: "go", rs: "rust", py: "python", js: "javascript", ts: "typescript",
    java: "java", rb: "ruby", php: "php", swift: "swift", kt: "kotlin",
    sh: "shell", bash: "shell", json: "json", yaml: "yaml", yml: "yaml",
    xml: "xml", html: "html", css: "css", sql: "sql", md: "markdown",
  };
  if (map[ext]) return map[ext];
  // Heuristics from content
  if (content.includes("#include") || content.includes("void ") || content.includes("nsI")) return "cpp";
  if (content.includes("func ") && (content.includes(":=") || content.includes("package "))) return "go";
  if (content.includes("def ") && content.includes("self")) return "python";
  if (content.includes("fn ") && content.includes("->") && content.includes("let ")) return "rust";
  return "plaintext";
}

interface CodeBlockProps {
  code: string;
  filePath?: string;
  address?: string;
  className?: string;
}

const HEADER_STYLE: CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 8,
  padding: "6px 10px",
  background: "var(--surface-sunk)",
  borderBottom: "1px solid var(--border-soft)",
  fontSize: 10,
  letterSpacing: "0.08em",
};

const PRE_STYLE: CSSProperties = {
  margin: 0,
  padding: 12,
  fontSize: 11,
  lineHeight: 1.5,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  overflow: "auto",
  maxHeight: 400,
  whiteSpace: "pre",
  fontFamily: "var(--font-mono)",
};

const FOOT_BTN_STYLE: CSSProperties = {
  width: "100%",
  padding: "4px 10px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "var(--surface-sunk)",
  borderTop: "1px solid var(--border-soft)",
  borderRadius: 0,
  cursor: "pointer",
  textAlign: "center",
  fontFamily: "var(--font-mono)",
};

/**
 * Read-only code viewer rendered as a mock-language sunk-surface
 * `<pre>` block. Displays optional header (path + language) and a
 * collapse toggle for long snippets.
 */
export function CodeBlock({ code: rawCode, filePath = "", address, className = "" }: CodeBlockProps) {
  // Strip indexer preamble like "[file extent: 10160 lines total; ...]"
  // and unescape \\n → newline, \\t → tab
  const code = useMemo(() => {
    return rawCode
      .replace(/^\[file extent:.*?\]\s*/i, "")
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .trim();
  }, [rawCode]);

  const [collapsed, setCollapsed] = useState(code.length > 2000);
  const displayCode = collapsed ? code.slice(0, 2000) + "\n// \u2026 truncated" : code;
  const lang = useMemo(() => detectLanguage(filePath || address || "", code), [filePath, address, code]);

  const label = filePath || address;

  return (
    <div
      className={className}
      style={{
        border: "1px solid var(--border-soft)",
        borderRadius: 3,
        background: "var(--surface-sunk)",
        overflow: "hidden",
      }}
    >
      {label && (
        <div className="font-mono uppercase" style={HEADER_STYLE}>
          <span
            style={{
              color: "var(--text-primary)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {label}
          </span>
          <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>
            {lang}
          </span>
        </div>
      )}
      <pre className="font-mono" style={PRE_STYLE}>
        {displayCode}
      </pre>
      {code.length > 2000 && (
        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          className="font-mono uppercase"
          style={FOOT_BTN_STYLE}
        >
          {collapsed
            ? `expand (+${(code.length - 2000).toLocaleString()} chars)`
            : "collapse"}
        </button>
      )}
    </div>
  );
}
