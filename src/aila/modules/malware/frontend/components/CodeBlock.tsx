import { lazy, Suspense, useMemo, useState } from "react";

const MonacoEditor = lazy(() =>
  import("@monaco-editor/react").then((m) => ({ default: m.default })),
);

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

/** Compute line count for editor height. */
function lineCount(text: string, max = 30, min = 3): number {
  const lines = text.split("\n").length;
  return Math.max(min, Math.min(lines, max));
}

interface CodeBlockProps {
  code: string;
  filePath?: string;
  address?: string;
  className?: string;
}

/**
 * Monaco-powered read-only code viewer for source/decompiled code
 * in investigation turn cards. Lazy-loaded so Monaco's ~2MB bundle
 * doesn't block initial page render.
 */
export function CodeBlock({ code: rawCode, filePath = "", address, className = "" }: CodeBlockProps) {
  // Strip indexer preamble like "[file extent: 10160 lines total; ...]"
  // and unescape \\n → newline, \\t → tab
  const code = useMemo(() => {
    let cleaned = rawCode
      .replace(/^\[file extent:.*?\]\s*/i, "")
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .trim();
    return cleaned;
  }, [rawCode]);

  const [collapsed, setCollapsed] = useState(code.length > 2000);
  const displayCode = collapsed ? code.slice(0, 2000) + "\n// … truncated" : code;
  const lang = useMemo(() => detectLanguage(filePath || address || "", code), [filePath, address, code]);
  const height = lineCount(displayCode) * 19 + 10;

  return (
    <div className={`rounded-md border border-border-default/40 overflow-hidden ${className}`}>
      {(filePath || address) && (
        <div className="flex items-center justify-between gap-2 px-3 py-1.5 bg-elevated/80 border-b border-border-default/40">
          <span className="text-2xs font-mono text-foreground/80 truncate">
            {filePath || address}
          </span>
          <span className="text-4xs font-mono text-text-muted uppercase tracking-wider shrink-0">
            {lang}
          </span>
        </div>
      )}
      <Suspense
        fallback={
          <pre className="p-3 text-2xs font-mono text-foreground/80 whitespace-pre-wrap bg-elevated/40">
            {displayCode}
          </pre>
        }
      >
        <MonacoEditor
          value={displayCode}
          language={lang}
          theme="vs-dark"
          height={height}
          options={{
            readOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            lineNumbers: "on",
            lineNumbersMinChars: 3,
            folding: false,
            fontSize: 12,
            fontFamily: "'Geist Mono', 'JetBrains Mono', 'Fira Code', monospace",
            renderLineHighlight: "none",
            overviewRulerLanes: 0,
            hideCursorInOverviewRuler: true,
            overviewRulerBorder: false,
            scrollbar: {
              vertical: "hidden",
              horizontal: "auto",
              verticalScrollbarSize: 0,
            },
            wordWrap: "on",
            padding: { top: 8, bottom: 8 },
            contextmenu: false,
            domReadOnly: true,
          }}
        />
      </Suspense>
      {code.length > 2000 && (
        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          className="w-full py-1 text-3xs font-mono uppercase tracking-wider text-text-muted hover:text-foreground bg-elevated/60 border-t border-border-default/40"
        >
          {collapsed ? `expand (+${(code.length - 2000).toLocaleString()} chars)` : "collapse"}
        </button>
      )}
    </div>
  );
}
