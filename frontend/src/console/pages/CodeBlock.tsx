import Editor, { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import { Component, type JSX, type ReactNode } from "react";

import { css } from "../css";

// Self-host Monaco: use the bundled instance instead of the default CDN loader
// so the editor works with no network access. Read-only rendering + Monarch
// syntax highlighting run on the main thread, so a no-op worker is enough (the
// language worker is never exercised here).
loader.config({ monaco });
if (typeof window !== "undefined") {
  const w = window as unknown as { MonacoEnvironment?: unknown };
  if (!w.MonacoEnvironment) {
    w.MonacoEnvironment = {
      getWorker(): Worker {
        return new Worker(URL.createObjectURL(new Blob(["self.onmessage=function(){};"], { type: "text/javascript" })));
      },
    };
  }
}

const preStyle = css(
  "margin:0;padding:8px 10px;font-family:var(--font-mono);font-size:10.5px;line-height:1.5;color:var(--text-primary);white-space:pre;overflow:auto;max-height:360px;",
);

// If Monaco fails to initialise, fall back to a plain <pre> so the code stays
// readable.
class CodeFallback extends Component<{ code: string; children: ReactNode }, { failed: boolean }> {
  state: { failed: boolean } = { failed: false };
  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }
  render(): ReactNode {
    if (this.state.failed) return <pre style={preStyle}>{this.props.code}</pre>;
    return this.props.children;
  }
}

// Provider language names -> Monaco language ids.
const LANG: Record<string, string> = {
  java: "java",
  python: "python",
  py: "python",
  c: "c",
  cpp: "cpp",
  "c++": "cpp",
  javascript: "javascript",
  js: "javascript",
  typescript: "typescript",
  ts: "typescript",
  go: "go",
  rust: "rust",
  kotlin: "kotlin",
  shell: "shell",
  bash: "shell",
};

// Read-only Monaco viewer for decompiled pseudocode and PoC scripts.
export default function CodeBlock({ code, language }: { code: string; language?: string }): JSX.Element {
  const lang = LANG[(language ?? "").toLowerCase()] ?? "plaintext";
  const lines = code.split("\n").length;
  const height = Math.min(360, Math.max(72, lines * 18 + 14));
  return (
    <div style={css("overflow:hidden;background:#1e1e1e;")}>
      <CodeFallback code={code}>
        <Editor
          height={height}
          language={lang}
          value={code}
          theme="vs-dark"
          loading={<pre style={preStyle}>{code}</pre>}
          options={{
            readOnly: true,
            domReadOnly: true,
            minimap: { enabled: false },
            fontSize: 11,
            fontFamily: "'Spline Sans Mono', ui-monospace, monospace",
            lineNumbers: "on",
            scrollBeyondLastLine: false,
            renderLineHighlight: "none",
            folding: false,
            wordWrap: "off",
            automaticLayout: true,
            guides: { indentation: false },
            scrollbar: { vertical: "auto", horizontal: "auto" },
          }}
        />
      </CodeFallback>
    </div>
  );
}
