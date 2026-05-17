/**
 * Lightweight syntax highlighter for PoC code previews
 * (08_FRONTEND_UX.md §Topic 4). Zero-dep — uses a small regex
 * tokenizer keyed on language. Supports python / javascript / c /
 * bash; falls back to plain text for unknown languages.
 *
 * Why not Prism / Shiki: those bring 100+ KB and don't render any
 * better at the small sizes we care about. The PoC preview is
 * scoped to short snippets where keyword/string/comment colouring
 * is enough signal. If a richer preview is needed later, swap this
 * component for a real highlighter — the prop surface won't change.
 */

type Lang = "python" | "javascript" | "ts" | "c" | "bash" | "text";

const LANG_KEYWORDS: Record<Lang, ReadonlyArray<string>> = {
  python: [
    "def", "class", "return", "if", "elif", "else", "for", "while",
    "try", "except", "finally", "with", "as", "import", "from",
    "raise", "yield", "lambda", "pass", "break", "continue", "in",
    "is", "not", "and", "or", "True", "False", "None", "async",
    "await", "global", "nonlocal", "assert",
  ],
  javascript: [
    "function", "const", "let", "var", "return", "if", "else",
    "for", "while", "do", "switch", "case", "default", "break",
    "continue", "try", "catch", "finally", "throw", "new", "this",
    "class", "extends", "super", "import", "export", "from",
    "async", "await", "yield", "true", "false", "null", "undefined",
    "typeof", "instanceof", "delete", "void",
  ],
  ts: [
    "function", "const", "let", "var", "return", "if", "else",
    "for", "while", "do", "switch", "case", "default", "break",
    "continue", "try", "catch", "finally", "throw", "new", "this",
    "class", "extends", "super", "import", "export", "from",
    "async", "await", "yield", "true", "false", "null", "undefined",
    "typeof", "instanceof", "delete", "void", "interface", "type",
    "enum", "implements", "private", "public", "protected", "readonly",
  ],
  c: [
    "int", "char", "short", "long", "float", "double", "unsigned",
    "signed", "void", "struct", "union", "enum", "typedef", "static",
    "const", "extern", "volatile", "if", "else", "for", "while",
    "do", "switch", "case", "default", "break", "continue", "return",
    "goto", "sizeof", "size_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "true",
    "false", "NULL",
  ],
  bash: [
    "if", "then", "else", "elif", "fi", "for", "while", "do", "done",
    "case", "esac", "in", "function", "return", "exit", "echo",
    "export", "source", "local", "readonly", "set", "unset", "shift",
    "trap", "true", "false",
  ],
  text: [],
};

function detectLang(language: string | null | undefined): Lang {
  const l = (language ?? "").toLowerCase().trim();
  if (l.startsWith("py")) return "python";
  if (l === "js" || l === "javascript" || l === "node") return "javascript";
  if (l === "ts" || l === "typescript") return "ts";
  if (l === "c" || l === "cpp" || l === "c++") return "c";
  if (l === "sh" || l === "bash" || l === "shell") return "bash";
  return "text";
}

interface Token {
  type: "kw" | "str" | "num" | "comment" | "text";
  value: string;
}

function tokenize(source: string, lang: Lang): Token[] {
  if (lang === "text") return [{ type: "text", value: source }];
  const keywords = new Set(LANG_KEYWORDS[lang]);
  const tokens: Token[] = [];

  // Comment styles per language.
  const lineComment = lang === "python" || lang === "bash" ? "#" : "//";
  const stringQuotes = lang === "bash" ? ['"', "'"] : ['"', "'", "`"];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    // Line comments
    if (source.startsWith(lineComment, i)) {
      const end = source.indexOf("\n", i);
      const stop = end === -1 ? source.length : end;
      tokens.push({ type: "comment", value: source.slice(i, stop) });
      i = stop;
      continue;
    }
    // Block comments (C-like)
    if ((lang === "c" || lang === "ts" || lang === "javascript")
      && source.startsWith("/*", i)) {
      const end = source.indexOf("*/", i + 2);
      const stop = end === -1 ? source.length : end + 2;
      tokens.push({ type: "comment", value: source.slice(i, stop) });
      i = stop;
      continue;
    }
    // String literal
    if (stringQuotes.includes(ch)) {
      const quote = ch;
      let j = i + 1;
      while (j < source.length && source[j] !== quote) {
        if (source[j] === "\\" && j + 1 < source.length) {
          j += 2;
          continue;
        }
        if (source[j] === "\n") break;
        j += 1;
      }
      tokens.push({ type: "str", value: source.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    // Number literal
    if (/[0-9]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9a-fxA-FX_.]/.test(source[j])) j += 1;
      tokens.push({ type: "num", value: source.slice(i, j) });
      i = j;
      continue;
    }
    // Identifier (then keyword check)
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j])) j += 1;
      const word = source.slice(i, j);
      tokens.push({
        type: keywords.has(word) ? "kw" : "text",
        value: word,
      });
      i = j;
      continue;
    }
    // Anything else: ship as text and advance 1.
    tokens.push({ type: "text", value: ch });
    i += 1;
  }
  return tokens;
}

const STYLE: Record<Token["type"], string> = {
  kw: "text-violet-300",
  str: "text-amber-300",
  num: "text-cyan-300",
  comment: "text-text-muted italic",
  text: "text-foreground",
};

export function SyntaxHighlighter({
  code,
  language,
  className,
}: {
  code: string;
  language?: string | null;
  className?: string;
}) {
  const lang = detectLang(language);
  const tokens = tokenize(code, lang);
  return (
    <pre
      className={
        "text-xs font-mono whitespace-pre overflow-x-auto p-2 "
        + "rounded bg-surface/60 border border-border-default "
        + (className ?? "")
      }
      data-language={lang}
    >
      <code>
        {tokens.map((t, idx) => (
          <span key={idx} className={STYLE[t.type]}>
            {t.value}
          </span>
        ))}
      </code>
    </pre>
  );
}
