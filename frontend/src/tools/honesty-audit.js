#!/usr/bin/env node
/**
 * honesty-audit.js -- AST-free structural honesty checker for TypeScript/TSX source.
 *
 * Detects 12 categories of frontend honesty violations:
 *  1. as_any               -- `as any` type assertion
 *  2. ts_suppress          -- @ts-ignore / @ts-expect-error suppressions
 *  3. console_statement    -- console.log/warn/error/debug in non-test files
 *  4. todo_comment         -- TODO/FIXME/HACK/XXX comments
 *  5. empty_catch          -- empty catch blocks
 *  6. double_cast          -- as unknown as (double-cast escape hatch)
 *  7. raw_fetch            -- bare fetch() not in the authorized API client
 *  8. hardcoded_api_url    -- string literals containing /api/ or localhost
 *  9. inline_any_param     -- function parameters typed as any
 * 10. theme_hardcode        -- hex color literals in .tsx files
 * 11. missing_response_type -- authorizedRequestJson( without <T> type param
 * 12. direct_env_access     -- process.env / import.meta.env outside platform/config/
 *
 * Usage:
 *   node frontend/src/tools/honesty-audit.js [dir] [--whitelist path]
 *
 * Exit 0 = clean. Exit 1 = findings found. Exit 2 = usage error.
 *
 * Design constraints:
 *   ESM. No external npm package imports. Only Node.js built-ins.
 *   Runs from repo root: node frontend/src/tools/honesty-audit.js frontend/src/
 */

import { readFileSync, readdirSync, existsSync, statSync } from "fs";
import { join, resolve, extname, relative } from "path";
import { createRequire } from "module";
import { pathToFileURL } from "url";

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const rootArg = args.find((a) => !a.startsWith("--")) ?? "frontend/src";
const whitelistArgIdx = args.indexOf("--whitelist");
const whitelistPath = whitelistArgIdx >= 0 ? args[whitelistArgIdx + 1] : null;

const rootDir = resolve(process.cwd(), rootArg);

if (!existsSync(rootDir)) {
  process.stderr.write(`honesty-audit: directory not found: ${rootDir}\n`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Whitelist loading
// ---------------------------------------------------------------------------

let whitelist = [];

if (whitelistPath) {
  const resolvedWhitelist = resolve(process.cwd(), whitelistPath);
  if (existsSync(resolvedWhitelist)) {
    try {
      // The whitelist may be CommonJS (exports.HONESTY_WHITELIST) or ESM.
      // Use createRequire to load CJS from an ESM context when possible.
      // If the whitelist file is itself ESM, we fall back to dynamic import.
      let mod;
      try {
        const _require = createRequire(import.meta.url);
        mod = _require(resolvedWhitelist);
      } catch {
        // CJS require failed (whitelist might be pure ESM) -- try dynamic import
        mod = await import(pathToFileURL(resolvedWhitelist).href);
      }
      if (Array.isArray(mod.HONESTY_WHITELIST)) {
        whitelist = mod.HONESTY_WHITELIST;
      } else if (mod.default && Array.isArray(mod.default.HONESTY_WHITELIST)) {
        whitelist = mod.default.HONESTY_WHITELIST;
      } else {
        process.stderr.write(
          `honesty-audit: whitelist must export HONESTY_WHITELIST array\n`
        );
      }
    } catch (err) {
      process.stderr.write(
        `honesty-audit: failed to load whitelist: ${err.message}\n`
      );
    }
  } else {
    process.stderr.write(
      `honesty-audit: whitelist path not found: ${resolvedWhitelist}\n`
    );
  }
}

/**
 * Check if a finding is whitelisted.
 * Whitelist format: [filename_suffix, rule_id, detail]
 */
function isWhitelisted(filePath, ruleId) {
  const normalized = filePath.replace(/\\/g, "/");
  return whitelist.some(([suffix, rule]) => {
    if (rule !== ruleId) return false;
    return normalized.endsWith(suffix.replace(/\\/g, "/"));
  });
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

/**
 * Each rule:
 *   id           -- identifier used in output and whitelist lookup
 *   description  -- human-readable label
 *   pattern      -- RegExp to match on a line (tested against raw line text)
 *   exclude      -- optional RegExp: if matches same line, skip this finding
 *   extensions   -- optional string[]: only apply to these file extensions
 *   skipFile     -- optional RegExp: skip entire file if path matches (forward-slash normalized)
 */
const RULES = [
  // 1. as_any -- `as any` type assertion bypasses the type checker
  {
    id: "as_any",
    description: "Type assertion to `any` bypasses type checker",
    pattern: /\bas\s+any\b/,
    // Exclude double-cast lines -- those are caught separately by rule 6
    exclude: /as\s+unknown\s+as\b/,
  },

  // 2. ts_suppress -- suppression comments
  {
    id: "ts_suppress",
    description: "@ts-ignore / @ts-expect-error suppresses the type checker",
    pattern: /@ts-(ignore|expect-error)/,
  },

  // 3. console_statement -- debug output in production files
  {
    id: "console_statement",
    description: "console statement left in production code",
    pattern: /\bconsole\.(log|warn|error|debug|info|trace)\s*\(/,
    skipFile: /\.(test|spec|stories)\.(ts|tsx|js|jsx)$|__tests__|\/testing\//,
  },

  // 4. todo_comment -- aspirational comments
  {
    id: "todo_comment",
    description: "TODO/FIXME/HACK/XXX aspirational comment",
    pattern: /\/\/\s*(TODO|FIXME|HACK|XXX)\b/i,
  },

  // 5. empty_catch -- silent exception swallowing (single-line empty body)
  {
    id: "empty_catch",
    description: "Empty catch block swallows exceptions silently",
    pattern: /catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}/,
  },

  // 6. double_cast -- `as unknown as X` double-cast escape hatch
  {
    id: "double_cast",
    description: "`as unknown as` double-cast -- find the root type mismatch",
    pattern: /as\s+unknown\s+as\b/,
  },

  // 7. raw_fetch -- bare fetch() outside the authorized HTTP client
  {
    id: "raw_fetch",
    description: "Raw fetch() bypasses auth headers and error normalization",
    pattern: /\bfetch\s*\(/,
    skipFile: /platform\/api\/http\.ts$|platform\/api\/sse\.ts$|lib\/sseClient\.ts$|hooks\/useSSE\.ts$/,
  },

  // 8. hardcoded_api_url -- /api/ path or localhost URL hardcoded in source
  {
    id: "hardcoded_api_url",
    description: "Hardcoded /api/ path or localhost URL -- use path constants",
    pattern: /["'`]\/api\/|["'`]https?:\/\/localhost/,
    extensions: [".ts", ".tsx"],
    skipFile: /platform\/api\/http\.ts$|platform\/config\//,
  },

  // 9. inline_any_param -- function parameter typed as `any`
  {
    id: "inline_any_param",
    description: "Function parameter typed as `any` -- use a specific type",
    // Matches: (foo: any  or , foo: any  (with optional whitespace)
    pattern: /(?:[(,])\s*\w+\s*:\s*any\b/,
    // Exclude lines that are just using `as any` (already caught by rule 1)
    exclude: /\bas\s+any\b/,
  },

  // 10. theme_hardcode -- hex color literals in .tsx files
  {
    id: "theme_hardcode",
    description: "Hex color literal in TSX -- use CSS variables or Tailwind tokens",
    pattern: /#[0-9a-fA-F]{3,8}\b/,
    extensions: [".tsx"],
    // Skip story files (visual regression reference values allowed)
    skipFile: /\.stories\.tsx$/,
    // Skip pure comment lines
    exclude: /^\s*\/\//,
  },

  // 11. missing_response_type -- authorizedRequestJson without <T>
  {
    id: "missing_response_type",
    description: "authorizedRequestJson() called without explicit response type <T>",
    pattern: /authorizedRequestJson\s*\(/,
    exclude: /authorizedRequestJson\s*<[^>]+>\s*\(/,
  },

  // 12. direct_env_access -- env access outside centralized config
  {
    id: "direct_env_access",
    description: "Direct env access -- centralize in platform/config/env.ts",
    pattern: /\b(process\.env|import\.meta\.env)\./,
    skipFile: /platform\/config\//,
    // Skip pure comment lines (JSDoc or // that mention env vars as documentation)
    exclude: /^\s*(?:\/\/|\*)/,
  },
];

// ---------------------------------------------------------------------------
// File-level rules -- fired once per matching file when a REQUIRED pattern
// is absent. Complements the per-line RULES above; use for import-boundary
// or scaffold-adherence checks where the interesting signal is the LACK of
// a token in a file, not its presence on a line.
//
// Each file rule:
//   id             -- identifier used in output and whitelist lookup
//   description    -- human-readable label
//   fileMatch      -- RegExp on forward-slash-normalized path; rule applies
//                     only to matching files
//   requireContent -- RegExp searched against the full file body; finding
//                     emits at line 1 when the pattern is NOT found
// ---------------------------------------------------------------------------
const FILE_RULES = [
  // Every module-frontend SSE hook MUST route its transport through the
  // shared platform hook (auth, reconnect/backoff, abort). Reinventing
  // fetch + line splitting inside a module produces a second convention
  // sitting next to the platform one and drifts (missed auth headers,
  // missed reconnect, missed abort). Enforced across modules because the
  // Python honesty audit cannot scan .ts/.tsx.
  {
    id: "module_sse_missing_platform_import",
    description:
      "Module SSE hook does not import useSSEStream from @platform/hooks/useSSEStream",
    // Any file named useInvestigation*Stream.ts(x) that lives under a
    // module frontend hooks directory (aila/modules/<mod>/frontend/hooks/
    // or frontend/src/modules/<mod>/hooks/). The platform hook itself
    // sits at frontend/src/platform/hooks/useSSEStream.ts (different
    // basename) so it never matches.
    fileMatch:
      /(?:aila\/modules\/[^/]+\/frontend|modules\/[^/]+\/frontend)\/hooks\/useInvestigation[^/]*Stream\.tsx?$/,
    // Import specifier is normalized on the string; matches whether the
    // module uses a default, namespace, or named import form.
    requireContent:
      /from\s+["']@platform\/hooks\/useSSEStream["']/,
  },
];

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(["node_modules", "__tests__", "dist", ".git", "coverage", "tools"]);
const SOURCE_EXTS = new Set([".ts", ".tsx"]);
const SKIP_FILE_SUFFIX = [
  /\.(test|spec)\.(ts|tsx)$/,
  /\.stories\.(ts|tsx)$/,
];

/**
 * Recursively collect TypeScript source files, respecting skip rules.
 */
function collectFiles(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      out.push(...collectFiles(fullPath));
      continue;
    }

    if (!SOURCE_EXTS.has(extname(entry.name))) continue;
    if (SKIP_FILE_SUFFIX.some((p) => p.test(entry.name))) continue;

    out.push(fullPath);
  }

  return out;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

// Additional roots scanned ONLY for FILE_RULES (import-boundary /
// scaffold-adherence checks). Per-line RULES are NOT applied here --
// module frontends carry a backlog of unrelated pre-existing findings
// (raw fetch, theme hex, double casts) that the shell audit was never
// wired to police, and turning them on wholesale would drown the SSE
// boundary check we actually care about here. When those backlogs are
// cleaned up the roots can move to the primary scan.
//
// Relative to process.cwd() -- when run via `pnpm --filter @aila/shell
// run honesty-audit` this is the frontend package dir, so ../src/aila
// resolves to the repo's Python + module tree.
const FILE_ONLY_ROOTS = [
  resolve(process.cwd(), "..", "src", "aila", "modules"),
];

function runFileRules(filePath) {
  const normalizedPath = filePath.replace(/\\/g, "/");
  let content;
  try {
    content = readFileSync(filePath, "utf8");
  } catch {
    return;
  }
  for (const rule of FILE_RULES) {
    if (!rule.fileMatch.test(normalizedPath)) continue;
    if (isWhitelisted(filePath, rule.id)) continue;
    if (rule.requireContent.test(content)) continue;
    findings.push({
      file: filePath,
      line: 1,
      rule: rule.id,
      snippet: rule.description,
    });
  }
}

const findings = [];
const files = collectFiles(rootDir);

for (const filePath of files) {
  const ext = extname(filePath);
  const normalizedPath = filePath.replace(/\\/g, "/");

  let content;
  try {
    content = readFileSync(filePath, "utf8");
  } catch {
    continue;
  }

  const lines = content.split(/\r?\n/);

  // File-level rules -- fire once per matching file when required
  // content is missing. Emits at line 1 so grouped output stays
  // scannable.
  for (const rule of FILE_RULES) {
    if (!rule.fileMatch.test(normalizedPath)) continue;
    if (isWhitelisted(filePath, rule.id)) continue;
    if (rule.requireContent.test(content)) continue;
    findings.push({
      file: filePath,
      line: 1,
      rule: rule.id,
      snippet: rule.description,
    });
  }

  for (const rule of RULES) {
    // Extension filter
    if (rule.extensions && !rule.extensions.includes(ext)) continue;

    // File-level skip
    if (rule.skipFile && rule.skipFile.test(normalizedPath)) continue;

    // Whitelist check at file+rule level
    if (isWhitelisted(filePath, rule.id)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!rule.pattern.test(line)) continue;
      if (rule.exclude && rule.exclude.test(line)) continue;

      findings.push({
        file: filePath,
        line: i + 1,
        rule: rule.id,
        snippet: line.trim().slice(0, 120),
      });
    }
  }
}

// File-only scan pass. Walks the additional roots (module frontends)
// and applies FILE_RULES only, so import-boundary checks fire against
// every module hook while the per-line RULES stay scoped to the
// primary root.
for (const root of FILE_ONLY_ROOTS) {
  if (!existsSync(root)) continue;
  for (const filePath of collectFiles(root)) {
    runFileRules(filePath);
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// Group by file for readable output, maintaining discovery order
const seen = new Set();
const fileOrder = [];
for (const f of findings) {
  if (!seen.has(f.file)) {
    seen.add(f.file);
    fileOrder.push(f.file);
  }
}

const byFile = new Map();
for (const f of findings) {
  if (!byFile.has(f.file)) byFile.set(f.file, []);
  byFile.get(f.file).push(f);
}

for (const filePath of fileOrder) {
  const relPath = relative(process.cwd(), filePath).replace(/\\/g, "/");
  for (const f of byFile.get(filePath)) {
    process.stdout.write(`${relPath}:${f.line}  [${f.rule}]  ${f.snippet}\n`);
  }
}

if (findings.length === 0) {
  process.stdout.write("honesty-audit: clean -- no findings\n");
  process.exit(0);
} else {
  process.stderr.write(
    `\nhonesty-audit: ${findings.length} finding(s) -- fix violations or add justified whitelist entries\n`
  );
  process.exit(1);
}
