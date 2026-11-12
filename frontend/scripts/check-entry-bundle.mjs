// Production-build gate (issue #363). Monaco's JavaScript, stylesheet, and language
// workers must not appear in the entry document or in the JavaScript it loads eagerly
// (its scripts and modulepreloads, plus their static imports); they load only when a
// code surface imports the lazy CodeBlock.
// Usage: node scripts/check-entry-bundle.mjs [distDir]   (default: ../dist)
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const distDir = path.resolve(
  process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist"),
);

// Chunk names come from the `vendor-monaco` group in vite.config.ts. monaco-editor
// emits its language workers as `<language>.worker-<hash>.js`.
const MONACO_NAME = /monaco/i;
const MONACO_WORKER = /\.worker-[^/]+\.js$/;
const MONACO_CHUNK = /^vendor-monaco-[^/]+\.js$/;

const HTML_ELEMENT = /<(script|link)\b([^>]*)>/gi;
const HTML_ATTRIBUTE = /([\w-]+)(?:\s*=\s*"([^"]*)")?/g;
// Static `import ... from`, `import "..."`, and `export ... from` specifiers. A dynamic
// `import(...)` has no quote after the keyword, so lazy chunks are never followed.
const STATIC_SPECIFIER = /(?<![\w$.])(?:import|export)(?![\w$])(?:[^'"`;()]*?\bfrom)?\s*["']([^"'\n]+)["']/g;

function isMonacoAsset(name) {
  return MONACO_NAME.test(name) || MONACO_WORKER.test(name);
}

function htmlAttributes(raw) {
  return Object.fromEntries(
    [...raw.matchAll(HTML_ATTRIBUTE)].map(([, name, value = ""]) => [name.toLowerCase(), value]),
  );
}

function relativeSpecifiers(source) {
  return [...source.matchAll(STATIC_SPECIFIER)]
    .map(([, specifier]) => specifier)
    .filter((specifier) => specifier.startsWith("./") || specifier.startsWith("../"));
}

function checkEntryBundle(dir) {
  const indexPath = path.join(dir, "index.html");
  if (!existsSync(indexPath)) {
    return { violations: [`${indexPath} not found; run vite build first`], closure: [] };
  }

  const violations = [];
  const roots = [];
  let hasModuleEntry = false;
  for (const [, tag, raw] of readFileSync(indexPath, "utf8").matchAll(HTML_ELEMENT)) {
    const element = tag.toLowerCase();
    const attributes = htmlAttributes(raw);
    const ref = attributes.href ?? attributes.src;
    if (ref === undefined) continue;
    // The browser fetches every script and modulepreload on page load; a modulepreload
    // also fetches its static import graph, so each one is a traversal root. A Monaco
    // reference is reported here and not traversed, so it is never reported twice.
    const isModulePreload =
      element === "link" && (attributes.rel ?? "").toLowerCase().split(/\s+/).includes("modulepreload");
    if (isMonacoAsset(ref)) {
      violations.push(`index.html references ${ref} from <${tag}>`);
    } else if (element === "script" || isModulePreload) {
      roots.push(ref);
    }
    if (element === "script" && attributes.type === "module") hasModuleEntry = true;
  }
  if (!hasModuleEntry) violations.push("index.html has no module entry script");

  const queue = roots.map((ref) => ({ file: ref.replace(/^\//, ""), importer: "index.html" }));
  const visited = new Set();
  const closure = [];
  for (let i = 0; i < queue.length; i += 1) {
    const { file, importer } = queue[i];
    if (visited.has(file)) continue;
    visited.add(file);
    if (isMonacoAsset(file)) {
      violations.push(`${importer} statically imports ${file}`);
      continue;
    }
    const absolute = path.join(dir, file);
    if (!existsSync(absolute)) {
      violations.push(`${importer} references missing ${file}`);
      continue;
    }
    closure.push(file);
    for (const specifier of relativeSpecifiers(readFileSync(absolute, "utf8"))) {
      queue.push({ file: path.posix.join(path.posix.dirname(file), specifier), importer: file });
    }
  }

  // Without this, renaming or dropping the Monaco group would pass the gate vacuously.
  const assetsDir = path.join(dir, "assets");
  const monacoEmitted =
    existsSync(assetsDir) && readdirSync(assetsDir).some((name) => MONACO_CHUNK.test(name));
  if (!monacoEmitted) violations.push("no vendor-monaco chunk emitted; the lazy editor is missing or renamed");

  return { violations, closure };
}

const { violations, closure } = checkEntryBundle(distDir);
if (violations.length > 0) {
  console.error(`entry bundle check failed for ${distDir}:`);
  for (const violation of violations) console.error(`  - ${violation}`);
  process.exitCode = 1;
} else {
  console.log(
    `entry bundle check passed: ${closure.length} static chunk(s), no Monaco asset in index.html or the entry import graph`,
  );
}
