import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "check-entry-bundle.mjs");

// Synthetic dist fixtures: keys are paths under the dist root.
function writeDist(root, files) {
  for (const [relative, content] of Object.entries(files)) {
    const absolute = path.join(root, relative);
    mkdirSync(path.dirname(absolute), { recursive: true });
    writeFileSync(absolute, content);
  }
  return root;
}

function entryDocument(head) {
  return `<!doctype html><html><head>${head}<script type="module" crossorigin src="/assets/index-a.js"></script></head><body><div id="root"></div></body></html>`;
}

function runCheck(distDir) {
  return spawnSync(process.execPath, [SCRIPT, distDir], { encoding: "utf8" });
}

describe("check-entry-bundle", () => {
  let root;

  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), "entry-bundle-"));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("passes when Monaco is reached only through a dynamic import", () => {
    const dist = writeDist(root, {
      "index.html": entryDocument('<link rel="modulepreload" crossorigin href="/assets/vendor-react-r.js">'),
      "assets/index-a.js": 'import { r } from "./vendor-react-r.js";\nimport("./CodeBlock-c.js");\nexport { r };\n',
      "assets/vendor-react-r.js": "export const r = 1;\n",
      "assets/CodeBlock-c.js": 'import "./vendor-monaco-m.js";\nexport default 1;\n',
      "assets/vendor-monaco-m.js": "export const m = 1;\n",
    });

    const result = runCheck(dist);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it("fails when the entry document module-preloads the Monaco chunk", () => {
    const dist = writeDist(root, {
      "index.html": entryDocument('<link rel="modulepreload" crossorigin href="/assets/vendor-monaco-m.js">'),
      "assets/index-a.js": "export {};\n",
      "assets/vendor-monaco-m.js": "export const m = 1;\n",
    });

    const result = runCheck(dist);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("vendor-monaco-m.js");
  });

  it("fails when a chunk the entry document module-preloads statically imports the Monaco chunk", () => {
    const dist = writeDist(root, {
      "index.html": entryDocument('<link rel="modulepreload" crossorigin href="/assets/shared-p.js">'),
      "assets/index-a.js": "export {};\n",
      "assets/shared-p.js": 'import "./vendor-monaco-m.js";\nexport const p = 1;\n',
      "assets/vendor-monaco-m.js": "export const m = 1;\n",
    });

    const result = runCheck(dist);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("shared-p.js");
    expect(result.stderr).toContain("vendor-monaco-m.js");
  });

  it("fails when the entry document links the Monaco stylesheet", () => {
    const dist = writeDist(root, {
      "index.html": entryDocument('<link rel="stylesheet" crossorigin href="/assets/vendor-monaco-m.css">'),
      "assets/index-a.js": "export {};\n",
      "assets/vendor-monaco-m.js": "export const m = 1;\n",
    });

    const result = runCheck(dist);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("vendor-monaco-m.css");
  });

  it("fails when the entry's static import graph reaches the Monaco chunk", () => {
    const dist = writeDist(root, {
      "index.html": entryDocument(""),
      "assets/index-a.js": 'import { m } from "./vendor-monaco-m.js";\nexport { m };\n',
      "assets/vendor-monaco-m.js": "export const m = 1;\n",
    });

    const result = runCheck(dist);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("vendor-monaco-m.js");
  });

  it("fails when no Monaco chunk is emitted, so a renamed group cannot pass vacuously", () => {
    const dist = writeDist(root, {
      "index.html": entryDocument(""),
      "assets/index-a.js": "export {};\n",
    });

    const result = runCheck(dist);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("vendor-monaco");
  });
});
