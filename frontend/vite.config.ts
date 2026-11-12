import path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(currentDirectory, "..");

/**
 * Read version from package.json at config time. Falls back to "0.0.0"
 * if package.json is unreadable so vite never fails to start.
 */
function readPackageVersion(): string {
  try {
    const raw = readFileSync(path.resolve(currentDirectory, "package.json"), "utf8");
    const parsed = JSON.parse(raw) as { version?: string };
    return typeof parsed.version === "string" && parsed.version.length > 0 ? parsed.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * Best-effort short git SHA. Falls back to "dev" when git is unavailable
 * (e.g. tarball build, sandboxed CI). Never throws.
 */
function readBuildSha(): string {
  try {
    return execSync("git rev-parse --short=8 HEAD", {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
    }).trim() || "dev";
  } catch {
    return "dev";
  }
}

const appVersion = readPackageVersion();
const buildSha = readBuildSha();

/**
 * Named vendor chunks. Monaco is reachable only through the lazy CodeBlock
 * import, so its chunk, CSS, and workers never enter the entry document.
 *
 * `includeDependenciesRecursively: false` on every group stops a group from
 * claiming the imports of its members. Without it the Monaco group claimed
 * React core through `@monaco-editor/react`, and every eager chunk then
 * depended on the Monaco chunk.
 *
 * Regexes tolerate both POSIX `/` and Windows `\` separators because Vite
 * reports module ids with the host platform's path style.
 */
const vendorChunkGroups = [
  {
    name: "vendor-react",
    test: /[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/,
    priority: 2,
    includeDependenciesRecursively: false,
  },
  {
    name: "vendor-tanstack",
    test: /[\\/]node_modules[\\/]@tanstack[\\/]/,
    priority: 1,
    includeDependenciesRecursively: false,
  },
  {
    name: "vendor-monaco",
    test: /[\\/]node_modules[\\/](monaco-editor|@monaco-editor|state-local)[\\/]/,
    priority: 0,
    includeDependenciesRecursively: false,
  },
];

export default defineConfig({
  plugins: [react()],
  define: {
    // Compile-time substitutions for the app version and build SHA.
    // JSON.stringify wraps each value as a string literal so the
    // substitution is syntactically valid wherever the global is read.
    __APP_VERSION__: JSON.stringify(appVersion),
    __APP_BUILD_SHA__: JSON.stringify(buildSha),
  },
  resolve: {
    alias: [
      { find: /^@\//, replacement: path.resolve(currentDirectory, "src/") + "/" },
    ],
  },
  server: {
    host: "0.0.0.0",
    port: 3000,
    fs: {
      allow: [repoRoot],
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 4173,
  },
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: vendorChunkGroups,
        },
      },
    },
  },
});
