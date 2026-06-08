import path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

import tailwindcss from "@tailwindcss/vite";
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
 * C14 — partition vendor code into deterministic chunks. Without this,
 * Rollup packs every eager import into a single 1.7 MB+ index chunk.
 * The partitions chosen below match the PRD §C 14 acceptance criteria:
 * react/react-router/@tanstack/recharts/@phosphor-icons each get their
 * own bundle so a route change that only needs (say) recharts can fetch
 * just that chunk, not re-download react with it.
 *
 * Regex tolerates both POSIX `/` and Windows `\` separators because
 * Vite reports module ids with the host platform's path style.
 * Order matters — first match wins, so more specific patterns first.
 */
function manualChunks(id: string): string | undefined {
  if (!id.includes("node_modules")) {
    return undefined;
  }
  if (/[\\/]node_modules[\\/](react|react-dom|scheduler|react-is)[\\/]/.test(id)) {
    return "vendor-react";
  }
  if (/[\\/]node_modules[\\/]react-router[\\/]/.test(id)) {
    return "vendor-router";
  }
  if (/[\\/]node_modules[\\/]@tanstack[\\/]/.test(id)) {
    return "vendor-tanstack";
  }
  if (/[\\/]node_modules[\\/]@phosphor-icons[\\/]/.test(id)) {
    return "vendor-phosphor";
  }
  if (/[\\/]node_modules[\\/](recharts|d3-[a-z-]+|victory-vendor)[\\/]/.test(id)) {
    return "vendor-recharts";
  }
  if (/[\\/]node_modules[\\/]@xyflow[\\/]/.test(id)) {
    return "vendor-xyflow";
  }
  if (/[\\/]node_modules[\\/]motion[\\/]/.test(id)) {
    return "vendor-motion";
  }
  if (/[\\/]node_modules[\\/](monaco-editor|@monaco-editor)[\\/]/.test(id)) {
    return "vendor-monaco";
  }
  if (/[\\/]node_modules[\\/](leaflet|react-leaflet)[\\/]/.test(id)) {
    return "vendor-leaflet";
  }
  if (/[\\/]node_modules[\\/]@base-ui[\\/]/.test(id)) {
    return "vendor-base-ui";
  }
  if (/[\\/]node_modules[\\/](html2canvas|papaparse|jszip)[\\/]/.test(id)) {
    return "vendor-data";
  }
  return undefined;
}

export default defineConfig({
  plugins: [tailwindcss(), react()],
  define: {
    // Compile-time substitutions read in `platform/config/version.ts`.
    // JSON.stringify wraps each value as a string literal so the
    // substitution is syntactically valid wherever the global is read.
    __APP_VERSION__: JSON.stringify(appVersion),
    __APP_BUILD_SHA__: JSON.stringify(buildSha),
  },
  optimizeDeps: {
    include: ["ogl", "@monaco-editor/react", "monaco-editor"],
  },
  resolve: {
    alias: [
      { find: /^@\//, replacement: path.resolve(currentDirectory, "src/") + "/" },
      { find: "@app", replacement: path.resolve(currentDirectory, "src/app") },
      { find: "@platform", replacement: path.resolve(currentDirectory, "src/platform") },
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
    rollupOptions: {
      output: {
        manualChunks,
      },
    },
  },
});
