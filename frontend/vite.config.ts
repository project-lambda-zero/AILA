import path from "node:path";
import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(currentDirectory, "..");

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
