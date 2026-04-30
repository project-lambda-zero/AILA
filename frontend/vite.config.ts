import path from "node:path";
import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(currentDirectory, "..");
const nodeModulesRoot = path.resolve(currentDirectory, "node_modules");

export default defineConfig({
  plugins: [tailwindcss(), react()],
  resolve: {
    alias: [
      { find: /^@\//, replacement: path.resolve(currentDirectory, "src/") + "/" },
      { find: "@app", replacement: path.resolve(currentDirectory, "src/app") },
      { find: "@platform", replacement: path.resolve(currentDirectory, "src/platform") },
      {
        find: "@tanstack/react-query",
        replacement: path.resolve(nodeModulesRoot, "@tanstack/react-query/build/modern/index.js"),
      },
      {
        find: "@testing-library/react",
        replacement: path.resolve(
          nodeModulesRoot,
          "@testing-library/react/dist/@testing-library/react.esm.js",
        ),
      },
      {
        find: "@testing-library/user-event",
        replacement: path.resolve(nodeModulesRoot, "@testing-library/user-event/dist/esm/index.js"),
      },
      { find: /^react$/, replacement: path.resolve(nodeModulesRoot, "react/index.js") },
      {
        find: /^react\/jsx-runtime$/,
        replacement: path.resolve(nodeModulesRoot, "react/jsx-runtime.js"),
      },
      { find: /^react-dom$/, replacement: path.resolve(nodeModulesRoot, "react-dom/index.js") },
      {
        find: /^react-dom\/client$/,
        replacement: path.resolve(nodeModulesRoot, "react-dom/client.js"),
      },
      {
        find: /^react-router-dom$/,
        replacement: path.resolve(nodeModulesRoot, "react-router-dom/dist/index.mjs"),
      },
    ],
    dedupe: ["react", "react-dom", "react-router-dom", "@tanstack/react-query"],
  },
  server: {
    host: "0.0.0.0",
    port: 3000,
    fs: {
      allow: [repoRoot],
    },
    // No Vite proxy — frontend uses absolute API URL (VITE_AILA_API_BASE_URL
    // or default http://127.0.0.1:8000). Backend CORS allows frontend origin.
    // Path-based proxies conflict with SPA routes (e.g. /systems is both a
    // frontend route and an API endpoint).
  },
  preview: {
    host: "0.0.0.0",
    port: 4173,
  },
});
