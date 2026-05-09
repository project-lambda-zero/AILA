import path from "node:path";
import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(currentDirectory, "..");

export default defineConfig({
  plugins: [tailwindcss(), react()],
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
});
