import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["src/testSetup.ts"],
    include: ["src/**/*.test.tsx", "src/**/*.test.ts", "scripts/**/*.test.mjs"],
  },
});
