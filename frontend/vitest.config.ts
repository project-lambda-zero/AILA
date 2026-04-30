import { mergeConfig } from "vite";
import { defineConfig } from "vitest/config";

import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      clearMocks: true,
      restoreMocks: true,
      mockReset: true,
      include: [
        "src/**/*.{test,spec}.{ts,tsx}",
        "../src/aila/modules/*/frontend/**/*.{test,spec}.{ts,tsx}",
      ],
      coverage: {
        provider: "v8",
        reporter: ["text", "json", "html"],
        reportsDirectory: "./coverage",
        include: [
          "src/hooks/**",
          "src/platform/features/radar/topologyUtils.ts",
          "src/platform/features/viz/useChartExport.ts",
        ],
        exclude: [
          "src/**/*.stories.tsx",
          "src/test/**",
          "src/**/*.d.ts",
          "src/vite-env.d.ts",
          // useSSE has a deeply async streaming loop (fetch + ReadableStream) that
          // requires a live SSE server to exercise. Its branch coverage is provided
          // by E2E tests (tests/e2e/notifications/sse-endpoint.spec.ts), not unit tests.
          "src/hooks/useSSE.ts",
        ],
        thresholds: {
          lines: 80,
          branches: 70,
          functions: 80,
        },
      },
    },
  }),
);
