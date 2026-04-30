import path from "path";
import { fileURLToPath } from "url";
import type { StorybookConfig } from "@storybook/react-vite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(frontendRoot, "..");

const config: StorybookConfig = {
  stories: [
    "../src/**/*.stories.@(ts|tsx)",
    "../../src/aila/modules/**/frontend/**/*.stories.@(ts|tsx)",
  ],
  addons: [
    "@storybook/addon-a11y",
    "@storybook/addon-themes",
  ],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  viteFinal: async (config) => {
    const { mergeConfig } = await import("vite");
    const { default: tailwindcss } = await import("@tailwindcss/vite");
    return mergeConfig(config, {
      plugins: [tailwindcss()],
      resolve: {
        alias: [
          { find: /^@\//, replacement: path.resolve(frontendRoot, "src") + "/" },
          { find: "@platform", replacement: path.resolve(frontendRoot, "src/platform") },
          { find: "@app", replacement: path.resolve(frontendRoot, "src/app") },
        ],
      },
      server: {
        fs: { allow: [repoRoot] },
      },
    });
  },
};

export default config;
