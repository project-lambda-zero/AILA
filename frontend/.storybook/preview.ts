import type { Preview } from "@storybook/react";
import { withThemeByClassName } from "@storybook/addon-themes";
import "../src/styles/globals.css";

const preview: Preview = {
  decorators: [
    withThemeByClassName({
      themes: {
        dark: "dark",
        light: "",
      },
      defaultTheme: "dark",
    }),
  ],
  parameters: {
    backgrounds: {
      default: "dark",
      values: [
        { name: "dark", value: "#131313" },
        { name: "light", value: "#fafaf9" },
      ],
    },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
};

export default preview;
