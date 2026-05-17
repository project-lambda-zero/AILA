import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

import { nav } from "./nav";
import { routes } from "./routes";
import { widgets } from "./widgets";

export const frontendSpec = {
  moduleId: "vr",
  nav,
  routes,
  widgets,
} satisfies ModuleFrontendSpec;
