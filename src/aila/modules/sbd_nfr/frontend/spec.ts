import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

import { nav } from "./nav";
import { routes } from "./routes";

export const frontendSpec = {
  moduleId: "sbd_nfr",
  nav,
  routes,
} satisfies ModuleFrontendSpec;
