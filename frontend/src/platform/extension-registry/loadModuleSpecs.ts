import { frontendSpec as forensicsSpec } from "@aila/forensics-frontend";
import { frontendSpec as helloWorldSpec } from "@aila/hello-world-frontend";
import { frontendSpec as vulnerabilitySpec } from "@aila/vulnerability-frontend";
import { frontendSpec as vrSpec } from "@aila/vr-frontend";

import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

const ALL_MODULE_SPECS: ReadonlyArray<ModuleFrontendSpec> = [
  forensicsSpec,
  helloWorldSpec,
  vulnerabilitySpec,
  vrSpec,
];

export function loadModuleFrontendSpecs(): ModuleFrontendSpec[] {
  return ALL_MODULE_SPECS.filter((spec): spec is ModuleFrontendSpec => Boolean(spec));
}
