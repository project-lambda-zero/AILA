import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

interface ModuleSpecFile {
  frontendSpec?: ModuleFrontendSpec;
}

const specModules = import.meta.glob<ModuleSpecFile>(
  "../../../../src/aila/modules/*/frontend/spec.ts",
  { eager: true },
);

export function loadModuleFrontendSpecs(): ModuleFrontendSpec[] {
  return Object.values(specModules)
    .map((moduleFile) => moduleFile.frontendSpec)
    .filter((spec): spec is ModuleFrontendSpec => Boolean(spec));
}
