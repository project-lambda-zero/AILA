import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

/**
 * Dynamic frontend-spec discovery (#41).
 *
 * Prior versions hardcoded a `import { frontendSpec as ... } from "@aila/..."`
 * list. That coupled the shell build to every module's package being present:
 * removing a module directory or its workspace symlink broke the whole SPA
 * build with an unresolved-import error. The list was also the wrong place
 * to add a new module -- authors had to remember to touch both the module's
 * frontend package AND this file.
 *
 * The new discovery is a filesystem glob evaluated by Vite at build time:
 * every module ships its `frontend/spec.ts` inside its own package directory
 * (per FRONTEND_MODULE_STANDARD), and this loader picks them up. Consequences:
 *
 * * Missing / uninstalled modules simply do not contribute a spec instead of
 *   failing the shell build.
 * * Adding a module is one edit -- create `<module>/frontend/spec.ts`.
 * * The shell never names a module id at all; it walks whatever it finds.
 *
 * `import.meta.glob` requires a static string literal so Vite can pre-scan
 * the filesystem. It also honours `server.fs.allow`, which is set to the
 * repo root in `vite.config.ts`, so the `../../../../` traversal is legal.
 */
const MODULE_SPEC_GLOB = import.meta.glob<Record<string, unknown>>(
  "../../../../src/aila/modules/*/frontend/spec.ts",
  { eager: true },
);

// Type guard preserves narrowing at the call site so downstream code sees
// each discovered candidate as a fully-typed ModuleFrontendSpec.
function isModuleFrontendSpec(value: unknown): value is ModuleFrontendSpec {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const candidate = value as { moduleId?: unknown };
  return typeof candidate.moduleId === "string" && candidate.moduleId.length > 0;
}

// Discover once at bundle time. `eager: true` above gives us the imported
// module objects synchronously, so this is a plain top-level array.
const DISCOVERED_SPECS: ReadonlyArray<ModuleFrontendSpec> = (() => {
  const specs: ModuleFrontendSpec[] = [];
  const seenModuleIds = new Set<string>();
  // Iterate in deterministic order so downstream slot ordering is stable
  // across platforms (filesystem iteration order is not guaranteed).
  for (const path of Object.keys(MODULE_SPEC_GLOB).sort()) {
    const candidate = MODULE_SPEC_GLOB[path]?.frontendSpec;
    if (!isModuleFrontendSpec(candidate)) {
      console.warn(
        `[loadModuleFrontendSpecs] Skipping ${path}: no valid \`frontendSpec\` export.`,
      );
      continue;
    }
    if (seenModuleIds.has(candidate.moduleId)) {
      console.warn(
        `[loadModuleFrontendSpecs] Duplicate moduleId "${candidate.moduleId}" at ${path} -- keeping first, ignoring this one.`,
      );
      continue;
    }
    seenModuleIds.add(candidate.moduleId);
    specs.push(candidate);
  }
  return specs;
})();

export function loadModuleFrontendSpecs(): ModuleFrontendSpec[] {
  return DISCOVERED_SPECS.slice();
}
