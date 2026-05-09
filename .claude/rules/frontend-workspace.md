# AILA Frontend Workspace Rules

The frontend is a pnpm workspace at the repo root. Every module's frontend is its own workspace package; the shell consumes them as `workspace:*` deps and bundles into a single SPA.

## Package layout

| Package                          | Path                                       | Type   |
|----------------------------------|--------------------------------------------|--------|
| `@aila/shell`                    | `frontend/`                                | App    |
| `@aila/typescript-config`        | `packages/typescript-config/`              | Config |
| `@aila/<module>-frontend`        | `src/aila/modules/<module>/frontend/`      | Module |

Module package names use kebab-case: `hello_world` → `@aila/hello-world-frontend`. The conversion is `s/_/-/g`.

## Hard rules

### 1. Every bare import declared in package.json
A module's source can only import packages that appear in that module's `package.json` `dependencies`, `peerDependencies`, or `devDependencies`. pnpm strict mode (`strict-peer-dependencies=true` in `.npmrc`) enforces this at install time — install fails if a module imports a package it didn't declare.

When adding a new bare import, ALSO add the dep to the module's `package.json` and run `pnpm install` before committing.

### 2. No cross-module imports
A module MUST NOT import from another `@aila/<module>-frontend` package. Cross-module communication goes through the shell's extension registry (`frontend/src/platform/extension-registry/`).

### 3. Catalogs over literal versions
Shared deps reference pnpm catalogs, never literal versions:

```jsonc
// CORRECT
{
  "peerDependencies": {
    "react": "catalog:react19",
    "@tanstack/react-query": "catalog:query"
  }
}

// WRONG
{
  "peerDependencies": {
    "react": "^19.2.4"
  }
}
```

Module-specific deps may use literals only if they're truly used by ONE module. As soon as a second consumer appears, promote the version into a catalog group in `pnpm-workspace.yaml`.

### 4. Framework deps are peerDependencies, not direct deps
Modules declare `react`, `react-dom`, `react-router`, `@tanstack/react-query`, and any shell-owned design-system package (`@phosphor-icons/react`, `motion`, `sonner`, etc.) as `peerDependencies`. The shell provides the single canonical copy. Direct deps would create duplicate React instances and break rules-of-hooks.

### 5. Module-specific deps are direct dependencies
Packages that only one module uses (e.g., `@dnd-kit/*` for vulnerability, `@xyflow/react` for sbd_nfr) live in that module's `dependencies`. The shell does NOT carry them.

### 6. Dev/test deps are devDependencies
`@testing-library/*`, `@storybook/*`, `vitest` go in `devDependencies` of each module that uses them.

### 7. tsconfig extends shared config
Every module's `tsconfig.json`:

```json
{
  "extends": "@aila/typescript-config/react-module",
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["../../../../../frontend/src/*"],
      "@app/*": ["../../../../../frontend/src/app/*"],
      "@platform/*": ["../../../../../frontend/src/platform/*"]
    }
  },
  "include": ["**/*.ts", "**/*.tsx"]
}
```

The shell uses `@aila/typescript-config/react-vite` (includes `vite/client` types). Modules use `react-module` (includes vite/client because they transitively consume shell code that uses `import.meta.env`).

### 8. Module package.json shape
Every module's `package.json`:

```json
{
  "name": "@aila/<module>-frontend",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "./spec.ts",
  "types": "./spec.ts",
  "exports": { ".": "./spec.ts" },
  "scripts": {
    "type-check": "tsc --noEmit",
    "test": "vitest run",
    "clean": "rm -rf node_modules"
  },
  "dependencies": { /* module-specific runtime deps via catalog refs */ },
  "peerDependencies": { /* shell-owned deps via catalog refs */ },
  "devDependencies": {
    "@aila/typescript-config": "workspace:*",
    "@types/react": "catalog:react19",
    "typescript": "catalog:"
    /* plus test deps if applicable */
  }
}
```

Modules ship as TS source (no build step). Vite handles them through workspace symlinks.

### 9. Shell registers modules by name
`frontend/src/platform/extension-registry/loadModuleSpecs.ts` imports each module's `frontendSpec` by package name:

```ts
import { frontendSpec as forensicsSpec } from "@aila/forensics-frontend";
import { frontendSpec as helloWorldSpec } from "@aila/hello-world-frontend";
// etc.
```

When adding a new module, add a named import here AND add the workspace dep in `frontend/package.json`.

### 10. react-router, not react-router-dom
React Router v7 unified the two packages. The codebase canonicalizes on `react-router`. Never import from `react-router-dom`.

## Anti-patterns

### Adding a dep to the shell to "make it available everywhere"
WRONG. If only one module uses it, declare it in that module's `package.json`. The shell only carries deps it itself imports.

### Editing `pnpm-lock.yaml` by hand
WRONG. Always re-run `pnpm install`. A hand-edited lockfile silently corrupts resolution.

### Using `npm` or `yarn`
WRONG. The repo is a pnpm workspace. Mixing tools breaks the symlink layout and the catalog system.

## Adding a new module's frontend

1. Create `src/aila/modules/<name>/frontend/package.json` (use hello_world as template)
2. Create `src/aila/modules/<name>/frontend/tsconfig.json` extending the shared config
3. Create `spec.ts` exporting `frontendSpec: ModuleFrontendSpec`
4. Add `"@aila/<name>-frontend": "workspace:*"` to `frontend/package.json` deps
5. Import the spec in `frontend/src/platform/extension-registry/loadModuleSpecs.ts`
6. Run `pnpm install` to wire symlinks
7. Verify: `pnpm -r run type-check && pnpm dev`

## Adding a dep to an existing module

```bash
# Module-specific dep:
pnpm add <pkg> --filter @aila/<module>-frontend

# Shared dep (must exist in a catalog already):
# Edit module's package.json directly, add "<pkg>": "catalog:<group>"
# Then: pnpm install

# Bumping a shared version:
# Edit pnpm-workspace.yaml catalog entry, then: pnpm install
```

After adding, re-run `pnpm install` (strict mode will reject undeclared imports).
