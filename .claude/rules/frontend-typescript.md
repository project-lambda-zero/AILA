# AILA Frontend TypeScript Rules

These extend the global TypeScript rules with AILA-specific guidance.

## Type imports

Group imports as:
1. External (npm packages)
2. Workspace (`@aila/*`)
3. Path-aliased internal (`@/`, `@app/`, `@platform/`)
4. Relative (`./`, `../`)

Use `import type` for type-only imports — they're erased at build time and prevent cycles.

## Strict mode is non-negotiable

The shared `@aila/typescript-config/base` enables `strict: true`. NEVER:
- Use `as any`
- Use `@ts-ignore` or `@ts-expect-error` without an inline justification comment explaining the specific TS limitation
- Loosen `strict` flags in a module's tsconfig (only the shared base controls them)

Prefer `unknown` over `any` for genuinely unknown types and narrow with type guards.

## Path aliases

| Alias        | Resolves to                       | When to use                                    |
|--------------|-----------------------------------|------------------------------------------------|
| `@/*`        | `frontend/src/*`                  | Shell-side absolute imports                    |
| `@app/*`     | `frontend/src/app/*`              | Shell app shell, routing, error boundaries    |
| `@platform/*`| `frontend/src/platform/*`         | Design system, extension registry, layout      |

Modules use the same aliases — they resolve into the shell (their consumer) at build time. Module-local imports use relative paths (`./components/Foo`).

## Module spec exports

Every module's `spec.ts` MUST export a `frontendSpec` const typed as `ModuleFrontendSpec`:

```ts
import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

export const frontendSpec: ModuleFrontendSpec = {
  // ...
};
```

Default exports are forbidden — the shell's registry imports `{ frontendSpec }` by name.

## React patterns

- Functional components only. No class components.
- Hooks-based state (`useState`, `useReducer`, `useContext`, or `zustand`). Avoid prop drilling beyond 2 levels.
- For data: `@tanstack/react-query` is the canonical async-state library. Don't manually wire `useEffect` + `useState` for fetches.
- For forms: use whatever the shell provides (currently uncontrolled refs / native form). No new form libraries without an ADR.

## Storybook

- Stories live next to components: `Foo.tsx` → `Foo.stories.tsx`.
- Use `@storybook/react` for `Meta` and `StoryObj` types.
- For interaction tests, import `expect`, `userEvent`, `within` from `storybook/test`.
- A module that adds stories must declare `@storybook/react` and `@storybook/react-vite` in its `devDependencies`.

## Vitest

- Test files end in `.test.ts(x)` or `.spec.ts(x)`.
- For DOM tests: import `@testing-library/jest-dom` matchers via the shell's `setup.ts`. Module test types come from the shared `react-module` tsconfig which already includes `@testing-library/jest-dom` types.
- A module that adds tests must declare `vitest`, `@testing-library/react`, `@testing-library/jest-dom`, `@testing-library/user-event` in its `devDependencies`.

## Forbidden imports

- `react-router-dom` — use `react-router` (v7 unified them)
- Direct paths into `node_modules/...` — let the resolver handle it
- Relative paths that climb out of a module (`../../../../../frontend/src/...`) — use `@/`, `@app/`, or `@platform/` aliases instead

## Honesty audit (frontend side)

`frontend/src/tools/honesty-audit.js` runs against shell source. The whitelist is at `frontend/honesty_whitelist.js`. Add a justification when you must suppress a finding; never add inline `// audit-ignore` style comments.
