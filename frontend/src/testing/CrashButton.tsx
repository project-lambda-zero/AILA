/**
 * CrashButton / CrashNow — test-only component used by 176a-03 e2e to exercise
 * AppErrorBoundary placement (D-23 / T-176a-02-02).
 *
 * Gated at the router level via `import.meta.env.DEV` (preflight FE-H) so it
 * is NEVER included in production bundles. Throws on mount AND on click so
 * both automated smoke and manual smoke paths can trigger the boundary.
 */

export function CrashNow(): never {
  throw new Error("CrashNow: intentional test crash (on mount)");
}

export function CrashButton() {
  return (
    <button
      type="button"
      onClick={() => {
        throw new Error("CrashButton: intentional test crash (on click)");
      }}
      className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover"
      data-testid="crash-button"
    >
      Crash now
    </button>
  );
}
