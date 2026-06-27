/**
 * Build-time identity for the SPA. Both values are injected by Vite's
 * `define` hook at config time (see `frontend/vite.config.ts`):
 *
 *   __APP_VERSION__   -- `version` field of `frontend/package.json`
 *   __APP_BUILD_SHA__ -- `git rev-parse --short=8 HEAD`, or `"dev"` when
 *                       git is unavailable (sandboxed CI, tarball build)
 *
 * Read these here, not from `import.meta.env` directly, so the honesty
 * audit's `direct_env_access` rule stays clean and consumers have one
 * canonical import.
 */
export const appVersion: string = __APP_VERSION__;
export const buildSha: string = __APP_BUILD_SHA__;

/**
 * Composite identifier suitable for an unobtrusive footer or "about"
 * dialog. `0.1.0 · a1b2c3d4` when both are present; falls back to the
 * version alone if SHA wasn't resolvable.
 */
export const buildIdentity: string =
  buildSha === "dev" || buildSha.length === 0 ? appVersion : `${appVersion} · ${buildSha}`;
