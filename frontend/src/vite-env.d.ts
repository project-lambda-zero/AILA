/// <reference types="vite/client" />

// Compile-time substitutions injected by `vite.config.ts` via `define`.
// Centralized read in `platform/config/version.ts` — never read directly.
declare const __APP_VERSION__: string;
declare const __APP_BUILD_SHA__: string;