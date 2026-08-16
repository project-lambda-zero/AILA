/*
 * Flash-free theme init (#47).
 *
 * Runs synchronously before React mounts so the correct theme class is on
 * <html> before first paint. Extracted from an inline <script> so the SPA
 * can be served under a strict CSP (`script-src 'self'`).
 *
 * AILA ships a single canonical design -- "midnight-cloud-8" (dark). The
 * former multi-theme switcher was removed; this script pins the one theme
 * and keeps the localStorage keys coherent for any legacy reader.
 */
(function () {
  var el = document.documentElement;
  el.setAttribute("data-theme", "midnight-cloud-8");
  el.setAttribute("data-mode", "dark");
  el.classList.add("dark");
  try {
    localStorage.setItem("aila-theme", "midnight-cloud-8");
    localStorage.setItem("aila-mode", "dark");
  } catch (e) {
    /* private-mode / disabled storage -- attributes above still applied */
  }
})();
