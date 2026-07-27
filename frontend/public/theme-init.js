/*
 * Flash-free theme init (#47).
 *
 * Runs synchronously before React mounts so the correct theme + mode
 * class is on <html> before the first paint. Extracted from the inline
 * <script> block in index.html so the SPA can be served under a
 * strict Content-Security-Policy (`script-src 'self'`) without an
 * `unsafe-inline` allowance or a fragile sha256- hash of the inline
 * body.
 *
 * Twelve themes are valid. Invalid / legacy stored values fall back
 * to 'midnight-cloud-8' (default).
 */
(function () {
  var valid = [
    "midnight-cloud-8",
    "frutiger-aero",
    "synthwave",
    "vaporwave",
    "ps1",
    "ps2",
    "cyberpunk-2077",
    "matrix",
    "truman-show",
    "half-life-1",
    "y2k-fever",
    "vendetta",
    "specimen-index",
  ];
  var light = [
    "frutiger-aero",
    "ps1",
    "truman-show",
    "y2k-fever",
    "specimen-index",
  ];
  var stored = localStorage.getItem("aila-theme");
  var theme = valid.indexOf(stored) !== -1 ? stored : "midnight-cloud-8";
  if (stored !== theme) localStorage.setItem("aila-theme", theme);
  var storedMode = localStorage.getItem("aila-mode");
  var mode =
    storedMode === "dark" || storedMode === "light"
      ? storedMode
      : light.indexOf(theme) !== -1
        ? "light"
        : "dark";
  if (storedMode !== mode) localStorage.setItem("aila-mode", mode);
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.setAttribute("data-mode", mode);
  if (mode === "dark") document.documentElement.classList.add("dark");
})();
