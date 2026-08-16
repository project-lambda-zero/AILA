/**
 * AILA service worker -- SELF-DESTRUCT.
 *
 * The previous frontend registered a caching service worker. The new
 * windowing-desktop build does not use one. Browsers re-fetch sw.js on every
 * navigation (bypassing the HTTP cache), so this replacement runs in any tab
 * that still has the old worker installed: it clears every Cache Storage entry,
 * unregisters itself, and reloads controlled tabs so they pick up the fresh app.
 */
self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      try {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      } catch {
        /* cache API unavailable -- nothing to purge */
      }
      try {
        await self.registration.unregister();
      } catch {
        /* already gone */
      }
      const clients = await self.clients.matchAll({ type: "window" });
      for (const client of clients) {
        try {
          client.navigate(client.url);
        } catch {
          /* client cannot be navigated */
        }
      }
    })(),
  );
});

// Never intercept fetches -- always go to network.
self.addEventListener("fetch", () => {});
