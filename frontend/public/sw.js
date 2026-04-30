/**
 * AILA Service Worker — offline GET cache (UX-07).
 *
 * Strategy: Network-first for all API GET requests.
 * On network failure, serve from Cache API with last-known response.
 * Only caches GET requests matching the backend API origin.
 *
 * Cache scope: requests to localhost:8000 or 127.0.0.1:8000 (dev backend).
 * Production deployments should update API_PATTERN to match the deployed origin.
 */

const CACHE_NAME = "aila-api-cache-v1";
const API_PATTERN = /https?:\/\/(?:localhost|127\.0\.0\.1):8000\//;

self.addEventListener("install", (event) => {
  // Activate immediately — don't wait for old SW to die
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  // Claim all clients immediately
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      // Prune old cache versions
      caches.keys().then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((key) => caches.delete(key)),
        ),
      ),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;

  // Only intercept GET requests to the backend API
  if (request.method !== "GET") return;
  if (!API_PATTERN.test(request.url)) return;

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          // Clone before consuming — cache the successful response
          const cloned = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            // Store with last-sync timestamp header injected
            const headers = new Headers(cloned.headers);
            headers.set("X-Cache-Time", new Date().toISOString());
            cloned.blob().then((body) => {
              const cachedResponse = new Response(body, {
                status: cloned.status,
                statusText: cloned.statusText,
                headers,
              });
              cache.put(request, cachedResponse);
            });
          });
        }
        return response;
      })
      .catch(async () => {
        // Network failed — try cache
        const cached = await caches.match(request);
        if (cached) {
          return cached;
        }
        // Nothing cached — return a 503 JSON error
        return new Response(
          JSON.stringify({ error: "offline", detail: "No cached response available." }),
          {
            status: 503,
            headers: { "Content-Type": "application/json" },
          },
        );
      }),
  );
});
