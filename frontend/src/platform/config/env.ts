const rawApiBaseUrl = import.meta.env.VITE_AILA_API_BASE_URL?.trim();

function normalizeBaseUrl(value: string | undefined): string {
  if (!value) {
    // Derive from the current window hostname so the app works from any IP
    // (localhost, 192.168.8.5, etc.) without needing VITE_AILA_API_BASE_URL.
    // In production: set VITE_AILA_API_BASE_URL to the actual backend origin.
    if (typeof window !== "undefined") {
      return `${window.location.protocol}//${window.location.hostname}:8000`;
    }
    return "http://127.0.0.1:8000";
  }
  return value.replace(/\/+$/, "");
}

export const appEnv = {
  apiBaseUrl: normalizeBaseUrl(rawApiBaseUrl),
};
