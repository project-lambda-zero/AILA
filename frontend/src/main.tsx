import React from "react";
import ReactDOM from "react-dom/client";

import "@/styles/globals.css";
import { App } from "@app/App";

// Register service worker for offline GET cache (UX-07)
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch((err) => {
      // SW registration failure is non-fatal -- app still works online
      console.warn("[SW] Registration failed:", err);
    });
  });
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
