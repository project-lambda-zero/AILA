import { useEffect, useRef, useState } from "react";

import { Link, useNavigate, useSearchParams } from "react-router";

import { exchangeOidcCode } from "@platform/api/auth";
import { useAuthStore } from "@platform/auth/useAuthStore";

/**
 * OIDC callback route -- handles the redirect from the Microsoft identity provider.
 *
 * Route: /auth/callback (public, no ProtectedRoute)
 *
 * Reads `code` and `state` from URL search params, calls the backend callback
 * endpoint, stores the resulting tokens via Zustand loginWithTokens, then
 * redirects to the dashboard.
 *
 * Security (T-140-08): CSRF protection is backend-side via signed state JWT in
 * HttpOnly cookie. Frontend passes state param through to the backend callback
 * which validates it against the stored cookie.
 */
export function OidcCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const exchanged = useRef(false);

  useEffect(() => {
    // Guard against double-invocation in React StrictMode
    if (exchanged.current) return;
    exchanged.current = true;

    const code = searchParams.get("code");
    const state = searchParams.get("state");

    if (!code || !state) {
      setError("Missing authorization code or state parameter.");
      return;
    }

    const redirectUri = `${window.location.origin}/auth/callback`;

    exchangeOidcCode(code, state, redirectUri)
      .then((tokens) => {
        useAuthStore.getState().loginWithTokens(tokens);
        navigate("/", { replace: true });
      })
      .catch((err: unknown) => {
        const message =
          err instanceof Error ? err.message : "Sign-in could not be completed.";
        setError(message);
      });
  }, [navigate, searchParams]);

  if (error) {
    return (
      <div className="oidc-callback">
        <p className="oidc-callback__error" role="alert">
          {error}
        </p>
        <Link className="oidc-callback__link" to="/login">
          Return to login
        </Link>
      </div>
    );
  }

  return (
    <div className="oidc-callback">
      <p className="oidc-callback__loading" aria-live="polite">
        Completing sign-in...
      </p>
      <style>{`
        .oidc-callback {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          gap: 1rem;
          background: var(--color-base);
          color: var(--color-text);
        }
        .oidc-callback__loading {
          font-family: "JetBrains Mono", monospace;
          color: var(--color-accent);
        }
        .oidc-callback__error {
          color: var(--color-critical);
          font-size: 0.9375rem;
        }
        .oidc-callback__link {
          color: var(--color-accent);
          text-decoration: underline;
          font-size: 0.875rem;
        }
      `}</style>
    </div>
  );
}
