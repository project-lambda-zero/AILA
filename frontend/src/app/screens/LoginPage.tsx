import { lazy, Suspense, useState } from "react";

import { Navigate, useLocation, useNavigate } from "react-router";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { fetchOidcAuthorizeUrl } from "@platform/api/auth";
import { useReducedMotion } from "@/hooks/useReducedMotion";

// Code-split terminal background so the ogl bundle isn't pulled into the
// main chunk for routes that don't need it.
const LoginFaultyTerminal = lazy(() =>
  import("./LoginFaultyTerminal").then((m) => ({ default: m.LoginFaultyTerminal })),
);

/**
 * Login page — theme-adaptive.
 *
 * Left panel: full-height dark panel with particle background and AILA branding.
 *   Hidden on mobile (<768px).
 * Right panel: username/password form with OIDC SSO link.
 *
 * Security: error messages are always generic "Invalid credentials".
 */
export function LoginPage() {
  const { status } = useAuthStore();
  const location = useLocation();
  const navigate = useNavigate();
  const prefersReducedMotion = useReducedMotion();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [oidcLoading, setOidcLoading] = useState(false);

  const state = location.state as { from?: string } | null;
  const target = state?.from ?? "/";

  if (status === "authenticated") {
    return <Navigate to={target} replace />;
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await useAuthStore.getState().login(username, password);
      navigate(target, { replace: true });
    } catch {
      setError("Invalid credentials");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleOidc(): Promise<void> {
    if (oidcLoading) return;
    setOidcLoading(true);
    try {
      const redirectUri = `${window.location.origin}/auth/callback`;
      const url = await fetchOidcAuthorizeUrl(redirectUri);
      window.location.href = url;
    } catch {
      setError("Could not initiate Microsoft sign-in. Please try again.");
      setOidcLoading(false);
    }
  }

  return (
    <div className="login-root">
      {/* Left panel — branding + particles */}
      <div className="login-left" aria-hidden="true">
        <div className="login-dot-grid" />

        {!prefersReducedMotion && (
          <Suspense fallback={null}>
            <LoginFaultyTerminal />
          </Suspense>
        )}

        <div className="login-brand">
          <span className="login-brand__wordmark">AILA</span>
          <span className="login-brand__tagline">AI Lab Assistant</span>
        </div>
      </div>

      {/* Right panel — form */}
      <main className="login-right">
        <p className="login-mobile-logo" aria-hidden="true">AILA</p>

        <div className="login-form-card">
          <h1 className="login-form-card__heading">Sign in</h1>

          {error ? (
            <div className="login-error" role="alert">
              {error}
            </div>
          ) : null}

          <form onSubmit={(e) => void handleSubmit(e)} noValidate>
            <div className="login-field">
              <label className="login-field__label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                className="login-field__input"
                type="text"
                autoComplete="username"
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={submitting}
              />
            </div>

            <div className="login-field">
              <label className="login-field__label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                className="login-field__input"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={submitting}
              />
            </div>

            <button
              className="login-submit-btn"
              type="submit"
              disabled={submitting}
              aria-busy={submitting}
            >
              {submitting ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <div className="login-divider" role="separator">
            <span>or</span>
          </div>

          <button
            className="login-sso-link"
            type="button"
            onClick={() => void handleOidc()}
            disabled={oidcLoading}
          >
            {oidcLoading ? "Redirecting..." : "Sign in with Microsoft"}
          </button>
        </div>
      </main>

      <style>{`
        .login-root {
          display: flex;
          min-height: 100vh;
          background: var(--color-base);
        }

        /* Left panel */
        .login-left {
          display: none;
          position: relative;
          width: 50%;
          background: var(--color-base);
          overflow: hidden;
        }
        @media (min-width: 768px) {
          .login-left { display: flex; align-items: flex-end; }
        }

        .login-dot-grid {
          position: absolute;
          inset: 0;
          background-image: radial-gradient(circle, color-mix(in srgb, var(--color-accent) 8%, transparent) 1px, transparent 1px);
          background-size: 24px 24px;
        }

        .login-brand {
          position: relative;
          z-index: 1;
          padding: 3rem;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }
        .login-brand__wordmark {
          font-family: var(--font-display);
          font-size: 4rem;
          font-weight: 700;
          color: var(--color-accent);
          letter-spacing: -0.02em;
          line-height: 1;
        }
        .login-brand__tagline {
          font-size: 1rem;
          color: var(--color-text-muted);
          font-family: var(--font-sans);
        }

        /* Right panel */
        .login-right {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 2rem 1.5rem;
          background: var(--color-surface);
        }

        .login-mobile-logo {
          display: block;
          font-family: var(--font-display);
          font-size: 1.75rem;
          font-weight: 700;
          color: var(--color-accent);
          margin-bottom: 2rem;
        }
        @media (min-width: 768px) {
          .login-mobile-logo { display: none; }
        }

        .login-form-card {
          width: 100%;
          max-width: 380px;
        }
        .login-form-card__heading {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 600;
          color: var(--color-text);
          margin-bottom: 1.5rem;
        }

        .login-error {
          margin-bottom: 1rem;
          padding: 0.75rem 1rem;
          border: 1px solid color-mix(in srgb, var(--color-accent) 50%, transparent);
          border-radius: var(--radius-md);
          background: color-mix(in srgb, var(--color-accent) 10%, transparent);
          color: var(--color-accent);
          font-size: 0.875rem;
        }

        .login-field {
          display: flex;
          flex-direction: column;
          gap: 0.375rem;
          margin-bottom: 1rem;
        }
        .login-field__label {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--color-text-muted);
        }
        .login-field__input {
          padding: 0.625rem 0.875rem;
          background: var(--color-base);
          border: 1px solid var(--color-border);
          border-radius: var(--radius-md);
          color: var(--color-text);
          font-size: 0.9375rem;
          font-family: var(--font-sans);
          transition: border-color 150ms ease;
          outline: none;
        }
        .login-field__input:focus {
          border-color: var(--color-accent);
        }
        .login-field__input:disabled {
          opacity: 0.5;
        }

        .login-submit-btn {
          width: 100%;
          padding: 0.75rem 1rem;
          background: var(--color-accent);
          color: var(--primary-foreground, #000);
          font-family: var(--font-sans);
          font-weight: 600;
          font-size: 0.9375rem;
          border: none;
          border-radius: var(--radius-md);
          cursor: pointer;
          transition: opacity 150ms ease;
          margin-top: 0.5rem;
        }
        .login-submit-btn:hover:not(:disabled) { opacity: 0.88; }
        .login-submit-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .login-divider {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin: 1.5rem 0 1rem;
          color: var(--color-text-muted);
          font-size: 0.75rem;
        }
        .login-divider::before,
        .login-divider::after {
          content: "";
          flex: 1;
          height: 1px;
          background: var(--color-border);
        }

        .login-sso-link {
          display: block;
          width: 100%;
          padding: 0.625rem 1rem;
          background: transparent;
          border: 1px solid var(--color-border);
          border-radius: var(--radius-md);
          color: var(--color-text-muted);
          font-family: var(--font-sans);
          font-size: 0.875rem;
          cursor: pointer;
          transition: border-color 150ms ease, color 150ms ease;
          text-align: center;
        }
        .login-sso-link:hover:not(:disabled) {
          border-color: var(--color-border-hover);
          color: var(--color-text);
        }
        .login-sso-link:disabled { opacity: 0.5; cursor: not-allowed; }
      `}</style>
    </div>
  );
}
