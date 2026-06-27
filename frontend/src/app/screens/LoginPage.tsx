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
 * Login page -- theme-adaptive.
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
      {/* Left panel -- branding + particles */}
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

      {/* Right panel -- form */}
      <main className="login-right">
        <p className="login-mobile-logo" aria-hidden="true">AILA</p>

        <div className="login-form-card">
          <h1 className="login-form-card__heading">Sign in</h1>
          <p className="login-form-card__subtitle">
            Welcome back! Sign in to continue.
          </p>

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

        /* Right panel -- adapted from Aceternity's "premium-auth-split"
           block. Aceternity uses raw Tailwind utility classes; we map
           every visual token (h-11 inputs, ring-1 elevation, soft
           shadows, lg-radius, gradient primary button, gap-y-8 form
           rhythm) to AILA's CSS-variable theme tokens so the styling
           inherits every theme (synthwave, vendetta, matrix, etc.)
           without literal color values. Only borders + input/button
           shells + spacing were adapted; left panel (FaultyTerminal
           bg) is intentionally untouched per operator constraint. */
        .login-right {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 2.5rem 1.5rem;
          background: var(--color-surface);
        }
        @media (min-width: 768px) {
          .login-right { padding: 2.5rem 3rem; }
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

        /* Card: max-w-md, centered heading + subtitle, gap-y-8 stack */
        .login-form-card {
          width: 100%;
          max-width: 28rem;
        }
        .login-form-card__heading {
          font-family: var(--font-display);
          font-size: 1.875rem;
          font-weight: 600;
          letter-spacing: -0.025em;
          color: var(--color-text);
          text-align: center;
          margin: 0 0 0.5rem;
        }
        .login-form-card__subtitle {
          font-size: 0.875rem;
          color: var(--color-text-muted);
          text-align: center;
          margin: 0 0 2rem;
        }

        /* Inline alert that still respects the new visual rhythm. */
        .login-error {
          margin-bottom: 1.25rem;
          padding: 0.75rem 1rem;
          border: 1px solid transparent;
          border-radius: 0.5rem;
          background: color-mix(in srgb, var(--color-accent) 10%, transparent);
          color: var(--color-accent);
          font-size: 0.875rem;
          box-shadow: 0 0 0 1px color-mix(in srgb, var(--color-accent) 30%, transparent);
        }

        /* Field stack: label above input, gap-y-2 between, gap-y-5
           between consecutive fields. */
        .login-field {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
          margin-bottom: 1.25rem;
        }
        .login-field__label {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--color-text);
        }

        /* h-11 (44px) input with the ring-1 elevation look. Border is
           transparent so a focus ring can grow without layout shift;
           the resting ring is a flat 1px box-shadow tinted with the
           theme text color, matching Aceternity's
           'ring-1 ring-black/10 dark:ring-white/10'. */
        .login-field__input {
          height: 2.75rem;
          padding: 0 0.875rem;
          background: var(--color-base);
          border: 1px solid transparent;
          border-radius: 0.5rem;
          color: var(--color-text);
          font-size: 0.9375rem;
          font-family: var(--font-sans);
          outline: none;
          box-shadow:
            0 0 0 1px color-mix(in srgb, var(--color-text) 12%, transparent),
            0 1px 2px color-mix(in srgb, #000 10%, transparent);
          transition: box-shadow 150ms ease, background-color 150ms ease;
        }
        .login-field__input::placeholder {
          color: color-mix(in srgb, var(--color-text-muted) 70%, transparent);
        }
        .login-field__input:focus {
          box-shadow:
            0 0 0 2px color-mix(in srgb, var(--color-accent) 45%, transparent),
            0 1px 2px color-mix(in srgb, #000 10%, transparent);
        }
        .login-field__input:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        /* Primary button: h-11, full width, vertical gradient on the
           accent color, soft drop shadow tinted with the same accent.
           Active-press uses a scale to match Aceternity's
           'active:scale-98'. */
        .login-submit-btn {
          width: 100%;
          height: 2.75rem;
          padding: 0 1rem;
          background: linear-gradient(
            to bottom,
            var(--color-accent),
            color-mix(in srgb, var(--color-accent) 82%, #000)
          );
          color: var(--primary-foreground, #fff);
          font-family: var(--font-sans);
          font-weight: 600;
          font-size: 0.9375rem;
          border: none;
          border-radius: 0.5rem;
          cursor: pointer;
          margin-top: 0.5rem;
          box-shadow: 0 8px 24px color-mix(in srgb, var(--color-accent) 30%, transparent);
          transition: filter 150ms ease, transform 80ms ease, opacity 150ms ease;
        }
        .login-submit-btn:hover:not(:disabled) { filter: brightness(1.06); }
        .login-submit-btn:active:not(:disabled) { transform: scale(0.98); }
        .login-submit-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Divider with hairlines on both sides + small "or" centered. */
        .login-divider {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin: 1.75rem 0 1.25rem;
          color: var(--color-text-muted);
          font-size: 0.75rem;
          text-transform: lowercase;
        }
        .login-divider::before,
        .login-divider::after {
          content: "";
          flex: 1;
          height: 1px;
          background: color-mix(in srgb, var(--color-text) 12%, transparent);
        }

        /* Secondary button (SSO). Same h-11 shell and ring elevation as
           the input field so the visual rhythm reads as a single stack
           rather than disconnected pieces. */
        .login-sso-link {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          width: 100%;
          height: 2.75rem;
          padding: 0 1rem;
          background: var(--color-base);
          border: 1px solid transparent;
          border-radius: 0.5rem;
          color: var(--color-text);
          font-family: var(--font-sans);
          font-weight: 500;
          font-size: 0.875rem;
          cursor: pointer;
          box-shadow:
            0 0 0 1px color-mix(in srgb, var(--color-text) 12%, transparent),
            0 1px 2px color-mix(in srgb, #000 10%, transparent);
          transition: filter 150ms ease, transform 80ms ease,
                      box-shadow 150ms ease, background-color 150ms ease;
        }
        .login-sso-link:hover:not(:disabled) {
          background: color-mix(in srgb, var(--color-elevated) 70%, var(--color-base));
          box-shadow:
            0 0 0 1px color-mix(in srgb, var(--color-text) 18%, transparent),
            0 2px 4px color-mix(in srgb, #000 12%, transparent);
        }
        .login-sso-link:active:not(:disabled) { transform: scale(0.98); }
        .login-sso-link:disabled { opacity: 0.5; cursor: not-allowed; }
      `}</style>
    </div>
  );
}
