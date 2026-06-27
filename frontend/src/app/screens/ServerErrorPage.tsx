import { Link } from "react-router";

import { WarningOctagon } from "@phosphor-icons/react/dist/csr/WarningOctagon";

interface ServerErrorPageProps {
  error?: Error;
  resetError?: () => void;
}

/**
 * 500 SYSTEM ERROR -- cyberpunk server error page (D-16).
 *
 * Used by AppErrorBoundary to render unhandled render errors, and also
 * registered as a direct `/500` route for backend 5xx navigation.
 *
 * Security (T-140-09): Stack traces are logged to console.error only.
 * The user-visible message is always generic.
 */
export function ServerErrorPage({ error: _error, resetError }: ServerErrorPageProps) {
  return (
    <div className="error-page error-page--500">
      {/* Large muted error code behind the content */}
      <span className="error-page__code" aria-hidden="true">
        500
      </span>

      <div className="error-page__content">
        <WarningOctagon
          size={64}
          weight="duotone"
          className="error-page-500__icon"
          aria-hidden="true"
        />

        <h1 className="error-page__heading error-page-500__heading">
          SYSTEM ERROR
        </h1>

        <p className="error-page__subtitle">
          Something went wrong. Please try again.
        </p>

        <div className="error-page-500__actions">
          {resetError ? (
            <button
              className="error-page-500__retry-btn"
              type="button"
              onClick={resetError}
            >
              Try again
            </button>
          ) : null}

          <Link className="error-page__link" to="/">
            Return to dashboard
          </Link>
        </div>
      </div>

      <style>{`
        .error-page--500 .error-page__code {
          color: rgba(239, 68, 68, 0.03);
        }

        .error-page-500__icon {
          color: var(--color-critical, #ef4444);
        }

        .error-page-500__heading {
          color: var(--color-critical, #ef4444);
        }

        .error-page-500__actions {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 0.75rem;
          margin-top: 0.5rem;
        }

        .error-page-500__retry-btn {
          padding: 0.625rem 1.5rem;
          background: var(--color-critical, #ef4444);
          color: #fff;
          font-weight: 600;
          font-size: 0.9375rem;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          transition: opacity 150ms ease;
        }
        .error-page-500__retry-btn:hover { opacity: 0.85; }

        .error-page--500 .error-page__link {
          color: var(--color-critical, #ef4444);
        }
      `}</style>
    </div>
  );
}
