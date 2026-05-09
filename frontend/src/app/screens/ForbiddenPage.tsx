import { Link } from "react-router";

import { ShieldSlash } from "@phosphor-icons/react";

/**
 * 403 ACCESS DENIED — cyberpunk forbidden page (D-16).
 *
 * Rendered by ProtectedRoute when the user's role is insufficient.
 * Uses AILA design tokens. No glitch animation (reserved for 404).
 */
export function ForbiddenPage() {
  return (
    <div className="error-page error-page--403">
      {/* Large muted error code behind the content */}
      <span className="error-page__code" aria-hidden="true">
        403
      </span>

      <div className="error-page__content">
        <ShieldSlash
          size={64}
          weight="duotone"
          className="error-page-403__icon"
          aria-hidden="true"
        />

        <div className="error-page-403__accent-strip" aria-hidden="true" />

        <h1 className="error-page__heading error-page-403__heading">
          ACCESS DENIED
        </h1>

        <p className="error-page__subtitle">
          You do not have permission to access this resource.
        </p>

        <Link className="error-page__link" to="/">
          Return to dashboard
        </Link>
      </div>

      <style>{`
        .error-page--403 .error-page__code {
          color: rgba(251, 191, 36, 0.03);
        }

        .error-page-403__icon {
          color: #fbbf24;
        }

        .error-page-403__heading {
          color: #fbbf24;
        }

        .error-page-403__accent-strip {
          width: 4px;
          height: 3rem;
          background: #fbbf24;
          border-radius: 2px;
          margin: 0 auto;
        }

        .error-page--403 .error-page__link {
          color: #fbbf24;
        }
      `}</style>
    </div>
  );
}
