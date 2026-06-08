import { Link } from "react-router";

import { WifiSlash } from "@phosphor-icons/react/dist/csr/WifiSlash";

/**
 * 404 SIGNAL LOST — cyberpunk not-found page (D-16).
 *
 * Uses the .glitch-text CSS class (keyframes in globals.css) for the heading
 * glitch animation. Respects reduced-motion via CSS media query.
 */
export function NotFoundPage() {
  return (
    <div className="error-page">
      {/* Large muted error code behind the content */}
      <span className="error-page__code" aria-hidden="true">
        404
      </span>

      <div className="error-page__content">
        <WifiSlash
          size={48}
          weight="duotone"
          className="error-page__icon"
          aria-hidden="true"
        />

        <h1
          className="glitch-text error-page__heading"
          data-text="SIGNAL LOST"
        >
          SIGNAL LOST
        </h1>

        <p className="error-page__subtitle">
          The page you requested does not exist.
        </p>

        <Link className="error-page__link" to="/">
          Return to dashboard
        </Link>
      </div>

      <style>{`
        .error-page {
          position: relative;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          background: var(--color-base);
          overflow: hidden;
        }

        .error-page__code {
          position: absolute;
          font-family: "JetBrains Mono", monospace;
          font-size: clamp(8rem, 25vw, 20rem);
          font-weight: 900;
          color: rgba(255, 255, 255, 0.03);
          user-select: none;
          pointer-events: none;
          line-height: 1;
        }

        .error-page__content {
          position: relative;
          z-index: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 1.25rem;
          text-align: center;
          padding: 2rem 1.5rem;
        }

        .error-page__icon {
          color: var(--color-accent);
        }

        .error-page__heading {
          font-family: "JetBrains Mono", monospace;
          font-size: clamp(2.5rem, 8vw, 5rem);
          font-weight: 700;
          color: var(--color-accent);
          line-height: 1;
          margin: 0;
        }

        .error-page__subtitle {
          font-size: 1rem;
          color: rgba(255, 255, 255, 0.45);
          max-width: 28rem;
          margin: 0;
        }

        .error-page__link {
          margin-top: 0.5rem;
          font-size: 0.9375rem;
          color: var(--color-accent);
          text-decoration: underline;
          text-underline-offset: 3px;
          transition: opacity 150ms ease;
        }
        .error-page__link:hover { opacity: 0.75; }
      `}</style>
    </div>
  );
}
