/**
 * #47 -- post-login redirect target sanitizer (open-redirect defence).
 *
 * The login flow accepts a next-URL from three untrusted sources: the
 * `state.from` field a router `<Navigate>` pushed, the `?next=` query
 * parameter the 401-interceptor set on the login URL, and any other
 * caller that navigates to `/login`. If any of those are propagated
 * verbatim into `navigate(target)` we open the door to
 *
 *   /login?next=https://evil.example/steal
 *   /login?next=//evil.example/steal        (protocol-relative)
 *   /login?next=javascript:alert(1)         (URL scheme injection)
 *   /login?next=/#/x                        (hash-router escape)
 *
 * -- all of which either redirect off-origin or execute untrusted code
 * once the user has just authenticated.
 *
 * The allowlist rules below produce a same-origin path OR the `"/"`
 * fallback. Nothing else escapes.
 */

const DEFAULT_TARGET = "/";

/**
 * Return `candidate` if it is a safe same-origin path, otherwise `"/"`.
 *
 * Rules:
 * 1. Only strings are accepted; non-strings collapse to the default.
 * 2. The value MUST start with a single `/` -- rejects empty, plain
 *    identifiers, and absolute URLs.
 * 3. `//` is rejected -- a protocol-relative URL like `//evil.example`
 *    would otherwise route the browser off-origin.
 * 4. `/\` (backslash after slash) is rejected -- some browsers treat
 *    `/\evil.example` as `//evil.example`.
 * 5. Any scheme-looking segment (`javascript:`, `data:`, `vbscript:`)
 *    is rejected even inside a path fragment.
 * 6. Control characters (< 0x20 and 0x7f) are rejected -- they can
 *    smuggle a scheme past a naive parser.
 *
 * We deliberately do NOT allow query strings or fragments to change
 * the origin (they can't) but we do preserve them so
 * `/vulnerability/scans?id=abc` still round-trips through login.
 */
export function sanitizeRedirectPath(candidate: unknown): string {
  if (typeof candidate !== "string") return DEFAULT_TARGET;
  if (candidate.length === 0) return DEFAULT_TARGET;

  // Rule 6: reject any control character before further inspection.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(candidate)) return DEFAULT_TARGET;

  // Rule 2: must begin with a single forward slash.
  if (candidate.charAt(0) !== "/") return DEFAULT_TARGET;

  // Rule 3 + 4: reject `//` and `/\` (protocol-relative or backslash-tricked).
  if (candidate.length >= 2) {
    const second = candidate.charAt(1);
    if (second === "/" || second === "\\") return DEFAULT_TARGET;
  }

  // Rule 5: reject any scheme-looking token anywhere before the query.
  // We split on `?` so a legitimate query value containing `://` stays
  // allowed (e.g. `/reports?callback=https%3A%2F%2F...`).
  const pathPart = candidate.split("?", 1)[0];
  if (/[a-z][a-z0-9+.\-]*:/i.test(pathPart)) return DEFAULT_TARGET;

  return candidate;
}

/**
 * Read a post-login redirect target from a router-state hint and a
 * `next` query parameter, in that order, then run it through
 * :func:`sanitizeRedirectPath`.
 *
 * Used by ``LoginPage`` and the OIDC callback screen so the same
 * allowlist governs every login flow.
 */
export function pickPostLoginTarget(
  stateHint: unknown,
  search: string | URLSearchParams | undefined,
): string {
  if (typeof stateHint === "string" && stateHint.length > 0) {
    return sanitizeRedirectPath(stateHint);
  }
  if (search !== undefined) {
    const params =
      typeof search === "string"
        ? new URLSearchParams(search.startsWith("?") ? search.slice(1) : search)
        : search;
    const next = params.get("next");
    if (next !== null) return sanitizeRedirectPath(next);
  }
  return DEFAULT_TARGET;
}
