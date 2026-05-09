"""HTML-to-PDF conversion via weasyprint.

Design references: D-02, D-06.

weasyprint is synchronous and CPU-intensive.  Callers run inside an async
request handler; the conversion runs inline and briefly blocks the event loop.
Heavy/long-running renders should be dispatched through a platform task that
owns its own threading boundary (D-06, T-136-06).

Font strategy: system fonts only (Arial/Helvetica/sans-serif).  No external
CDN font URLs are referenced in templates — weasyprint does not resolve them
reliably and they introduce network latency and privacy concerns (Pitfall 1
from RESEARCH.md).

Usage:
    pdf_bytes = html_to_pdf(html_string)
"""

from __future__ import annotations

__all__ = ["html_to_pdf"]


def html_to_pdf(html_string: str) -> bytes:
    """Convert an HTML string to PDF bytes using weasyprint.

    weasyprint is CPU-intensive and synchronous (T-136-06); the caller is
    responsible for offloading to a worker when render time matters.

    Uses system fonts only — no external font URLs (Pitfall 1).

    Args:
        html_string: Fully-rendered HTML document as a string.

    Returns:
        PDF bytes suitable for streaming to the client as
        application/pdf.
    """
    from weasyprint import HTML  # lazy import — heavy optional dependency

    return HTML(string=html_string).write_pdf()  # type: ignore[no-any-return]
