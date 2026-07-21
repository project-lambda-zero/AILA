"""aila_fuzz_reporter -- sidecar that ships fuzzer telemetry + crashes
to an AILA instance running elsewhere.

Architecture (D-33): the AILA platform never runs the fuzzer
in-process. The operator (or the launcher endpoint) starts the
fuzzer on a dedicated Linux workstation; this sidecar runs in the
same shell session and pushes the fuzzer's progress / crash output
to AILA over HTTP.

Entry point: ``python -m aila_fuzz_reporter --help``

Per-engine scrapers live in ``aila_fuzz_reporter.scrapers``. Each
scraper implements the small ``Scraper`` protocol (see ``base.py``).
"""
from __future__ import annotations

__all__ = ["__version__"]
__version__ = "0.3.0"
