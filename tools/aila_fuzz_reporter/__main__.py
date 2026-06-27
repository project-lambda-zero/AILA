"""``python -m aila_fuzz_reporter`` -- drive the scrape loop.

Usage:

  python -m aila_fuzz_reporter \\
      --aila-url    http://aila.example:8000 \\
      --api-key     "$AILA_API_KEY" \\
      --campaign-id 9c1f-...-...-... \\
      --engine      fuzzilli \\
      --storage     ~/.aila/fuzz/9c1f.../

Per-engine flags:

  --engine fuzzilli      → --storage <dir>           (Fuzzilli storagePath)
  --engine afl++         → --out <dir>               (AFL++ -o dir)
  --engine libfuzzer     → --log <file> --artifacts <dir>
                                                     (libFuzzer log + artifact_prefix dir)

Loop:
  - Every ``--interval`` (default 30 s): scrape sample → PATCH campaign.
  - Every iteration: discover crashes → POST new ones (dedup via local
    seen-set keyed on stack_hash).
  - On KeyboardInterrupt: exit cleanly.
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Any

from .base import AilaClient, Scraper
from .scrapers import AflPlusPlusScraper, FuzzilliScraper, LibFuzzerScraper

_log = logging.getLogger("aila_fuzz_reporter")


def _build_scraper(args: argparse.Namespace) -> Scraper:
    if args.engine == "fuzzilli":
        if not args.storage:
            _die("--storage is required for --engine fuzzilli")
        return FuzzilliScraper(args.storage)
    if args.engine == "afl++":
        if not args.out:
            _die("--out is required for --engine afl++")
        return AflPlusPlusScraper(args.out)
    if args.engine == "libfuzzer":
        if not args.log or not args.artifacts:
            _die("--log AND --artifacts are required for --engine libfuzzer")
        return LibFuzzerScraper(args.log, args.artifacts)
    _die(f"unknown engine: {args.engine}")


def _die(msg: str) -> None:
    print(f"aila-fuzz-reporter: {msg}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aila-fuzz-reporter",
        description=(
            "Push a running fuzzer's progress + crashes into an AILA "
            "fuzz campaign. Runs alongside the fuzzer on the dedicated "
            "workstation (D-33)."
        ),
    )
    parser.add_argument("--aila-url", required=True,
                        help="Base URL of the AILA instance (e.g. http://aila:8000).")
    parser.add_argument("--api-key", required=True,
                        help="AILA API key with vr:operator role.")
    parser.add_argument("--campaign-id", required=True,
                        help="UUID of the vr_fuzz_campaigns row.")
    parser.add_argument("--engine", required=True,
                        choices=("fuzzilli", "afl++", "libfuzzer"),
                        help="Which fuzzer to scrape.")
    parser.add_argument("--storage", type=Path, default=None,
                        help="Fuzzilli --storagePath dir.")
    parser.add_argument("--out", type=Path, default=None,
                        help="AFL++ -o output dir.")
    parser.add_argument("--log", type=Path, default=None,
                        help="libFuzzer stderr log file.")
    parser.add_argument("--artifacts", type=Path, default=None,
                        help="libFuzzer artifact_prefix dir.")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="Polling interval in seconds (default 30).")
    parser.add_argument("--verbose", action="store_true",
                        help="DEBUG logging.")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    )

    scraper = _build_scraper(args)
    client = AilaClient(
        base_url=args.aila_url,
        api_key=args.api_key,
        campaign_id=args.campaign_id,
    )
    _log.info(
        "scrape loop start: engine=%s campaign=%s interval=%.1fs aila=%s",
        scraper.name, args.campaign_id, args.interval, args.aila_url,
    )

    stop = {"go": True}
    def _on_signal(signum: int, frame: Any) -> None:
        del signum, frame
        _log.info("signal received → exiting after current iteration")
        stop["go"] = False
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    seen_hashes: set[str] = set()
    while stop["go"]:
        # 1) Telemetry sample.
        sample = scraper.poll()
        if sample is not None:
            ok = client.patch_campaign(sample)
            _log.debug("patch_campaign ok=%s sample=%s", ok, sample)
        # 2) Crash discovery + POST.
        for crash in scraper.discover_crashes():
            if crash.stack_hash in seen_hashes:
                continue
            ok = client.post_crash(crash)
            if ok:
                seen_hashes.add(crash.stack_hash)
                _log.info(
                    "crash POSTed signature=%s type=%s",
                    crash.crash_signature, crash.crash_type,
                )
        # 3) Sleep with interruptibility -- break out fast on signal.
        slept = 0.0
        while stop["go"] and slept < args.interval:
            time.sleep(min(1.0, args.interval - slept))
            slept += 1.0
    _log.info("scrape loop exit clean. crashes_reported=%d", len(seen_hashes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
