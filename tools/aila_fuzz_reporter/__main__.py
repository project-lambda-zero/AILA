"""``python -m aila_fuzz_reporter`` -- drive the scrape loop.

Usage:

  python -m aila_fuzz_reporter \\
      --aila-url    http://aila.example:8000 \\
      --api-key     "$AILA_API_KEY" \\
      --campaign-id 9c1f-...-...-... \\
      --engine      fuzzilli \\
      --storage     ~/.aila/fuzz/9c1f.../

Per-engine flags:

  --engine fuzzilli      -> --storage <dir>           (Fuzzilli storagePath)
  --engine afl++         -> --out <dir>               (AFL++ -o dir)
  --engine libfuzzer     -> --log <file> --artifacts <dir>
                                                     (libFuzzer log + artifact_prefix dir)

Loop:
  - Every ``--interval`` (default 30 s): scrape sample -> PATCH campaign.
  - Every iteration: discover crashes -> POST new ones. Dedup runs on a
    stack-frame hash (``base.stack_hash_of``) derived from any stack
    trace the scraper surfaces; the local seen-set survives restart
    via a small JSON state file written next to the reporter's own
    working directory (default ``$XDG_STATE_HOME/aila-fuzz-reporter/
    <campaign-id>.seen`` on POSIX, ``%LOCALAPPDATA%\\aila-fuzz-reporter\\
    <campaign-id>.seen`` on Windows). See ``--state-dir`` to override.
  - On KeyboardInterrupt: flush the seen-set to disk and exit cleanly.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

from .base import AilaClient, CrashRecord, Scraper, stack_hash_of
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


def _default_state_dir() -> Path:
    """Return the OS-appropriate default directory for the seen-set file.

    Priority:
      1. ``AILA_FUZZ_REPORTER_STATE_DIR`` env (operator override).
      2. ``$XDG_STATE_HOME/aila-fuzz-reporter`` on POSIX.
      3. ``%LOCALAPPDATA%/aila-fuzz-reporter`` on Windows.
      4. ``~/.local/state/aila-fuzz-reporter`` as a POSIX fallback.
    """
    env_override = os.environ.get("AILA_FUZZ_REPORTER_STATE_DIR")
    if env_override:
        return Path(env_override).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "aila-fuzz-reporter"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "aila-fuzz-reporter"


def _state_path(state_dir: Path, campaign_id: str) -> Path:
    """Return the per-campaign seen-set JSON path.

    ``campaign_id`` is scrubbed to filesystem-safe characters (UUIDs
    only need alphanumerics + hyphens, but the scrubber protects
    against a caller supplying a stray path separator).
    """
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in campaign_id)
    return state_dir / f"{safe}.seen"


def _load_seen_set(state_path: Path) -> set[str]:
    """Load the persisted stack-hash set from ``state_path``.

    A missing file returns an empty set (fresh run). A malformed file
    logs a warning and returns empty -- the reporter degrades to
    fresh-run behaviour rather than crashing, since the seen-set is
    an optimisation on top of the backend's own
    ``(campaign_id, stack_hash)`` uniqueness constraint.
    """
    if not state_path.exists():
        return set()
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning(
            "seen-set at %s unreadable (%s); starting fresh",
            state_path, exc,
        )
        return set()
    hashes = payload.get("stack_hashes")
    if not isinstance(hashes, list):
        _log.warning(
            "seen-set at %s malformed (missing stack_hashes list); starting fresh",
            state_path,
        )
        return set()
    return {str(h) for h in hashes if isinstance(h, str)}


def _save_seen_set(state_path: Path, seen: set[str]) -> None:
    """Persist ``seen`` to ``state_path`` via a tmpfile + atomic rename.

    Fail-open: an I/O failure logs a warning but does not raise into
    the scrape loop -- the current process keeps deduplicating in
    memory and the loss is only visible after restart.
    """
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_path.with_suffix(state_path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(
                {"version": 1, "stack_hashes": sorted(seen)},
                ensure_ascii=True,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, state_path)
    except OSError as exc:
        _log.warning("seen-set persist failed for %s: %s", state_path, exc)


def _dedup_key(crash: CrashRecord) -> str:
    """Return the durable dedup key for ``crash``.

    Preference order:
      1. Frame-based hash via :func:`stack_hash_of` when the scraper
         surfaced a stack trace. This collapses the same underlying
         bug across recompiles / minor build changes because file
         paths and offsets are excluded from the canonical form (see
         ``base.stack_hash_of``).
      2. Otherwise the scraper-supplied ``crash.stack_hash`` as a
         fallback. Scrapers today derive that from the crash filename
         which changes across runs, so it is strictly weaker than the
         frame hash -- but returning ``""`` here would suppress dedup
         entirely and re-POST every crash every iteration, which is
         worse.

    Falling back preserves prior behaviour on engines that do not
    (yet) attach a stack trace so the change is safe.
    """
    if crash.stack_trace:
        return stack_hash_of(crash.stack_trace)
    return crash.stack_hash


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
    parser.add_argument(
        "--state-dir", type=Path, default=None,
        help=(
            "Directory that holds the per-campaign seen-set JSON so "
            "dedup survives restart. Defaults to "
            "$AILA_FUZZ_REPORTER_STATE_DIR, else $XDG_STATE_HOME/"
            "aila-fuzz-reporter (POSIX) or %LOCALAPPDATA%/"
            "aila-fuzz-reporter (Windows)."
        ),
    )
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

    # Persistent seen-set (#60): load whatever the previous process
    # left behind so a restart does not re-POST every already-registered
    # crash on the next iteration. The state file is scoped by
    # campaign id so multiple concurrent reporters on the same host do
    # not collide.
    state_dir = args.state_dir or _default_state_dir()
    state_path = _state_path(state_dir, args.campaign_id)
    seen_hashes: set[str] = _load_seen_set(state_path)
    _log.info(
        "scrape loop start: engine=%s campaign=%s interval=%.1fs aila=%s "
        "state=%s resumed=%d",
        scraper.name, args.campaign_id, args.interval, args.aila_url,
        state_path, len(seen_hashes),
    )

    stop = {"go": True}
    def _on_signal(signum: int, frame: Any) -> None:
        del signum, frame
        _log.info("signal received -> exiting after current iteration")
        stop["go"] = False
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    try:
        while stop["go"]:
            # 1) Telemetry sample.
            sample = scraper.poll()
            if sample is not None:
                ok = client.patch_campaign(sample)
                _log.debug("patch_campaign ok=%s sample=%s", ok, sample)
            # 2) Crash discovery + POST. Dedup keys on the frame-based
            # stack hash when a trace is available, otherwise falls
            # back to the scraper-supplied stack_hash.
            new_this_iteration = False
            for crash in scraper.discover_crashes():
                key = _dedup_key(crash)
                if not key or key in seen_hashes:
                    continue
                ok = client.post_crash(crash)
                if ok:
                    seen_hashes.add(key)
                    new_this_iteration = True
                    _log.info(
                        "crash POSTed signature=%s type=%s key=%s",
                        crash.crash_signature, crash.crash_type, key[:16],
                    )
            # 2b) Persist the seen-set only when it actually grew so we
            # do not pay a disk write per idle iteration.
            if new_this_iteration:
                _save_seen_set(state_path, seen_hashes)
            # 3) Sleep with interruptibility -- break out fast on signal.
            slept = 0.0
            while stop["go"] and slept < args.interval:
                time.sleep(min(1.0, args.interval - slept))
                slept += 1.0
    finally:
        # Belt-and-suspenders flush on exit so a signal-driven shutdown
        # that raced with an incomplete iteration still saves whatever
        # the current process observed.
        _save_seen_set(state_path, seen_hashes)
    _log.info("scrape loop exit clean. crashes_reported=%d", len(seen_hashes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
