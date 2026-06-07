"""Refresh every audit-mcp index from its upstream git.

Walks `GET /tools/list_indexes`, then per-index calls
`POST /tools/refresh_index` with `{"index_id": "..."}`. Returns a summary of
which indexes were already current, which got re-indexed, and which failed.

Run via `bash start.sh refresh-audit-mcp` or directly:

    python scripts/refresh_audit_mcp_indexes.py [--force] [--only <id>...]
                                                [--url http://127.0.0.1:18822]
                                                [--timeout 600] [--json]

The script is conservative by default:

- Sequential per-index (audit-mcp's thread pool handles concurrent git fetches
  fine; we serialize so the log is readable and disk I/O doesn't spike).
- Per-index timeout (default 600s) bounds a hung git fetch from blocking the
  whole sweep.
- `--force` rebuilds even when the SHA didn't change. Useful after a
  trailmark/semble upgrade where the on-disk format changed.
- `--only` restricts the sweep to a comma-separated list of index_ids (or
  unique prefixes); everything else is skipped.

Exit codes:
    0  every index returned `current` or `refreshing`
    1  one or more indexes failed
    2  audit-mcp unreachable
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = "http://127.0.0.1:18822"
DEFAULT_TIMEOUT_S = 600.0


def _http_post(url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _list_indexes(base_url: str, timeout: float) -> list[dict[str, Any]]:
    data = _http_post(f"{base_url}/tools/list_indexes", {}, timeout=timeout)
    return data.get("indexes") or []


def _refresh_one(
    base_url: str,
    index_id: str,
    *,
    force: bool,
    timeout: float,
) -> dict[str, Any]:
    return _http_post(
        f"{base_url}/tools/refresh_index",
        {"index_id": index_id, "force": force},
        timeout=timeout,
    )


def _slug(record: dict[str, Any]) -> str:
    root = record.get("root_path") or ""
    # last path component is enough for human-readable output
    for sep in ("/", "\\"):
        if sep in root:
            root = root.rsplit(sep, 1)[-1]
    return root or record.get("index_id", "?")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL, help=f"audit-mcp base URL (default {DEFAULT_URL})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help="per-call timeout in seconds")
    parser.add_argument("--force", action="store_true",
                        help="rebuild even when the SHA did not change")
    parser.add_argument("--only", default="",
                        help="comma-separated index_ids (or unique prefixes) to refresh; default = all")
    parser.add_argument("--json", action="store_true",
                        help="emit one JSON object per index to stdout (machine-readable)")
    args = parser.parse_args(argv)

    base_url = args.url.rstrip("/")

    try:
        records = _list_indexes(base_url, timeout=min(30.0, args.timeout))
    except urllib.error.URLError as exc:
        print(f"audit-mcp unreachable at {base_url}: {exc.reason}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"audit-mcp list_indexes failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    if only:
        records = [r for r in records if any(r.get("index_id", "").startswith(p) for p in only)]
        if not records:
            print(f"no indexes match --only {sorted(only)!r}", file=sys.stderr)
            return 1

    counts = {"current": 0, "refreshing": 0, "error": 0}
    started_at = time.time()

    if not args.json:
        print(f"refreshing {len(records)} audit-mcp indexes "
              f"(force={args.force}, timeout={args.timeout:.0f}s)")
        print(f"{'index_id':14} {'name':28} {'status':12} {'detail':50}")
        print("-" * 110)

    for rec in records:
        index_id = rec.get("index_id", "")
        name = _slug(rec)
        t0 = time.time()
        try:
            result = _refresh_one(
                base_url, index_id,
                force=args.force,
                timeout=args.timeout,
            )
        except urllib.error.URLError as exc:
            result = {"status": "error", "error": f"URLError: {exc.reason}"}
        except Exception as exc:  # noqa: BLE001
            result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

        status = result.get("status", "error")
        counts[status] = counts.get(status, 0) + 1
        dt = time.time() - t0

        if args.json:
            print(json.dumps({
                "index_id": index_id,
                "name": name,
                "elapsed_s": round(dt, 2),
                **result,
            }))
            continue

        if status == "current":
            sha = (result.get("sha") or "")[:8]
            detail = f"unchanged ({sha})"
        elif status == "refreshing":
            old = (result.get("old_sha") or "—")[:8]
            new = (result.get("new_sha") or "?")[:8]
            detail = f"{old} -> {new}"
        else:
            detail = result.get("error", "?")[:50]
        print(f"{index_id:14} {name[:28]:28} {status:12} {detail[:50]:50} ({dt:.1f}s)")

    total = time.time() - started_at
    if not args.json:
        print("-" * 110)
        print(f"done in {total:.1f}s: "
              f"{counts.get('current', 0)} current, "
              f"{counts.get('refreshing', 0)} refreshing, "
              f"{counts.get('error', 0)} error")

    return 0 if counts.get("error", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
