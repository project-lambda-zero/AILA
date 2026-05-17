# aila-fuzz-reporter

Sidecar that ships fuzzer telemetry + crashes from a running fuzz
campaign into AILA. Runs alongside the fuzzer on the dedicated
workstation (D-33) — AILA itself never invokes the fuzzer.

## What it does

Every `--interval` seconds:

1. Scrapes the fuzzer's state file (Fuzzilli `stats.json`, AFL++
   `fuzzer_stats`, libFuzzer stderr log) → `Sample` of execs/sec,
   coverage, corpus size, crash count.
2. `PATCH /api/vr/fuzz/campaigns/{id}` with the scalars that
   changed. The backend `patch_campaign` path snapshots a row to
   `vr_fuzz_telemetry` whenever a metric moves, so the AILA UI
   sparkline + stuck-detection populate automatically.
3. Scans the fuzzer's crash dir for new files. Each unique file
   (deduplicated locally by `stack_hash`) is `POST`ed to
   `/api/vr/fuzz/crashes`. The backend reads the first 4 KB of
   `reproducer_path` for the hex preview.

## Quickstart

```bash
# 1) Install — the sidecar is pure-stdlib, no pip deps.
git clone https://github.com/project-lambda-zero/AILA
cp -r AILA/tools/aila_fuzz_reporter /opt/

# 2) Pre-create the campaign in AILA (gets back a campaign_id):
curl -sX POST https://aila/api/vr/fuzz/campaigns \
     -H "X-API-Key: $AILA_API_KEY" \
     -H 'Content-Type: application/json' \
     -d '{
       "target_id": "<your_target_id>",
       "workspace_id": "<your_workspace_id>",
       "name": "my fuzzilli campaign",
       "engine_id": "fuzzilli_v8",
       "strategy_id": "generative",
       "analysis_system_id": <your_system_id>
     }'

# 3) Start the fuzzer (manually or via POST /campaigns/{id}/launch).

# 4) Run the sidecar in the same shell session:
python3 -m aila_fuzz_reporter \
    --aila-url    https://aila.example \
    --api-key     "$AILA_API_KEY" \
    --campaign-id <campaign_id_from_step_2> \
    --engine      fuzzilli \
    --storage     ~/.aila/fuzz/<campaign_id>/
```

## Per-engine flags

| engine     | required flags                              | scrapes from                              |
|------------|---------------------------------------------|-------------------------------------------|
| `fuzzilli` | `--storage <dir>`                           | `<dir>/stats.json` + `<dir>/crashes/`     |
| `afl++`    | `--out <dir>`                               | `<dir>/default/fuzzer_stats` + `crashes/` |
| `libfuzzer`| `--log <file>` + `--artifacts <dir>`        | log tail + `<artifacts>/crash-*` etc.     |

## Auth

Pass an AILA API key with `operator` role via `--api-key`. The
sidecar sends it on every request as both `X-API-Key` and
`Authorization: Bearer <key>` so the AILA `require_user_or_api_key`
dependency accepts whichever path is configured.

## Reliability

- HTTP failures retry with exponential backoff (1 s → 30 s, 5
  attempts).
- `4xx` responses are non-retryable — the sidecar logs the body
  and moves on. Common causes: stale API key, validation errors.
- Crashes are deduplicated locally by `stack_hash` so restarting
  the sidecar against the same campaign + crash dir does not
  re-POST.
- `SIGINT` / `SIGTERM` finish the current iteration then exit.

## systemd unit example

For long-running campaigns on a dedicated rig, drop the sidecar
into systemd so it restarts if the python process dies:

```ini
# /etc/systemd/system/aila-fuzz-reporter@<campaign_id>.service
[Unit]
Description=AILA fuzz reporter for campaign %i
After=network-online.target

[Service]
Type=simple
User=fuzz
WorkingDirectory=/opt
Environment=AILA_API_KEY=...
ExecStart=/usr/bin/python3 -m aila_fuzz_reporter \
    --aila-url    https://aila.example \
    --api-key     ${AILA_API_KEY} \
    --campaign-id %i \
    --engine      fuzzilli \
    --storage     /home/fuzz/.aila/fuzz/%i \
    --interval    30
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable + start with:

```bash
systemctl enable --now aila-fuzz-reporter@<campaign_id>.service
journalctl -fu aila-fuzz-reporter@<campaign_id>.service
```

## What it does NOT do

- Does **not** start or stop the fuzzer. That's the operator's job
  (or AILA's `POST /vr/fuzz/campaigns/{id}/launch` endpoint, which
  SSHes to the workstation and runs the launcher commands defined
  in `aila.modules.vr.services.fuzz_launcher`).
- Does **not** classify crashes — `crash_type` is left as the engine
  reports it (AFL++ op suffix, libFuzzer artifact kind, etc.) or
  `None` for Fuzzilli. AILA's existing auto-triage in
  `register_crash` runs on the backend.
- Does **not** read ASan/MSan reports yet. When the operator wires
  the harness to dump a sanitizer report next to the reproducer,
  we'll extend `discover_crashes()` to attach the report bytes via
  the `extra` field.
