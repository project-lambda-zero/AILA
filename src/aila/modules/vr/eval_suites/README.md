# VR benchmark-measurement harness

Scores the VR investigation engine against published academic cyber-agent
benchmark suites and publishes a per-suite leaderboard, so platform quality
is measured instead of asserted (issue #157).

Supported suites: `cybench`, `nyu_ctf`, `htb_lite`.

## What it does

1. `start_suite_run` loads a suite manifest, and for each benchmark task
   spins one VR investigation against the task's pre-provisioned target
   (identical to an operator-launched investigation), enqueues it, and
   records a `pending` result row.
2. `collect_suite_run` scores every task whose investigation has reached a
   terminal state: the task is `solved` when the known reference answer
   appears in a produced outcome, and the live LLM cost and outcome
   polarity are recorded. Per-task rows roll up into the run's
   `solved_count` / `total_cost_usd`.
3. The leaderboard projects each suite's most recent run (solve rate, avg
   cost per task).

## Manifest format

Targets are heavyweight and ingested out-of-band through the normal
target-intake path (`POST /vr/targets` + ingestion), then reused across
measurement runs. The manifest lists each task's known reference answer and
the `target_id` of its already-ingested target.

`<vr.eval_suite_dataset_root>/<suite>/manifest.json`:

```json
{
  "tasks": [
    {
      "task_id": "crypto-01",
      "name": "weak-rng-token",
      "category": "crypto",
      "description": "Recover the signing token.",
      "reference_answer": "flag{r3cov3red_t0k3n}",
      "target_id": "<vr target id, pre-ingested>",
      "budget_usd": 25.0
    }
  ]
}
```

A `name{...}` wrapper (e.g. `flag{...}`, `CTF{...}`) and surrounding
whitespace are tolerated when matching; the comparison is case-insensitive.

## Running a live measurement (operator steps)

A live run needs infrastructure this harness does not bundle:

1. Obtain the public datasets and unpack them under one root, one
   subdirectory per suite:
   - Cybench: https://github.com/andyzorigin/cybench
   - NYU CTF Bench: https://github.com/NYU-LLM-CTF/NYU_CTF_Bench
2. Provision and ingest a VR target per benchmark task through the normal
   target-intake path; write each `target_id` plus its known
   `reference_answer` into `<root>/<suite>/manifest.json`.
3. Set `vr.eval_suite_dataset_root` to `<root>` (PUT `/config/vr/*`).
4. Ensure Redis is up and VR workers are running (the suite and its
   per-task investigations run as ARQ jobs), and that a model budget is
   available (each task is a full investigation).
5. `POST /vr/eval-suites/runs {"suite": "cybench"}` to start a run.
6. When the investigations finish, `POST /vr/eval-suites/runs/{id}/collect`
   to score the run, then read `GET /vr/eval-suites/leaderboard`.

Producing a published benchmark number is therefore an operator-run
activity (datasets + Redis + model budget); the harness code, scoring, and
leaderboard are exercised by unit tests under `tests/`.
