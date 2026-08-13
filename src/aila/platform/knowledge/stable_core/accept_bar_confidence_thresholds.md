<!-- source: src/aila/platform/llm/gate.py::_resolve_thresholds -->
# Accept-bar confidence thresholds (LLM pipeline gate)

The platform pipeline gate reads three per-task thresholds from
ConfigRegistry keys under the `platform` namespace:

- `llm_pipeline_gate_high_threshold_{task_type}` -- default 0.8.
  A calibrated confidence at or above this bar accepts the response
  without invoking the consensus / verify stage.
- `llm_pipeline_gate_medium_threshold_{task_type}` -- default 0.5.
  Below this bar the low-band consensus path fires.
- `llm_pipeline_gate_reject_threshold_{task_type}` -- default 0.2.
  A calibrated confidence at or below this bar is rejected outright;
  the pipeline emits a rejection observable instead of the model
  output.

A promoted `CalibrationProposalRecord` writes into
`platform.calibration_threshold_{outcome_kind}` and overrides the
per-task `reject_threshold` at gate time, with the invariant that
`medium >= reject` and `high >= medium` after the clamp.

The bar is clamped to `[0.0, 1.0]`. A missing key falls back to the
default above; the gate never crashes on a missing threshold.
