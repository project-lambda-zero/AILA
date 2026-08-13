<!-- source: src/aila/modules/vr/agents/prompts/system_audit.md ("The submit gate") -->
# Variant-hunt submit-gate exhaustion checklist (VR)

The variant-hunt submit gate in `vuln_researcher.run_turn` rejects a
terminal submit on a `kind=variant_hunt` investigation when
`variant_hunt_orders` is empty AND the first 400 characters of the
`answer` do not open with one of the recognised exhaustion phrases.
Two ways to satisfy the gate:

Path A -- populate `variant_hunt_orders`. Each entry MUST cite a
`(file, function)` pair the agent read. Required fields: `title`,
`hypothesis`, `file`, `function`. `target_id: null` means the same
repository. The `hypothesis` is the child investigation's kill
criterion: name the function, the untrusted-input parameter, the
expected unsafe behaviour, and the suspected sink location.

Path B -- submit with the `answer` opening with one of these EXACT
phrases (case-insensitive, matched against the first 400 characters):

- `NO FURTHER VARIANTS`
- `NO NEW VARIANTS`
- `NO ADJACENT VARIANTS`
- `NO REMAINING VARIANTS`
- `NO OTHER VARIANTS`
- `NO VARIANT EXISTS`
- `NO VARIANT FOUND`
- `NO VARIANT REMAINS`
- `VARIANT HUNT EXHAUSTED`
- `VARIANT HUNT COMPLETE`
- `EXHAUSTIVE NEGATIVE`
- `EXHAUSTIVE SEARCH`

Synonyms outside this list do NOT satisfy the gate. After
`VR_VARIANT_HUNT_REJECT_CAP` (default 3) consecutive rejections the
submit is forced through and stamped `payload.variant_hunt_advisory`.
