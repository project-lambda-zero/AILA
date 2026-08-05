Audit APK static check **{check_id}** ({group}) on APK `{package}`
(versionName {version_name}, sha256 {sha256}...). Use audit_mcp index
`{index_id}` for the jadx-decompiled tree ({jadx_class_count} classes);
`read_lines` also reaches AndroidManifest.xml + res/ under that index.

## {title}

{description}

This is a concrete, statically-answerable check -- a definite finding or a
cited negative, not a compliance opinion. A clean result is valid ONLY
after the evidence below is examined; cite `file:line` for every claim.
{polarity_block}
## Verification steps

{steps_block}
{evidence_block}
## Evidence hints (seed `mcp__audit_mcp_semantic_search` / `search_functions` / `search_constants`)

{hints_block}

## Load-bearing APIs / manifest attributes

{apis_block}

## Mapping

- CWE: {cwe_block}
- OWASP MASVS v2.1.0: {masvs_block}
