# liveness_whitelist.py
# Suppressions for `aila.tools.liveness_audit` findings that are known
# false positives -- keys / columns whose read is INHERENTLY invisible
# to any static analyzer (getattr with an f-string, dict-splat of
# dynamic origin, raw SQL, an operator-supplied key from a request body,
# etc.). Every entry MUST cite the specific mechanism that clears it.
# See `src/aila/tools/liveness_audit.py` for the rule docstrings and
# their precision limits.
#
# Format:
#   LIVENESS_WHITELIST = [
#       ("path_or_key_substring", "rule_name", "human-readable reason"),
#       ...
#   ]
#
# Suppression semantics:
#   * ``rule_name`` must match the finding's rule exactly.
#   * ``path_or_key_substring`` must appear in the finding's message.
#   * ``reason`` is INFORMATIONAL only -- it lives here so a reader
#     knows WHY the entry exists; the finding message never contains it.
# The whitelist runs in loose match mode: a per-key entry covers every
# site whose finding message names that key.

LIVENESS_WHITELIST = [
    # --- R1 unread_config_key ---------------------------------------------
    # Per-provider TLS-verify toggles are read through
    # ``getattr(config, f"{provider_name}_verify_tls", True)`` in
    # ``src/aila/modules/vulnerability/providers/_http.py``. The f-string
    # starts with an interpolation so the prefix corpus can never cover
    # them; the read is real and per-provider, sourced from
    # ``VulnerabilityConfigSchema``. Rule 5 in the module's config_schema
    # docstring documents the pattern.
    (
        "nvd_verify_tls", "unread_config_key",
        "read via getattr(config, f'{provider_name}_verify_tls') in "
        "modules/vulnerability/providers/_http.py::_resolve_verify_tls",
    ),
    (
        "osv_verify_tls", "unread_config_key",
        "read via getattr(config, f'{provider_name}_verify_tls') in "
        "modules/vulnerability/providers/_http.py::_resolve_verify_tls",
    ),
    (
        "epss_verify_tls", "unread_config_key",
        "read via getattr(config, f'{provider_name}_verify_tls') in "
        "modules/vulnerability/providers/_http.py::_resolve_verify_tls",
    ),
    (
        "kev_verify_tls", "unread_config_key",
        "read via getattr(config, f'{provider_name}_verify_tls') in "
        "modules/vulnerability/providers/_http.py::_resolve_verify_tls",
    ),
    (
        "alpine_verify_tls", "unread_config_key",
        "read via getattr(config, f'{provider_name}_verify_tls') in "
        "modules/vulnerability/providers/_http.py::_resolve_verify_tls",
    ),
    (
        "arch_verify_tls", "unread_config_key",
        "read via getattr(config, f'{provider_name}_verify_tls') in "
        "modules/vulnerability/providers/_http.py::_resolve_verify_tls",
    ),
]
