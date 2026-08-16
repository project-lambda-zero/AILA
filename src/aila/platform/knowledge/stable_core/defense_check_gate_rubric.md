<!-- source: src/aila/platform/agents/submit_gates.py::check_defense_verification -->
# Defense-check submit gate rubric (RFC #94)

The platform submit gate rejects any `direct_finding` or
`assessment_report` at medium-or-above confidence whose branch tool-call
history is missing one of the following, based on the claim class:

Overflow / allocation claims (any of `overflow`, `integer_overflow`,
`allocation`, `heap_oob`, `buffer_overflow`, `oob_write`):

1. `read_function` on the allocator used at the vulnerability site
   (for example `av_calloc`, `av_malloc`, `ngx_palloc`,
   `apr_palloc`, `OPENSSL_malloc`, `g_malloc`, `kmalloc`, plain libc
   `malloc` / `calloc` / `realloc`). This proves whether the
   allocator handles the overflow internally.
2. `read_function` on the input reader feeding the overflow operand
   (for example `avio_rb16`, `get_bits_long`, `bytestream2_get_le32`,
   `recv`, `read`, `fread`). This pins the bit-width and maximum
   value that decides whether the overflow is arithmetically possible.

All finding claims (any claim class other than `none` / `generic`):

3. At least one `callers_of` call that traces the vulnerability site
   back to a demuxer, decoder, protocol callback, or API handler
   reachable from untrusted input.

On rejection the gate rewrites the decision to
`action='reasoning'` and injects a steering directive naming the
exact tool call the branch has to make next; the submit is
force-through only after the module's rejection cap (see the
`_defense_check_gate_reject_count` observable).
