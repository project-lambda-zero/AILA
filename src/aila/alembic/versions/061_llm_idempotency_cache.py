"""llm_idempotency_cache -- request-key keyed cache for retry-safe LLM calls.

Adds:
  - `llm_idempotency_cache` table

Schema:
  request_key      VARCHAR(64) PRIMARY KEY  -- sha256 of (inv,branch,turn,prompt_hash)
  investigation_id VARCHAR(36) NOT NULL     -- for cascade-delete on /reset
  branch_id        VARCHAR(36)              -- nullable: not all callers know
  turn_number      INT
  response_json    TEXT NOT NULL
  prompt_tokens    INT DEFAULT 0
  completion_tokens INT DEFAULT 0
  cost_usd         FLOAT DEFAULT 0.0
  created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
  expires_at       TIMESTAMP WITH TIME ZONE NOT NULL  -- TTL 7d, periodic prune

The LLM client checks this cache by request_key before every API call. On
HIT, returns the cached response and skips the network round-trip -- the
exact same prompt cannot produce a different answer on retry, but DOES
cost real money every time. On MISS, calls the API, persists the response
under request_key, returns.

When run_vr_investigate fires with max_tries>1 and the first try crashes
after the LLM call but before the tool result is durably saved, the retry
gets the cached LLM response back and proceeds directly to the tool
dispatch -- no duplicate Claude call, no double-billing.

Cache key derivation is the caller's responsibility (see chat_structured
in aila/platform/llm/client.py). The caller decides what counts as
"same request" -- for vr investigations this includes the case_state hash
so a different turn with different context yields a different key even
if the user_prompt accidentally collides.

Index on (investigation_id, created_at) supports /reset cleanup and
periodic TTL prune. Primary key on request_key gives O(1) hit lookup.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "061_llm_idempotency_cache"
down_revision = "060_vr_target_analysis_stages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "llm_idempotency_cache",
        sa.Column("request_key", sa.String(length=64), primary_key=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("turn_number", sa.Integer(), nullable=True),
        sa.Column("response_json", sa.Text(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP + INTERVAL '7 days'"),
        ),
    )
    op.create_index(
        "ix_llm_idempotency_inv_created",
        "llm_idempotency_cache",
        ["investigation_id", "created_at"],
    )
    op.create_index(
        "ix_llm_idempotency_expires",
        "llm_idempotency_cache",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_llm_idempotency_expires", table_name="llm_idempotency_cache")
    op.drop_index("ix_llm_idempotency_inv_created", table_name="llm_idempotency_cache")
    op.drop_table("llm_idempotency_cache")
