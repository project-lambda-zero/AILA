"""Platform agent runtime primitives (RFC-03).

Per-turn reasoning primitives shared by every module's investigation
engine. Modules supply their record types, prompts, tool specs, and
submit gates; the platform owns the turn mechanics. Phase 1 lands the
two zero-drift lifts: the operator-intent classifier and the automatic
operator-steering injector.
"""
from __future__ import annotations

from aila.platform.agents.auto_steering import maybe_post_auto_steering
from aila.platform.agents.intent_classifier import classify_intent

__all__ = ["classify_intent", "maybe_post_auto_steering"]
