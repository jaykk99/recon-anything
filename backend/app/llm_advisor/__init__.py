"""LLM advisor: the smartest reliable free/keyless model, wired in.

Measured live 2026-11-14 (see EVAL_2026-11-14.md). Winner:
``meromero-26b`` via the Bro gateway, direct fallback chain below.
"""
from .client import DEFAULT_CHAIN, chat, is_refusal
from .enrich import draft_detector, enrich_candidates, stress_hypothesis

__all__ = ["DEFAULT_CHAIN", "chat", "is_refusal", "draft_detector",
           "enrich_candidates", "stress_hypothesis"]
