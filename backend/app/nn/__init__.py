"""NN tooling for ReconAnything: triage scoring + program synthesis.

``synthesis`` is the Sandboxed Synthesizer (program synthesis /
self-modifying tooling): it reverse-engineers unknown formats from
examples, generates decoder source, verifies it with a strict AST
allowlist, executes it only inside an isolated subprocess against
held-out fixtures, and stages passing tools for human review. Detection
only; synthesized tools never auto-merge, never auto-deploy, never touch
the live scanner, and never predict VERIFIED_REAL.
"""
from __future__ import annotations

from .synthesis import (
    ASTVerifier,
    SandboxResult,
    SandboxRunner,
    Schema,
    SchemaInferer,
    SynthesisError,
    SynthesisPipeline,
    SynthesisReport,
    Synthesizer,
    VerificationResult,
    stage_for_review,
    synthesize,
    tool_id_for,
)

__all__ = [
    "ASTVerifier",
    "SandboxResult",
    "SandboxRunner",
    "Schema",
    "SchemaInferer",
    "SynthesisError",
    "SynthesisPipeline",
    "SynthesisReport",
    "Synthesizer",
    "VerificationResult",
    "stage_for_review",
    "synthesize",
    "tool_id_for",
]
