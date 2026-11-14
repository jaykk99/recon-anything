"""Neural / game-theoretic triage models for ReconAnything.

Triage only. Nothing in this package predicts VERIFIED_REAL.

Imports are lazy (PEP 562): importing ``app.nn`` must not import
the submodules, so ``python -m app.nn.marl`` does not trigger a
double-import warning.
"""
from typing import Any

__all__ = [
    "CFR", "KuhnPoker", "MatrixGame", "rock_paper_scissors", "solve",
    "EvasionGame", "evaluate_replay", "replay", "solve_evasion",
]

_LAZY = {
    "CFR": ("cfr", "CFR"),
    "KuhnPoker": ("cfr", "KuhnPoker"),
    "MatrixGame": ("cfr", "MatrixGame"),
    "rock_paper_scissors": ("cfr", "rock_paper_scissors"),
    "solve": ("cfr", "solve"),
    "EvasionGame": ("marl", "EvasionGame"),
    "evaluate_replay": ("marl", "evaluate_replay"),
    "replay": ("marl", "replay"),
    "solve_evasion": ("marl", "solve_evasion"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        module_name, attr = _LAZY[name]
        from importlib import import_module
        module = import_module(f".{module_name}", __package__)
        value = getattr(module, attr)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
