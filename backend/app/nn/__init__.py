"""Neural / probabilistic triage modules for ReconAnything.

- active_inference: Active Inference & Free Energy Principle loop
  that replaces the static queue order with EIG-ranked recon
  queries (see backend/docs/nn-active-inference.md).
"""
from .active_inference import (  # noqa: F401
    ActiveInferenceLoop,
    Belief,
    Query,
    pick_next_contract,
    pick_next_contracts,
)
