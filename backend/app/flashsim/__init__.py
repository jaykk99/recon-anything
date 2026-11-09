"""Flash-loan simulation matrix (spot-oracle economic-flaw lane).

Local simulation only. Output rows are UNVERIFIED candidates by
construction; this package never emits VERIFIED_REAL (no-simulation rule:
live proof is validator v2's job).
"""
from .matrix import (CANDIDATE_STATUS, SIM_DRAIN_POSITIVE, SIM_ERROR,
                     SIM_NO_EDGE, SIM_NOT_SPOT_ORACLE)

__all__ = ["CANDIDATE_STATUS", "SIM_DRAIN_POSITIVE", "SIM_ERROR",
           "SIM_NO_EDGE", "SIM_NOT_SPOT_ORACLE"]
