"""Fixtures for the deep L2 / DA detectors (feat/deep-lowlevel-50).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate";
CLEAN[id] MUST stay silent under ALL three L2 detectors.
"""
import hashlib
import json

# ---------------------------------------------------------------------------
# 17. cross_rollup_sequencer_liveness_monitor
# ---------------------------------------------------------------------------

_L2_VULN = json.dumps({
    "batches": [
        {"batch_number": 1, "timestamp": 1_700_000_000, "tx_count": 12},
        {"batch_number": 2, "timestamp": 1_700_000_600, "tx_count": 9},
        {"batch_number": 3, "timestamp": 1_700_008_200, "tx_count": 4},
        {"batch_number": 4, "timestamp": 1_700_008_800, "tx_count": 0},
        {"batch_number": 5, "timestamp": 1_700_009_400, "tx_count": 0},
        {"batch_number": 6, "timestamp": 1_700_010_000, "tx_count": 0},
        {"batch_number": 7, "timestamp": 1_700_010_600, "tx_count": 0},
        {"batch_number": 8, "timestamp": 1_700_011_200, "tx_count": 0},
    ],
    "now": 1_700_020_000,
})

_L2_CLEAN = json.dumps({
    "batches": [
        {"batch_number": 1, "timestamp": 1_700_000_000, "tx_count": 12},
        {"batch_number": 2, "timestamp": 1_700_000_600, "tx_count": 9},
        {"batch_number": 3, "timestamp": 1_700_001_200, "tx_count": 4},
        {"batch_number": 4, "timestamp": 1_700_001_800, "tx_count": 7},
    ],
    "now": 1_700_002_400,
})

# ---------------------------------------------------------------------------
# 18. optimistic_fraud_proof_challenge_window_tracker
# ---------------------------------------------------------------------------

_FRAUD_VULN = json.dumps({
    "challenge_period_s": 86400,
    "finalized_roots": [
        {"id": "root-vuln", "submitted_at": 1_700_000_000,
         "finalized_at": 1_700_086_400, "dispute_pending": True},
    ],
})

_FRAUD_CLEAN = json.dumps({
    "challenge_period_s": 604800,
    "finalized_roots": [
        {"id": "root-clean", "submitted_at": 1_700_000_000,
         "finalized_at": 1_700_604_800, "dispute_pending": False},
    ],
})

# ---------------------------------------------------------------------------
# 19. blob_kzg_commitment_da_correlator
# ---------------------------------------------------------------------------

def _blob(commitment: bytes, wrong_hash: bool = False) -> dict:
    good = b"\x01" + hashlib.sha256(commitment).digest()[1:]
    vh = ("0x" + "00" * 32) if wrong_hash else "0x" + good.hex()
    return {
        "commitment": "0x" + commitment.hex(),
        "versioned_hash": vh,
        "data_available": not wrong_hash,
    }


_BLOB_VULN = json.dumps({"blobs": [_blob(b"\x11" * 48, wrong_hash=True)]})
_BLOB_CLEAN = json.dumps({"blobs": [_blob(b"\x11" * 48)]})

VULN = {
    "cross_rollup_sequencer_liveness_monitor": _L2_VULN,
    "optimistic_fraud_proof_challenge_window_tracker": _FRAUD_VULN,
    "blob_kzg_commitment_da_correlator": _BLOB_VULN,
}

CLEAN = {
    "cross_rollup_sequencer_liveness_monitor": _L2_CLEAN,
    "optimistic_fraud_proof_challenge_window_tracker": _FRAUD_CLEAN,
    "blob_kzg_commitment_da_correlator": _BLOB_CLEAN,
}
