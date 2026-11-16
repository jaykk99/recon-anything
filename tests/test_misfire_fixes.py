"""Misfire-guard regression tests (fix-zero-verified, 2026-11-15).

Reconstructed 2026-11-15: the original /tmp/test_misfire_fixes.py was
lost to a VM reboot before it was committed. These 10 tests cover the
same four guards, against the real guard code:

- EOF fires only on bytes starting with the EOF magic EF00
  (deep_lowlevel._analyze_eof)
- ZK nullifier needs a real ZK marker, not a bare withdraw()
  (zero_knowledge_nullifier_audit.analyze)
- BLS needs the literal "bls", not the substring "aggregate"
  (bls_sig_aggregator_audit.analyze)
- unchecked_math skips internal/private functions
  (deep_audit6._analyze_unchecked_math)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.plugins.bsc_common import S  # noqa: E402
from app.plugins.deep_lowlevel import _analyze_eof  # noqa: E402
from app.plugins.deep_audit6 import _analyze_unchecked_math  # noqa: E402
from app.plugins.zero_knowledge_nullifier_audit import analyze as zk_analyze  # noqa: E402
from app.plugins.bls_sig_aggregator_audit import analyze as bls_analyze  # noqa: E402

EOF_SPEC = S("eof_container_code_section_verifier", "deep_lowlevel",
             severity="high", detail="test")
MATH_SPEC = S("unchecked_math_user_input", "deep6",
              severity="high", detail="test")

LEGACY_BYTECODE = (
    "0x608060405234801561001057600080fd5b506040516101e63803806101e6"
    "8339818101604052810190610032919061007a565b80600081905550506100"
    "a0565b60008151905061006b816100e5565b92915050565b60006020828403"
    "19009152908051906020019091908051906020019091905050565b6100a0"
    "816100e5565b81146100ab57600080fd5b50565b6100e2816100d6565b8114"
    "6100ed57600080fd5b50565b6100f9816100e5565b811461010457600080fd"
    "5b50565b61011a816100e5565b811461012557600080fd5b5056fea26469"
    "7066736f6c634300081a0033"
)


# --- EOF: only EF00 bytes are EOF candidates -------------------------------

def test_legacy_bytecode_is_not_eof():
    assert _analyze_eof(LEGACY_BYTECODE, EOF_SPEC) == []


def test_ef00_short_container_is_flagged():
    # "0xef00" alone is too short to even be a candidate (len < 8);
    # a real EF00-prefixed container that fails verification is flagged.
    findings = _analyze_eof("0xef00010100020000006000", EOF_SPEC)
    assert len(findings) >= 1
    assert any("code section" in f["detail"] for f in findings)


def test_ef00_embedded_in_source_is_flagged():
    src = 'bytes memory b = hex"0xEF00010100020000006000";'
    assert len(_analyze_eof(src, EOF_SPEC)) >= 1


# --- ZK nullifier: needs a real ZK marker ---------------------------------

def test_plain_withdraw_without_zk_marker_is_silent():
    text = ("contract Vault { function withdraw(uint256 amount) public {"
            " msg.sender.call{value: amount}(\"\"); } }")
    assert zk_analyze(text, {}) == []


def test_shielded_withdraw_without_nullifier_fires():
    text = ("shielded pool contract: users deposit notes into the "
            "shielded pool and withdraw by presenting a proof.")
    kinds = [f[0] for f in zk_analyze(text, {})]
    assert "zk_nullifier_missing" in kinds


def test_shielded_with_nullifier_but_no_spent_storage_fires():
    text = ("shielded pool withdraw: the nullifier is derived in the "
            "circuit and presented with the proof.")
    kinds = [f[0] for f in zk_analyze(text, {})]
    assert "zk_nullifier_not_stored" in kinds


# --- BLS: needs the literal "bls" ------------------------------------------

def test_aggregate_without_bls_is_silent():
    text = ("Aggregator contract: aggregate() combines oracle reports "
            "and settles the aggregated value on chain.")
    assert bls_analyze(text, {}) == []


def test_bls_without_proof_of_possession_fires():
    text = ("BLS aggregate signatures: bls aggregate() combines "
            "validator signatures into one aggregated signature.")
    kinds = [f[0] for f in bls_analyze(text, {})]
    assert "bls_missing_proof_of_possession" in kinds


# --- unchecked_math: internal/private functions are skipped ----------------

_INTERNAL_SRC = """
contract Vault {
    uint256 public total;
    function _transferShares(uint256 amount) internal {
        unchecked { uint256 x = amount + 1; total += x; }
    }
}
"""

_PUBLIC_SRC = """
contract Vault {
    uint256 public total;
    function add(uint256 amount) public {
        unchecked { uint256 x = amount + 1; total += x; }
    }
}
"""


def test_internal_unchecked_math_is_skipped():
    assert _analyze_unchecked_math(_INTERNAL_SRC, MATH_SPEC) == []


def test_public_unchecked_math_still_fires():
    assert len(_analyze_unchecked_math(_PUBLIC_SRC, MATH_SPEC)) >= 1
