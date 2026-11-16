"""Gate tests for the codegen loop's first generated detector:
native_vault_share_inflation (backend/app/plugins/deep_audit.py).

Provenance: drafted by the Bro-gateway LLM advisor chain (raw draft
at backend/scripts/codegen/drafts/native_vault_share_inflation.txt),
reviewed and fixed before install (the raw draft read a "payable"
key _Scope never sets, so it could never fire; see the analyzer
docstring). The gates below are what let it register:

- the planted native-ETH vault fixture MUST fire (exactly 1 finding,
  high severity, candidate class, on deposit);
- WETH9, real OpenZeppelin ERC4626, and guarded vaults MUST stay
  silent (0 findings);
- the OLD vault_share_inflation detector MUST still fire 0 on the
  fixture: that miss is the gap this detector closes;
- the codegen loop's own gate_detector() MUST pass end to end.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.investigator.fixtures import (  # noqa: E402
    VAULT_VULN_SOURCE, WETH9_SOURCE)
from app.plugins.deep_audit import (  # noqa: E402
    SPECS, analyze_deep_source)

SPEC_ID = "native_vault_share_inflation"
OZ_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "codegen", "fixtures", "oz-erc4626.sol")


def _spec(spec_id):
    return [s for s in SPECS if s.id == spec_id][0]


def _run(src, spec_id=SPEC_ID):
    return analyze_deep_source(src, _spec(spec_id)) or []


def test_fires_on_planted_native_vault():
    out = _run(VAULT_VULN_SOURCE)
    assert len(out) == 1, out
    f = out[0]
    assert f["kind"] == SPEC_ID
    assert f["function"] == "deposit"
    assert f["severity"] == "high"
    assert f["report_class"] == "candidate"
    assert "donate" in f["detail"]
    assert "withdrawAll" in f["detail"]


def test_old_detector_misses_the_fixture():
    # The gap: vault_share_inflation needs totalAssets() and the
    # fixture has none, so it fires 0. This test pins the gap so a
    # future refactor that fixes the old detector (or breaks the
    # new one) is visible instead of silent.
    out = _run(VAULT_VULN_SOURCE, "vault_share_inflation")
    assert out == []


def test_weth9_stays_silent():
    assert _run(WETH9_SOURCE) == []


def test_openzeppelin_erc4626_stays_silent():
    assert os.path.isfile(OZ_PATH), "OZ ERC4626 fixture missing"
    with open(OZ_PATH) as fh:
        assert _run(fh.read()) == []


def test_guarded_vaults_stay_silent():
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts"))
    from codegen_loop import load_fixtures  # noqa: E402
    fx = load_fixtures()
    for name in ("guarded_vault_offset", "guarded_vault_dead_shares",
                 "guarded_vault_minimum"):
        assert _run(fx[name]) == [], name


def test_codegen_loop_gate_passes():
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts"))
    from codegen_loop import gate_detector  # noqa: E402
    res = gate_detector(SPEC_ID, "deep_audit")
    assert res["passed"], res


def test_registered_in_discover():
    from app.plugins.registry import discover  # noqa: E402
    assert SPEC_ID in discover()
