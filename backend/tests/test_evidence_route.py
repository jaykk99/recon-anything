"""Evidence routing: only source-dependent findings block on acquisition.

The batch's "no source" bucket mixed bytecode-checkable rows with rows
that genuinely need a read, so nothing drained. Checks that:
  * constants/selectors/layout route to bytecode,
  * runtime reads (owner, admin slot, balances) route to runtime,
  * already-decoded slices (unchecked arithmetic) route to decoded,
  * access control and recipient routing route to source,
  * unknown vocabulary defaults to source (conservative),
  * split() partitions without mutating input and reports honest shares.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import evidence_route as er  # noqa: E402


def _f(key, plugin="deep_audit8"):
    return {"key": key, "plugin": plugin, "category": "web3"}


def test_bytecode_settleable():
    for key in ("hardcoded_hash_constant_mismatch",
                "permit_domain_mismatch",
                "zero_address_check_missing"):
        assert er.evidence_for(_f(key)) == "bytecode", key


def test_runtime_settleable():
    assert er.evidence_for(_f("proxy_admin_slot_mismatch")) == "runtime"
    assert er.evidence_for(_f("owner_renounced")) == "runtime"
    assert er.evidence_for(_f("balance_mismatch")) == "runtime"


def test_decoded_does_not_re_acquire():
    finding = _f("unchecked_math_user_input", "deep_audit6")
    assert er.evidence_for(finding) == "decoded"
    assert er.needs_acquisition(finding) is False


def test_source_required():
    assert er.evidence_for(_f("access_control_flaw")) == "source"
    assert er.evidence_for(_f("recipient_mismatch")) == "source"
    assert er.evidence_for(_f("withdraw_authorization")) == "source"


def test_unknown_defaults_to_source():
    assert er.evidence_for(_f("some_new_detector")) == "source"
    assert er.evidence_for("not a dict") == "source"


def test_split_partitions_and_reports():
    rows = [_f("unchecked_math_user_input", "deep_audit6"),
            _f("hardcoded_hash_constant_mismatch"),
            _f("owner_renounced"),
            _f("access_control_flaw"),
            _f("recipient_mismatch")]
    out = er.split(rows)
    assert len(out["no_acquisition"]) == 3
    assert len(out["needs_acquisition"]) == 2
    assert out["total"] == 5
    assert out["counts"] == {"bytecode": 1, "runtime": 1, "decoded": 1,
                            "source": 2}
    assert out["acquisition_share"] == 0.4
    assert all(r["evidence_required"] != "source"
               for r in out["no_acquisition"])
    # input untouched
    assert "evidence_required" not in rows[0]


def test_split_never_raises():
    out = er.split([None, "x", {"key": None}])
    assert out["total"] == 1  # only the dict row counts


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} evidence route tests passed")


if __name__ == "__main__":
    _run_all()
