"""Bytecode-family clustering: one read per family, verdicts propagated.

The batch's biggest lever: the same runtime bytecode sits behind hundreds
of addresses, so reading and adjudicating each one re-derives one verdict.
Checks that:
  * identical runtime hashes (per chain) collapse into one cluster,
  * the representative prefers verified / sourced / most findings,
  * different chains never merge (immutables differ per chain),
  * records without a hash stay singletons flagged needs_hash,
  * verdicts propagate to every member and join back onto rows,
  * reduction and summary counts are honest,
  * malformed input never raises.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import source_clusters as sc  # noqa: E402


def _rec(addr, hash_, chain="bsc", verified=False, source="", findings=None):
    rec = {"address": addr, "runtime_hash": hash_, "chain": chain,
           "verified": verified, "source": source}
    if findings is not None:
        rec["findings"] = findings
    return rec


def test_same_hash_collapses():
    rows = [_rec("0x" + f"{i:040x}", "aaa") for i in range(5)]
    report = sc.cluster(rows)
    assert report["address_count"] == 5
    assert report["cluster_count"] == 1
    assert report["clusters"][0]["size"] == 5
    assert report["reduction"] == 0.8


def test_representative_prefers_verified_then_findings():
    rows = [
        _rec("0x" + "b" * 40, "aaa"),
        _rec("0x" + "a" * 40, "aaa", verified=True),
        _rec("0x" + "c" * 40, "aaa", findings=[1, 2, 3]),
    ]
    rep = sc.cluster(rows)["clusters"][0]["representative"]
    assert rep == "0x" + "a" * 40
    rows = [_rec("0x" + "c" * 40, "aaa", findings=[1, 2, 3]),
            _rec("0x" + "b" * 40, "aaa")]
    rep = sc.cluster(rows)["clusters"][0]["representative"]
    assert rep == "0x" + "c" * 40


def test_chains_do_not_merge():
    rows = [_rec("0x" + "a" * 40, "aaa", chain="eth"),
            _rec("0x" + "b" * 40, "aaa", chain="bsc")]
    report = sc.cluster(rows)
    assert report["cluster_count"] == 2


def test_missing_hash_is_a_flagged_singleton():
    report = sc.cluster([{"address": "0x" + "a" * 40, "chain": "bsc"}])
    cl = report["clusters"][0]
    assert cl["size"] == 1 and cl["needs_hash"] is True
    assert report["unhashed_clusters"] == 1


def test_verdict_propagates_to_members():
    rows = [_rec("0x" + f"{i:040x}", "aaa") for i in range(3)]
    report = sc.cluster(rows)
    cid = report["clusters"][0]["id"]
    stamped = sc.propagate(report, cid, "fp", "registry-gated mint")
    verdicts = sc.verdicts_for(stamped)
    assert set(verdicts.values()) == {"fp"}
    assert len(verdicts) == 3
    # originals are untouched
    assert sc.verdicts_for(report)["0x" + f"{0:040x}"] == "unread"
    assert stamped["clusters"][0]["note"] == "registry-gated mint"


def test_apply_verdicts_joins_back_onto_rows():
    rows = [_rec("0x" + f"{i:040x}", "aaa", findings=[1])
            for i in range(2)]
    report = sc.cluster(rows)
    cid = report["clusters"][0]["id"]
    stamped = sc.propagate(report, cid, "tp", "unguarded mint")
    joined = sc.apply_verdicts(rows, stamped)
    assert all(r["bytecode_verdict"] == "tp" for r in joined)
    assert all(r["bytecode_cluster"] == cid for r in joined)


def test_summary_counts_unread_members():
    rows = ([_rec("0x" + f"{i:040x}", "aaa") for i in range(4)] +
            [_rec("0x" + f"{i:040x}", "bbb") for i in range(10, 12)])
    report = sc.cluster(rows)
    summary = sc.summary(report)
    assert summary["families"] == 2
    assert summary["addresses"] == 6
    assert summary["unread_addresses"] == 6
    stamped = sc.propagate(report, report["clusters"][0]["id"], "fp")
    summary = sc.summary(stamped)
    assert summary["verdicts"]["fp"] == 1
    assert summary["unread_addresses"] == report["clusters"][-1]["size"]


def test_unknown_verdict_is_rejected():
    report = sc.cluster([_rec("0x" + "a" * 40, "aaa")])
    try:
        sc.propagate(report, report["clusters"][0]["id"], "probably")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown verdict accepted")


def test_malformed_never_raises():
    report = sc.cluster([None, "x", {"address": None}, {"findings": 3}])
    assert report["cluster_count"] == 0
    assert sc.verdicts_for({"clusters": "nope"}) == {}
    assert sc.summary({})["families"] == 0
    assert sc.apply_verdicts([None, {"x": 1}], {}) == [
        {"x": 1, "bytecode_verdict": "unread", "bytecode_cluster": ""}]


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} source cluster tests passed")


if __name__ == "__main__":
    _run_all()
