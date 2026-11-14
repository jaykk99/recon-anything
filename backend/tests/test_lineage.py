"""Unit gate for deployment-lineage clustering (app/lineage.py).

Pure, offline, deterministic: no network, no chain, no clock. Checks that:
  * a contract and its deployer cluster (creation is not a payment),
  * one private funder links two otherwise unrelated deployers,
  * exchange/bridge/mixer/sanctioned funders never link addresses,
  * hub funders (exchange-like fan-out) never link addresses,
  * shared standard bytecode alone does NOT merge unrelated contracts,
  * the same CREATE2 recipe (init code + salt) does merge them,
  * output is order-independent and stable,
  * clusters become funnel leads tied to the audited contracts,
  * malformed input never raises.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import lineage  # noqa: E402
from app.funnel import build_funnel  # noqa: E402


def _a(n: int) -> str:
    return "0x" + f"{n:040x}"


CONTRACT_A, CONTRACT_B = _a(0xAA01), _a(0xBB01)
DEPLOYER_1, DEPLOYER_2 = _a(0xD001), _a(0xD002)
FUNDER = _a(0xF00D)
EXCHANGE = _a(0xE0E0)


def _edge(frm, to, asset="native", amount=10, tx="0xtx", block=1):
    return {"from": frm, "to": to, "asset": asset, "amount_raw": amount,
            "tx_hash": tx, "block": block}


def test_contract_and_deployer_cluster():
    report = lineage.cluster(contracts=[{"address": CONTRACT_A,
                                         "deployer": DEPLOYER_1}])
    assert report["cluster_count"] == 1
    cl = report["clusters"][0]
    assert set(cl["members"]) == {CONTRACT_A, DEPLOYER_1}
    assert "shared_deployer" in cl["signals"]
    assert cl["confidence"] >= 55
    assert cl["contracts"] == [CONTRACT_A]
    assert cl["evidence"] and CONTRACT_A in cl["evidence"][0]["addresses"]


def test_shared_private_funder_links_two_deployers():
    report = lineage.cluster(
        edges=[_edge(FUNDER, DEPLOYER_1, tx="0xaa"),
               _edge(FUNDER, DEPLOYER_2, tx="0xbb")],
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2}])
    assert report["cluster_count"] == 1
    cl = report["clusters"][0]
    assert cl["size"] == 5, cl["members"]
    assert set(cl["contracts"]) == {CONTRACT_A, CONTRACT_B}
    assert "funded" in cl["signals"]
    assert cl["risk"] in ("medium", "high")


def test_exchange_funder_never_links():
    report = lineage.cluster(
        edges=[_edge(EXCHANGE, DEPLOYER_1), _edge(EXCHANGE, DEPLOYER_2)],
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2}],
        labels={EXCHANGE: {"label": "Binance Hot Wallet",
                           "category": "exchange"}})
    # each deployer still clusters with its own contract, but the exchange
    # must not merge the two lineages
    assert report["cluster_count"] == 2, report["clusters"]
    anchors = {c["anchor"] for c in report["clusters"]}
    assert len(anchors) == 2
    assert all(CONTRACT_A not in c["members"] or CONTRACT_B not in c["members"]
               for c in report["clusters"])
    assert EXCHANGE in report["input"]["terminus_funders"]


def test_hub_funder_never_links():
    edges = [_edge(FUNDER, _a(0x9000 + i)) for i in range(30)]
    report = lineage.cluster(edges=edges)
    assert report["cluster_count"] == 0, report["clusters"]


def test_shared_standard_bytecode_does_not_merge():
    report = lineage.cluster(
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1,
                    "bytecode_hash": "std-erc20"},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2,
                    "bytecode_hash": "std-erc20"}])
    # each deployer still clusters with its own contract; the shared
    # standard bytecode must not put both contracts in one cluster
    assert report["cluster_count"] == 2, report["clusters"]
    assert all(not ({CONTRACT_A, CONTRACT_B} <= set(c["contracts"]))
               for c in report["clusters"])


def test_same_create2_recipe_merges():
    report = lineage.cluster(
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1,
                    "bytecode_hash": "init-hash", "salt": "0xsalt"},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2,
                    "bytecode_hash": "init-hash", "salt": "0xsalt"}])
    assert report["cluster_count"] == 1
    cl = report["clusters"][0]
    assert set(cl["contracts"]) == {CONTRACT_A, CONTRACT_B}
    assert "init_code" in cl["signals"]


def test_order_independent_and_stable():
    inputs = dict(
        edges=[_edge(FUNDER, DEPLOYER_1), _edge(FUNDER, DEPLOYER_2)],
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2}])
    first = lineage.cluster(**inputs)
    reversed_inputs = dict(edges=list(reversed(inputs["edges"])),
                           contracts=list(reversed(inputs["contracts"])))
    second = lineage.cluster(**reversed_inputs)
    assert [(c["id"], c["members"], c["confidence"])
            for c in first["clusters"]] == \
           [(c["id"], c["members"], c["confidence"])
            for c in second["clusters"]]


def test_sanctioned_label_raises_risk():
    neutral = lineage.cluster(contracts=[{"address": CONTRACT_A,
                                          "deployer": DEPLOYER_1}])
    flagged = lineage.cluster(
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1}],
        labels={DEPLOYER_1: {"label": "OFAC SDN address",
                             "category": "sanctioned",
                             "severity": "high"}})
    assert neutral["clusters"][0]["risk"] != "high"
    assert flagged["clusters"][0]["risk"] == "high"
    assert flagged["clusters"][0]["labels"][0]["category"] == "sanctioned"


def test_clusters_become_funnel_leads():
    report = lineage.cluster(
        edges=[_edge(FUNDER, DEPLOYER_1), _edge(FUNDER, DEPLOYER_2)],
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2}])
    rows = lineage.to_findings(report)
    assert len(rows) == 2
    assert {r["key"] for r in rows} == {"deployment_cluster"}
    funnel = build_funnel(rows)
    assert funnel["lead_count"] == 2
    lead = funnel["leads"][0]
    assert lead["class"] == "deployment_lineage"
    assert lead["asset"].startswith("0x")
    assert "0x" in lead["asset"] and "\u2026" in lead["asset"]
    assert any("owner()" in c for c in lead["manual_checks"])


def test_to_findings_caps_rows_per_cluster():
    contracts = [{"address": _a(0xAA00 + i), "deployer": DEPLOYER_1}
                 for i in range(6)]
    report = lineage.cluster(contracts=contracts)
    rows = lineage.to_findings(report, max_per_cluster=3)
    assert len(rows) == 3


def test_augment_from_provenance_findings():
    row = {"plugin": "contract_creator_osint", "category": "web3",
           "key": "creator_fresh_wallet_deployer", "value": "deployed",
           "confidence": 80,
           "evidence": {"severity": "medium",
                        "hit": {"contract": CONTRACT_A,
                                "creator": DEPLOYER_1,
                                "funder": FUNDER,
                                "funder_label": "Fresh wallet"}}}
    rows = lineage.augment([row])
    assert len(rows) == 2
    assert rows[1]["key"] == "deployment_cluster"
    assert rows[1]["evidence"]["contract"] == CONTRACT_A


def test_malformed_input_never_raises():
    report = lineage.cluster(edges=[None, "x", {"from": 5}, {"to": None}],
                             contracts="not-a-list", labels=[], deployers={})
    assert report["cluster_count"] == 0
    assert lineage.to_findings({"clusters": "nope"}) == []
    assert lineage.render_markdown({"clusters": []}) == ""
    assert lineage.augment([None, {"x": 1}]) == [{"x": 1}]


def test_markdown_section():
    report = lineage.cluster(
        edges=[_edge(FUNDER, DEPLOYER_1), _edge(FUNDER, DEPLOYER_2)],
        contracts=[{"address": CONTRACT_A, "deployer": DEPLOYER_1},
                   {"address": CONTRACT_B, "deployer": DEPLOYER_2}])
    md = lineage.render_markdown(report)
    assert md.startswith("## Deployment lineage")
    assert CONTRACT_A in md and "hypothes" in md.lower()


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} lineage tests passed")


if __name__ == "__main__":
    _run_all()
