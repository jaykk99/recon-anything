"""Cross-modal / multimodal embeddings for the NN triage scorer.

Self-contained: synthetic rows only, no network, no scanner data.
Run:  python -m pytest backend/tests/test_nn_multimodal.py -q
(or: python -m pytest backend/tests/ -q -k multimodal)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.multimodal import (MultimodalEmbedder, extract_modal_texts,
                               tokenize_bytecode)

CODE_A = """function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "insufficient");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
    balances[msg.sender] -= amount;
}"""

CODE_A_RENAMED = """function withdraw(uint256 value) public {
    require(balances[msg.sender] >= value, "insufficient");
    (bool ok, ) = msg.sender.call{value: value}("");
    require(ok, "transfer failed");
    balances[msg.sender] -= value;
}"""

CODE_B = """function setOracle(address feed) external onlyOwner {
    require(feed != address(0), "zero feed");
    priceFeed = AggregatorV3Interface(feed);
    emit OracleUpdated(feed);
}"""


def _row(plugin, key, code, value, label, detail=""):
    return {
        "finding": {
            "plugin": plugin, "key": key, "severity": "high",
            "bounty_value": "high", "confidence": 85, "value": value,
            "recipient_class": "OTHER", "chain": "other",
            "function": "withdraw",
            "evidence": {
                "source_origin": "other", "contract_role": "standalone",
                "risk": "high", "code": code, "detail": detail or value,
                "check": key, "function": "withdraw",
            },
        },
        "label": label, "verdict": "SYNTH", "chain": "other",
        "address": "", "plugin": plugin, "key": key,
        "function": "withdraw",
    }


def _corpus():
    rows = []
    for i in range(4):
        rows.append(_row("crypto_drain_scanner", "unprotected_drain",
                         CODE_A, "attacker drains vault balance", 1,
                         "unprotected drain via reentrant withdraw"))
    for i in range(4):
        rows.append(_row("oracle_trust_assumption_break",
                         "oracle_manipulation", CODE_B,
                         "oracle price can be manipulated", 1,
                         "single oracle feed with no staleness check"))
    for i in range(4):
        rows.append(_row("contract_logic", "access_control_flaw",
                         CODE_B, "owner-only setter missing check", 0,
                         "harmless owner setter, no funds at risk"))
    return rows


def _fitted():
    rows = _corpus()
    emb = MultimodalEmbedder().fit(rows)
    emb.build_index(rows)
    return emb, rows


# --- similarity -----------------------------------------------------------

def test_near_duplicate_contracts_land_close():
    emb, rows = _fitted()
    orig = rows[0]
    dup = _row("crypto_drain_scanner", "unprotected_drain",
               CODE_A_RENAMED, "attacker drains vault balance", 1,
               "unprotected drain via reentrant withdraw")
    unrelated = _row("oracle_trust_assumption_break",
                     "oracle_manipulation", CODE_B,
                     "oracle price can be manipulated", 1,
                     "single oracle feed with no staleness check")
    a, _ = emb.embed_sparse(orig)
    b, _ = emb.embed_sparse(dup)
    c, _ = emb.embed_sparse(unrelated)
    sim_dup = MultimodalEmbedder.cosine_sparse(a, b)
    sim_unrel = MultimodalEmbedder.cosine_sparse(a, c)
    assert sim_dup > 0.6, f"near-duplicate too far: {sim_dup:.3f}"
    assert sim_dup > sim_unrel + 0.2, (
        f"no separation: dup {sim_dup:.3f} vs unrelated {sim_unrel:.3f}")


def test_unrelated_findings_land_far_apart():
    emb, rows = _fitted()
    a, _ = emb.embed_sparse(rows[0])   # drain / CODE_A
    b, _ = emb.embed_sparse(rows[4])   # oracle / CODE_B
    sim = MultimodalEmbedder.cosine_sparse(a, b)
    assert sim < 0.4, f"unrelated rows too close: {sim:.3f}"


def test_same_plugin_retrieval():
    emb, rows = _fitted()
    query = _row("crypto_drain_scanner", "unprotected_drain",
                 CODE_A_RENAMED, "attacker drains vault balance", 1,
                 "unprotected drain via reentrant withdraw")
    neigh = emb.neighbours(emb.embed(query)["dense"], k=5)
    assert neigh, "no neighbours returned"
    same = sum(1 for n in neigh if n["plugin"] == "crypto_drain_scanner")
    assert same >= 3, f"only {same}/5 neighbours share the plugin"


# --- modalities -------------------------------------------------------------

def test_missing_modalities_are_safe():
    emb, _rows = _fitted()
    empty = {"finding": {"plugin": "", "key": "", "severity": "",
                         "confidence": 0, "value": "",
                         "recipient_class": "", "chain": "",
                         "function": "", "evidence": {}},
             "label": 0, "verdict": "SYNTH", "chain": "",
             "address": "", "plugin": "", "key": "", "function": ""}
    sparse, presence = emb.embed_sparse(empty)
    assert sparse == {}
    assert presence == [0.0, 0.0, 0.0]
    dense = emb.project(sparse)
    assert dense == [0.0] * 32
    # k-NN falls back to the train base rate, never a confident score.
    assert emb.knn_score(dense) == emb.train_pos_rate


def test_opcode_histogram_counts_as_bytecode():
    emb, _rows = _fitted()
    row = _row("contract_recon", "opcode_profile", CODE_A,
               "opcode histogram", 0)
    row["finding"]["evidence"]["opcodes"] = {"CALL": 2, "SSTORE": 1}
    sparse, presence = emb.embed_sparse(row)
    assert presence[1] == 1.0, "histogram must light the bytecode block"
    texts = extract_modal_texts(row)
    assert texts["opcodes"] == {"CALL": 2, "SSTORE": 1}


def test_hex_bytecode_decodes_to_mnemonics():
    toks = tokenize_bytecode(None, "0x6001600201")
    assert "op:PUSH1" in toks and "op:ADD" in toks
    assert "op:PUSH1>PUSH1" in toks, "bigrams must exist for sequences"
    emb, _rows = _fitted()
    row = _row("contract_recon", "bytecode_profile", "", "raw bytecode", 0)
    row["finding"]["evidence"]["bytecode"] = "0x6001600201"
    _sparse, presence = emb.embed_sparse(row)
    assert presence[1] == 1.0


def test_source_text_is_the_code_excerpt():
    row = _row("crypto_drain_scanner", "unprotected_drain",
               CODE_A, "attacker drains vault balance", 1)
    texts = extract_modal_texts(row)
    assert "withdraw" in texts["source"]
    assert "balances" in texts["source"]
    assert "crypto_drain_scanner" in texts["finding"]


# --- determinism / fitting hygiene -------------------------------------------

def test_embedding_is_deterministic():
    emb, rows = _fitted()
    a = emb.embed(rows[0])
    b = emb.embed(rows[0])
    assert a["dense"] == b["dense"]
    assert a["sparse"] == b["sparse"]
    emb2 = MultimodalEmbedder().fit(rows)
    assert emb2.embed(rows[0])["dense"] == a["dense"]


def test_novel_test_token_does_not_break_embedding():
    emb, rows = _fitted()
    novel = _row("brand_new_plugin", "zzq_novel_key",
                 "function zzqNovelThing() public { }",
                 "a finding with tokens never seen in training", 0)
    emb_out = emb.embed(novel)
    assert all(v == v and abs(v) != float("inf")
               for v in emb_out["dense"])
    norm = sum(v * v for v in emb_out["dense"]) ** 0.5
    assert norm <= 1.0 + 1e-9


def test_knn_head_separates_clusters():
    emb, rows = _fitted()
    q_drain = _row("crypto_drain_scanner", "unprotected_drain",
                   CODE_A_RENAMED, "attacker drains vault balance", 1)
    # Same source code as the oracle rows, but the finding text is
    # the harmless contract_logic one: the finding modality must
    # pull it toward the label-0 cluster, not the label-1 oracle
    # rows that share the code.
    q_benign = _row("contract_logic", "access_control_flaw",
                    CODE_B, "owner-only setter missing check", 0,
                    "harmless owner setter, no funds at risk")
    s_drain = emb.knn_score(emb.embed(q_drain)["dense"])
    s_benign = emb.knn_score(emb.embed(q_benign)["dense"])
    assert s_drain > 0.7, f"drain-like query scored {s_drain:.3f}"
    assert s_benign < 0.5, f"benign-like query scored {s_benign:.3f}"


# --- end to end: train + score with the multimodal block -----------------------

def _write_tiny_dataset(tmpdir):
    cands, batches = [], {"findings": []}
    for i in range(30):
        plugin = "crypto_drain_scanner" if i % 2 == 0 else "contract_logic"
        code = CODE_A if i % 2 == 0 else CODE_B
        cands.append({
            "chain": "bsc", "address": "0x%040x" % (i + 1),
            "plugin": plugin, "key": "k%d" % i,
            "severity": "high",
            "validation": {"verdict": "UNVERIFIED" if i % 3 else "FALSE_POSITIVE"},
            "function": "withdraw", "value": "v%d" % i,
        })
        batches["findings"].append({
            "plugin": plugin, "key": "k%d" % i, "severity": "high",
            "bounty_value": "high", "confidence": 85,
            "value": "synthetic finding %d" % i,
            "recipient_class": "OTHER",
            "evidence": {
                "source_origin": "Sourcify v2",
                "contract_role": "standalone", "risk": "high",
                "code": code, "detail": "synthetic detail %d" % i,
                "check": "k%d" % i, "function": "withdraw",
            },
        })
    cpath = os.path.join(tmpdir, "candidates.jsonl")
    bpath = os.path.join(tmpdir, "batches.jsonl")
    with open(cpath, "w", encoding="utf-8") as fh:
        for c in cands:
            fh.write(json.dumps(c) + "\n")
    # One batch row per candidate, same (chain, address, plugin,
    # key): that is the join key build_dataset uses, so every
    # candidate enriches with its own code/detail evidence.
    with open(bpath, "w", encoding="utf-8") as fh:
        for c, f in zip(cands, batches["findings"]):
            fh.write(json.dumps({
                "chain": "bsc", "address": c["address"],
                "findings": [f],
            }) + "\n")
    return cpath, bpath


def test_train_multimodal_end_to_end(tmp_path):
    from app.nn.pipeline import load_model, score_finding_dicts
    from app.nn.train import train

    cpath, bpath = _write_tiny_dataset(str(tmp_path))
    out = os.path.join(str(tmp_path), "out")
    result = train(cpath, bpath, out, epochs=3, hidden="8,4",
                   holdout="own", multimodal=True)
    assert result["holdout"] == "own"
    assert result["test_rows"] == 6  # 20% of 30 own rows
    assert result["n_multimodal_features"] == 35
    assert result["multimodal"] is not None
    assert "retrieval" in result["multimodal"]
    assert os.path.exists(os.path.join(out, "weights.json"))
    model = load_model(os.path.join(out, "weights.json"))
    assert model is not None
    _net, _spec, meta = model
    assert "multimodal" in meta
    scored = score_finding_dicts(
        [{"plugin": "crypto_drain_scanner", "key": "k0",
          "severity": "high", "bounty_value": "high", "confidence": 85,
          "value": "synthetic finding", "recipient_class": "OTHER",
          "chain": "bsc", "function": "withdraw",
          "evidence": {"source_origin": "Sourcify v2",
                       "contract_role": "standalone", "risk": "high",
                       "code": CODE_A, "detail": "synthetic detail",
                       "check": "k0", "function": "withdraw"}}],
        model=model)
    assert scored[0]["nn_score"] is not None
    assert "nn_blend_score" in scored[0]
    assert "nn_neighbours" in scored[0]
    assert len(scored[0]["nn_neighbours"]) == 3


def test_train_without_multimodal_still_works(tmp_path):
    from app.nn.pipeline import load_model, score_finding_dicts
    from app.nn.train import train

    cpath, bpath = _write_tiny_dataset(str(tmp_path))
    out = os.path.join(str(tmp_path), "out")
    result = train(cpath, bpath, out, epochs=3, hidden="8,4",
                   holdout="own", multimodal=False)
    assert result["multimodal"] is None
    assert result["n_multimodal_features"] == 0
    model = load_model(os.path.join(out, "weights.json"))
    scored = score_finding_dicts(
        [{"plugin": "contract_logic", "key": "k1",
          "severity": "high", "bounty_value": "high", "confidence": 85,
          "value": "synthetic finding", "recipient_class": "OTHER",
          "chain": "bsc", "function": "withdraw",
          "evidence": {"source_origin": "Sourcify v2",
                       "contract_role": "standalone", "risk": "high",
                       "code": CODE_B, "detail": "synthetic detail",
                       "check": "k1", "function": "withdraw"}}],
        model=model)
    assert scored[0]["nn_score"] is not None
    assert "nn_blend_score" not in scored[0]
