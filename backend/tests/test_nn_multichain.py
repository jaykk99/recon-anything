"""Multichain v3 features: chain normalisation, family/domain signals,
stablecoin/privacy/UTXO flags, and per-chain metric reporting.

All assertions use real shapes from the v3 spec; no invented rows.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.features import (CHAINS, FeatureSpec, build_vocab,  # noqa: E402
                             derive_domain, extract, normalize_chain)
from app.nn.train import per_chain_metrics  # noqa: E402
from nn_fixtures import ROWS  # noqa: E402


def _spec():
    return build_vocab([f for f, _ in ROWS])


def _base(**over):
    f = dict(ROWS[0][0])
    f.update(over)
    return f


def test_all_25_chains_present():
    assert len(CHAINS) == 26  # 25 chains + "other"
    for c in ("bitcoin", "litecoin", "dogecoin", "bitcoin_cash", "dash",
              "ethereum", "solana", "bnb", "tron", "polygon", "avalanche",
              "arbitrum", "optimism", "base", "cardano", "xrp", "ton",
              "polkadot", "sui", "aptos", "usdt", "usdc", "dai", "monero",
              "zcash"):
        assert c in CHAINS


def test_chain_aliases_normalise():
    assert normalize_chain("bsc") == "bnb"
    assert normalize_chain("matic") == "polygon"
    assert normalize_chain("eth") == "ethereum"
    assert normalize_chain("unknown-chain-xyz") == "other"
    assert normalize_chain("") == "other"


def test_chain_family_and_flags():
    spec = _spec()
    names = spec.feature_names()
    # Bitcoin row: utxo family + is_utxo, not privacy.
    v = extract(_base(chain="bitcoin"), spec)
    assert v[names.index("chain:bitcoin")] == 1.0
    assert v[names.index("chain_family:utxo")] == 1.0
    assert v[names.index("is_utxo")] == 1.0
    assert v[names.index("is_privacy")] == 0.0
    # Monero row: privacy family + is_privacy, not utxo-family
    # (family is single-valued; is_utxo stays 0 for Monero).
    v = extract(_base(chain="monero"), spec)
    assert v[names.index("chain_family:privacy")] == 1.0
    assert v[names.index("is_privacy")] == 1.0
    # Zcash: privacy family, but UTXO-model flag still set.
    v = extract(_base(chain="zcash"), spec)
    assert v[names.index("chain_family:privacy")] == 1.0
    assert v[names.index("is_utxo")] == 1.0
    # Solana: own family, no utxo/privacy flags.
    v = extract(_base(chain="solana"), spec)
    assert v[names.index("chain_family:solana")] == 1.0
    assert v[names.index("is_utxo")] == 0.0
    assert v[names.index("is_privacy")] == 0.0


def test_stablecoin_flag_from_text_and_stamp():
    spec = _spec()
    names = spec.feature_names()
    v = extract(_base(chain="ethereum",
                      value="USDC balance can be drained"), spec)
    assert v[names.index("is_stablecoin")] == 1.0
    # Builder-stamped flag counts even when the value text is terse.
    v = extract(_base(chain="usdc", is_stablecoin=True), spec)
    assert v[names.index("chain:usdc")] == 1.0
    assert v[names.index("chain_family:token")] == 1.0
    assert v[names.index("is_stablecoin")] == 1.0
    # Plain ETH row: no stablecoin flag.
    v = extract(_base(chain="ethereum"), spec)
    assert v[names.index("is_stablecoin")] == 0.0


def test_domain_derivation():
    assert derive_domain({"plugin": "xss"}) == "web_api"
    assert derive_domain({"plugin": "sqli"}) == "web_api"
    assert derive_domain(
        {"plugin": "firmware_hardcoded_api_keys"}) == "hardware_firmware"
    assert derive_domain({"plugin": "bitcoin"}) == "node_infra"
    assert derive_domain({"plugin": "contract_logic"}) == "contract"
    # Builder-stamped domain wins over the plugin default.
    assert derive_domain({"plugin": "xss",
                          "domain": "node_infra"}) == "node_infra"
    spec = _spec()
    names = spec.feature_names()
    v = extract(_base(plugin="xss", chain="other", domain="web_api"), spec)
    assert v[names.index("domain:web_api")] == 1.0


def test_per_chain_metrics_small_slice_reports_counts_only():
    rows = [{"chain": "solana", "label": 1, "finding": {}},
            {"chain": "solana", "label": 1, "finding": {}}]
    out = per_chain_metrics(rows, [0.9, 0.8])
    assert out["solana"]["n"] == 2
    assert out["solana"]["n_positive"] == 2
    assert "accuracy" not in out["solana"]  # too few to measure


def test_per_chain_metrics_bsc_slice_has_metrics():
    rows = []
    scores = []
    for i in range(6):
        rows.append({"chain": "bsc", "label": 1 if i < 5 else 0,
                     "finding": {}})
        scores.append(0.9 if i < 5 else 0.1)
    out = per_chain_metrics(rows, scores)
    assert out["bnb"]["n"] == 6  # bsc normalises to bnb
    assert out["bnb"]["accuracy"] == 1.0
    assert out["bnb"]["roc_auc"] == 1.0
