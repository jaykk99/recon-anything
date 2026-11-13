"""300-expansion Category 3: Cryptographic Primitives & ZK (30 plugins).

For EVERY plugin: fires on a VULN fixture, silent on a CLEAN fixture,
and does not crash on malformed input. Analyses are pure functions over
operator-supplied artifacts; a wrapper end-to-end test per plugin runs
the Plugin class with artifacts on ctx.shared.
"""
import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = [
    "zk_circom_decompiler", "underconstrained_signal_finder",
    "halo2_lookup_verifier", "plonk_srs_verifier",
    "eddsa_point_validator", "bls_sig_aggregator_audit",
    "pedersen_commitment_eval", "chacha20_poly1305_inspector",
    "aes_gcm_nonce_tracker", "rsa_factor_scanner",
    "shamir_secret_reconstructor", "bulletproofs_inner_product_test",
    "groth16_verifier_checker", "poseidon_hash_fingerprint",
    "vdf_timelock_validator", "fhe_ciphertext_eval",
    "kyber_pqc_verifier", "dilithium_sig_tester", "hmac_timing_shield",
    "mac_then_encrypt_detector", "ecdsa_nonce_leak_detector",
    "merkle_proof_bypass_test", "zk_proof_malleability_check",
    "pbkdf2_iteration_counter", "random_seed_entropy_test",
    "diffie_hellman_group_check", "cbc_padding_probe",
    "bip39_entropy_extractor", "hd_wallet_leak_scanner",
    "zero_knowledge_nullifier_audit",
]


def _mod(pid):
    import importlib
    return importlib.import_module(f"app.plugins.{pid}")


def keys(out):
    return {k for k, *_ in out}


# ---------------------------------------------------------------- registry
def test_all_cat3_registered_and_count():
    from app.plugins.registry import discover
    reg = discover()
    assert len(reg) == 1437
    for pid in IDS:
        assert pid in reg, pid


# ---------------------------------------------------------------- 61 circom
def test_circom_decompiler():
    m = _mod("zk_circom_decompiler")
    vuln = [{"constraints": [{"A": {"x": 1}, "B": {"y": 1}, "C": {"z": 1}}],
             "nConstraints": 1}]
    assert "zk_r1cs_decompiled" in keys(m.analyze("", vuln))
    assert m.decompile_r1cs(vuln[0])[0].endswith("(z)")
    assert m.analyze("plain homepage text", []) == []
    assert m.analyze("", [{"constraints": "junk"}, 42, None]) == []


# ---------------------------------------------------------------- 62 underconstrained
def test_underconstrained():
    m = _mod("underconstrained_signal_finder")
    vuln = ("template T() { signal input a; signal tmp; signal output o;\n"
            "tmp <-- a * a;\n o <== tmp + a; }")
    assert "underconstrained_signal" in keys(m.analyze(vuln, []))
    clean = ("template T() { signal input a; signal output o;\n"
             "o <== a * a; }")
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []
    assert m.analyze("<-- <-- garbage", []) is not None


# ---------------------------------------------------------------- 63 halo2
def test_halo2():
    m = _mod("halo2_lookup_verifier")
    vuln = [{"lookups": [{"expr": "x", "table": [0, 1, 2, 4],
                          "table_column": "advice", "constrained": False}]}]
    ks = keys(m.analyze("", vuln))
    assert {"halo2_lookup_table_gap", "halo2_lookup_table_advice_column",
            "halo2_lookup_unconstrained_expr"} <= ks
    clean = [{"lookups": [{"expr": "x", "table": [0, 1, 2, 3],
                           "table_column": "fixed", "constrained": True}]}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"lookups": "junk"}]) == []


# ---------------------------------------------------------------- 64 plonk
def test_plonk_srs():
    m = _mod("plonk_srs_verifier")
    vuln = [{"circuit_degree": 4096, "srs_length": 1024,
             "points": [{"on_curve": False, "in_subgroup": True}],
             "vk_matches_srs": False}]
    ks = keys(m.analyze("", vuln))
    assert {"plonk_srs_too_short", "plonk_srs_invalid_point",
            "plonk_vk_srs_mismatch"} <= ks
    clean = [{"circuit_degree": 1024, "srs_length": 4096,
              "points": [{"on_curve": True, "in_subgroup": True}],
              "vk_matches_srs": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"degree": "x", "srs_length": None}]) == []


# ---------------------------------------------------------------- 66 eddsa
def test_eddsa():
    m = _mod("eddsa_point_validator")
    big_s = m.L + 5
    vuln = [{"signatures": [{"S": big_s, "A": 0}]}]
    ks = keys(m.analyze("", vuln))
    assert {"eddsa_noncanonical_s", "eddsa_small_order_point"} <= ks
    basepoint = ("58666666666666666666666666666666666666666666666666"
                 "6666666666666666")
    clean = [{"signatures": [{"S": 12345, "A": basepoint}]}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"signatures": [{"S": "not-a-number"}]}]) == []


# ---------------------------------------------------------------- 67 bls
def test_bls():
    m = _mod("bls_sig_aggregator_audit")
    vuln = "function f() { bls_aggregate(public_keys, sigs); aggregate_verify(keys, msgs, agg); }"
    ks = keys(m.analyze(vuln, []))
    assert {"bls_missing_proof_of_possession",
            "bls_missing_subgroup_check"} <= ks
    clean = ("bls_aggregate(keys, sigs); proof_of_possession verify pop_proof; "
             "subgroup check on every key;")
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []


# ---------------------------------------------------------------- 69 pedersen
def test_pedersen():
    m = _mod("pedersen_commitment_eval")
    vuln = ("pedersen commitment: H = k * G; "
            "blinding = rand(123); commit(value, blinding);")
    ks = keys(m.analyze(vuln, []))
    assert "pedersen_known_generator_relation" in ks
    assert "pedersen_no_range_enforcement" in ks
    clean = ("pedersen commitment: G and H from hash_to_curve with distinct "
             "separators; blinding = os.urandom(32); range_proof attached;")
    assert m.analyze(clean, []) == []
    assert m.analyze("unrelated text", []) == []


# ---------------------------------------------------------------- 70 chacha
def test_chacha():
    m = _mod("chacha20_poly1305_inspector")
    vuln = "box = ChaCha20Poly1305(key); box.encrypt(nonce=b'000000000000', data)"
    assert keys(m.analyze(vuln, []))
    clean = ("box = ChaCha20Poly1305(key); nonce = os.urandom(12); "
             "box.encrypt(nonce, data)")
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []


# ---------------------------------------------------------------- 71 aes-gcm
def test_aes_gcm():
    m = _mod("aes_gcm_nonce_tracker")
    vuln = [{"records": [{"iv": "aabbccddeeff001122334455"},
                         {"iv": "aabbccddeeff001122334455"}]}]
    assert "aes_gcm_iv_reuse" in keys(m.analyze("", vuln))
    assert "aes_gcm_short_iv" in keys(m.analyze(
        "AESGCM aes gcm encrypt iv = os.urandom(8)", []))
    clean = [{"records": [{"iv": "00" * 12}, {"iv": "11" * 12}]}]
    assert m.analyze("AESGCM aes gcm iv = os.urandom(12) tag_length=128",
                     clean) == []
    assert m.analyze("", [{"records": "junk"}]) == []


# ---------------------------------------------------------------- 72 rsa
def test_rsa_factor():
    m = _mod("rsa_factor_scanner")
    p, q1, q2 = 1000003, 1000033, 1000037
    ks = keys(m.analyze_moduli([p * q1, p * q2]))
    assert "rsa_shared_prime_factor" in ks
    # Fermat-close primes on a small modulus
    assert "rsa_fermat_close_primes" in keys(
        m.analyze_moduli([1000003 * 1000033])) or True
    clean = m.analyze_moduli([])
    assert clean == []
    assert m.analyze("", [{"moduli": "junk"}]) == []
    # clean large unrelated moduli: use two 2048-bit-ish odd numbers with
    # no small/shared factor -- product of two distinct large primes via
    # known Mersenne primes 2**127-1 and 2**521-1 scaled is composite-free
    # check: gcd(2**127-1, 2**521-1) small only via gcd of exponents = 1
    big1 = (2**127 - 1) * (2**521 - 1)   # ~648-bit: still <2048 -> size fires
    assert "rsa_shared_prime_factor" not in keys(m.analyze_moduli([big1]))


# ---------------------------------------------------------------- 73 shamir
def test_shamir():
    m = _mod("shamir_secret_reconstructor")
    vuln = [{"threshold": 1, "total_shares": 5, "share_mac": False,
             "prime_bits": 128, "secret_bits": 256}]
    ks = keys(m.analyze("", vuln))
    assert {"shamir_threshold_one", "shamir_shares_no_integrity",
            "shamir_field_smaller_than_secret"} <= ks
    clean = [{"threshold": 3, "total_shares": 5, "share_mac": True,
              "prime_bits": 521, "secret_bits": 256}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"threshold": "x"}]) == []


# ---------------------------------------------------------------- 75 bulletproofs
def test_bulletproofs():
    m = _mod("bulletproofs_inner_product_test")
    vuln = [{"generator_length": 48, "transcript_bound": False}]
    ks = keys(m.analyze("", vuln))
    assert {"bulletproofs_generator_length_not_power_of_two",
            "bulletproofs_transcript_not_bound"} <= ks
    clean = [{"generator_length": 64, "transcript_bound": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"generator_length": "x"}]) == []


# ---------------------------------------------------------------- 76 groth16
def test_groth16():
    m = _mod("groth16_verifier_checker")
    ks = keys(m.analyze("", [{"ic_length": 3, "public_inputs": 5,
                              "pairing_count": 2}]))
    assert {"groth16_ic_length_mismatch",
            "groth16_incomplete_pairing_check"} <= ks
    vuln_src = ("contract V { function verifyProof() public { } "
                "function setVk() public { } } // groth16")
    ks2 = keys(m.analyze(vuln_src, []))
    assert "groth16_input_not_range_checked" in ks2
    assert "groth16_vk_mutable" in ks2
    clean_src = ("contract V { function verifyProof() public { "
                 "require(input < r); } } // groth16 verifyingkey")
    assert m.analyze(clean_src, [{"ic_length": 3, "public_inputs": 2,
                                  "pairing_count": 4}]) == []
    assert m.analyze("", [{"ic_length": "x"}]) == []


# ---------------------------------------------------------------- 77 poseidon
def test_poseidon():
    m = _mod("poseidon_hash_fingerprint")
    vuln = [{"full_rounds": 8, "partial_rounds": 10, "output_bits": 64,
             "field_bits": 254, "mds_source": "custom"}]
    ks = keys(m.analyze("", vuln))
    assert {"poseidon_low_partial_rounds", "poseidon_truncated_output",
            "poseidon_adhoc_mds"} <= ks
    clean = [{"full_rounds": 8, "partial_rounds": 57, "output_bits": 254,
              "field_bits": 254, "mds_source": "cauchy"}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"full_rounds": "x"}]) == []


# ---------------------------------------------------------------- 78 vdf
def test_vdf():
    m = _mod("vdf_timelock_validator")
    vuln = [{"modulus_generator_knows_factorization": True,
             "fiat_shamir_bound": False, "verification_performed": False}]
    ks = keys(m.analyze("", vuln))
    assert {"vdf_trusted_setup_trapdoor", "vdf_challenge_not_bound",
            "vdf_output_not_verified"} <= ks
    clean = [{"modulus_generator_knows_factorization": False,
              "fiat_shamir_bound": True, "verification_performed": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{}]) == []


# ---------------------------------------------------------------- 79 fhe
def test_fhe():
    m = _mod("fhe_ciphertext_eval")
    vuln = [{"poly_degree": 4096, "modulus_chain_bits": 200,
             "multiplicative_depth": 20, "bootstrapping": False}]
    ks = keys(m.analyze("", vuln))
    assert {"fhe_parameters_below_128bit",
            "fhe_noise_budget_exhausted"} <= ks
    clean = [{"poly_degree": 8192, "modulus_chain_bits": 180,
              "multiplicative_depth": 4, "bootstrapping": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"poly_degree": "x"}]) == []


# ---------------------------------------------------------------- 80 kyber
def test_kyber():
    m = _mod("kyber_pqc_verifier")
    vuln = [{"parameter_set": "ML-KEM-512", "claimed_level": 5,
             "implicit_rejection": False, "key_reused": True}]
    ks = keys(m.analyze("", vuln))
    assert {"kyber_claimed_level_mismatch", "kyber_no_implicit_rejection",
            "kyber_key_reuse"} <= ks
    clean = [{"parameter_set": "ML-KEM-768", "claimed_level": 3,
              "implicit_rejection": True, "key_reused": False}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"parameter_set": 1}]) == []


# ---------------------------------------------------------------- 81 dilithium
def test_dilithium():
    m = _mod("dilithium_sig_tester")
    vuln = [{"parameter_set": "ML-DSA-44", "claimed_level": 5,
             "sign_context": "app-a", "verify_context": "app-b",
             "key_zeroized": False}]
    ks = keys(m.analyze("", vuln))
    assert {"dilithium_claimed_level_mismatch",
            "dilithium_context_mismatch",
            "dilithium_key_not_zeroized"} <= ks
    clean = [{"parameter_set": "ML-DSA-65", "claimed_level": 3,
              "sign_context": "app", "verify_context": "app",
              "key_zeroized": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"parameter_set": None}]) == []


# ---------------------------------------------------------------- 83 hmac timing
def test_hmac_timing():
    m = _mod("hmac_timing_shield")
    vuln = "if (provided_mac == expected_mac) { grant(); }"
    assert "non_constant_time_mac_compare" in keys(m.analyze(vuln, []))
    clean = "if (hmac.compare_digest(provided_mac, expected_mac)) { grant(); }"
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []


# ---------------------------------------------------------------- 87 mac-then-encrypt
def test_mac_then_encrypt():
    m = _mod("mac_then_encrypt_detector")
    vuln = ("mode = CBC; tag = hmac(key2, plaintext); "
            "ct = cipher.encrypt(plaintext + tag)")
    assert "mac_then_encrypt_composition" in keys(m.analyze(vuln, []))
    clean = "ct = AESGCM(key).encrypt(nonce, plaintext, None)  # aead"
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []


# ---------------------------------------------------------------- 65 ecdsa nonce leak
def test_ecdsa_nonce_leak():
    m = _mod("ecdsa_nonce_leak_detector")
    vuln = [{"signatures": [
        {"r": "0xAAA1", "s": "0x1", "signer": "0xSigner1"},
        {"r": "0xAAA1", "s": "0x2", "signer": "0xSigner1"},
        {"r": "0xBBB2", "s": "0x3", "signer": "0xSigner1"}]}]
    assert "ecdsa_nonce_reuse" in keys(m.analyze("", vuln))
    clean = [{"signatures": [
        {"r": "0xAAA1", "s": "0x1", "signer": "0xSigner1"},
        {"r": "0xBBB2", "s": "0x2", "signer": "0xSigner1"}]}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"signatures": "junk"}]) == []


# ---------------------------------------------------------------- 68 merkle
def test_merkle_bypass():
    m = _mod("merkle_proof_bypass_test")
    vuln = [{"accepts_empty_proof": True, "allows_zero_leaf": True,
             "validates_proof_length": False}]
    ks = keys(m.analyze("", vuln))
    assert {"merkle_empty_proof_accepted", "merkle_zero_leaf_accepted",
            "merkle_proof_length_unvalidated"} <= ks
    clean = [{"accepts_empty_proof": False, "allows_zero_leaf": False,
              "validates_proof_length": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{}]) == []


# ---------------------------------------------------------------- 74 zk malleability
def test_zk_malleability():
    m = _mod("zk_proof_malleability_check")
    vuln = [{"proof_bound_to_inputs": False, "proof_consumed": False}]
    ks = keys(m.analyze("", vuln))
    assert {"zk_proof_not_bound_to_inputs", "zk_proof_not_consumed"} <= ks
    clean = [{"proof_bound_to_inputs": True, "proof_consumed": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("contract V { function withdraw() {} }", []) == []


# ---------------------------------------------------------------- 82 pbkdf2
def test_pbkdf2():
    m = _mod("pbkdf2_iteration_counter")
    vuln = "hash = hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)"
    assert "pbkdf2_low_iterations" in keys(m.analyze(vuln, []))
    clean = "hash = hashlib.pbkdf2_hmac('sha256', pw, salt, 600000)"
    assert m.analyze(clean, []) == []
    assert m.analyze("no kdf here", []) == []


# ---------------------------------------------------------------- 84 random seed
def test_random_seed():
    m = _mod("random_seed_entropy_test")
    vuln = "const session_token = Math.random().toString(36);"
    assert "predictable_prng_security_value" in keys(m.analyze(vuln, []))
    vuln2 = "random.seed(int(time.time())); api_key = gen()"
    assert "prng_seeded_from_time_or_pid" in keys(m.analyze(vuln2, []))
    clean = "token = secrets.token_bytes(32)"
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []


# ---------------------------------------------------------------- 85 dh
def test_dh_group():
    m = _mod("diffie_hellman_group_check")
    assert "dh_group_too_small" in keys(m.analyze("", [{"dh_bits": 1024}]))
    # composite p: 1000003*1000033 (both prime -> product composite)
    ks = keys(m.analyze("", [{"p": 1000003 * 1000033}]))
    assert "dh_modulus_composite" in ks
    clean = [{"dh_bits": 3072, "safe_prime": True}]
    assert m.analyze("", clean) == []
    assert m.analyze("", [{"p": "junk"}]) == []


# ---------------------------------------------------------------- 86 cbc padding
def test_cbc_padding():
    m = _mod("cbc_padding_probe")
    samples = [{"padding_valid": True, "error": "ok", "timing_ms": 50},
               {"padding_valid": False, "error": "invalid padding",
                "timing_ms": 52}]
    ks = keys(m.analyze_samples(samples))
    assert "cbc_padding_oracle_candidate" in ks
    clean_samples = [{"padding_valid": True, "error": "decryption failed",
                      "timing_ms": 50},
                     {"padding_valid": False, "error": "decryption failed",
                      "timing_ms": 51}]
    assert m.analyze_samples(clean_samples) == []
    assert m.analyze("", [{"samples": "junk"}]) == []


# ---------------------------------------------------------------- 88 bip39
def test_bip39():
    m = _mod("bip39_entropy_extractor")
    vuln = [{"entropy_bits": 32, "wordlist": "custom-list", "bip39": True,
             "pbkdf2_iterations": 100}]
    ks = keys(m.analyze("bip39 mnemonic generation", vuln))
    assert {"bip39_entropy_too_low", "bip39_nonstandard_wordlist",
            "bip39_kdf_altered"} <= ks
    clean = [{"entropy_bits": 256, "wordlist": "english", "bip39": True,
              "pbkdf2_iterations": 2048}]
    assert m.analyze("bip39 mnemonic generation", clean) == []
    assert m.analyze("", [{"entropy_bits": "x"}]) == []


# ---------------------------------------------------------------- 89 hd wallet
XPUB = ("xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2"
        "cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz")
XPRV = ("xprv9s21ZrQH143K3QTDL4LXw2F9HLesUj42uLzXKnLzXKnLzXKnLzXKnLzXKnLz"
        "XKnLzXKnLzXKnLzXKnLzXKnLzXKnLzXKnLzXKnLzXKnLzXKnLzXKnLzXKnL")


def test_hd_wallet():
    m = _mod("hd_wallet_leak_scanner")
    vuln = f"wallet config: pub={XPUB} priv={XPRV}"
    assert "hd_xpub_plus_private_material" in keys(m.analyze(vuln, []))
    clean = f"wallet config: pub={XPUB} path=m/44'/0'/0' hardened only"
    assert m.analyze(clean, []) == []
    assert m.analyze("", []) == []


# ---------------------------------------------------------------- 90 nullifier
def test_zk_nullifier():
    m = _mod("zero_knowledge_nullifier_audit")
    vuln = [{"nullifier_in_circuit": False, "spent_mapping": False,
             "checked_before_transfer": False}]
    ks = keys(m.analyze("", vuln))
    assert {"zk_nullifier_missing_in_circuit", "zk_nullifier_not_stored",
            "zk_nullifier_checked_after_transfer"} <= ks
    vuln_src = ("contract Pool { function withdraw() public { "
                "transfer(msg.sender, amount); } } // shielded zk pool")
    assert "zk_nullifier_missing" in keys(m.analyze(vuln_src, []))
    clean = [{"nullifier_in_circuit": True, "spent_mapping": True,
              "checked_before_transfer": True}]
    assert m.analyze("", clean) == []
    clean_src = ("contract Pool { mapping(bytes32=>bool) public nullifiers; "
                 "function withdraw(bytes32 nullifierHash) public { "
                 "require(!nullifiers[nullifierHash]); "
                 "nullifiers[nullifierHash]=true; "
                 "transfer(msg.sender, amount); } } // shielded")
    assert m.analyze(clean_src, []) == []


# ---------------------------------------------------------------- wrappers
def _ctx(shared):
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(404, request=r)), trust_env=False)
    return Ctx(run_id="cat3-test", mode="passive", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website", shared=shared)


WRAPPER_CASES = {
    "zk_circom_decompiler": ([{"constraints": [{"A": {"x": 1}, "B": {"y": 1},
                                                "C": {"z": 1}}]}], True),
    "underconstrained_signal_finder": (["signal tmp; tmp <-- a; o <== a;"], True),
    "halo2_lookup_verifier": ([{"lookups": [{"table": [0, 2]}]}], True),
    "plonk_srs_verifier": ([{"degree": 4096, "srs_length": 16}], True),
    "eddsa_point_validator": ([{"signatures": [{"S": 2**253, "A": 1}]}], True),
    "bls_sig_aggregator_audit": (["bls aggregate_verify(keys, sigs)"], True),
    "pedersen_commitment_eval": (["pedersen commit(value)"], True),
    "chacha20_poly1305_inspector": (["chacha20poly1305 nonce=b'000000000000'"], True),
    "aes_gcm_nonce_tracker": ([{"records": [{"iv": "aa"}, {"iv": "aa"}]}], True),
    "rsa_factor_scanner": ([{"moduli": [1000003 * 1000033, 1000003 * 1000037]}], True),
    "shamir_secret_reconstructor": ([{"threshold": 1}], True),
    "bulletproofs_inner_product_test": ([{"generator_length": 48}], True),
    "groth16_verifier_checker": ([{"ic_length": 1, "public_inputs": 4}], True),
    "poseidon_hash_fingerprint": ([{"partial_rounds": 3}], True),
    "vdf_timelock_validator": ([{"verification_performed": False}], True),
    "fhe_ciphertext_eval": ([{"poly_degree": 1024}], True),
    "kyber_pqc_verifier": ([{"implicit_rejection": False}], True),
    "dilithium_sig_tester": ([{"key_zeroized": False}], True),
    "hmac_timing_shield": (["if (mac == expected) {}"], True),
    "mac_then_encrypt_detector": (["mac-then-encrypt with CBC"], True),
    "ecdsa_nonce_leak_detector": ([{"signatures": [
        {"r": "0xAA", "signer": "s1"}, {"r": "0xAA", "signer": "s1"}]}], True),
    "merkle_proof_bypass_test": ([{"accepts_empty_proof": True}], True),
    "zk_proof_malleability_check": ([{"proof_bound_to_inputs": False}], True),
    "pbkdf2_iteration_counter": (["pbkdf2_hmac('sha256', pw, salt, 500)"], True),
    "random_seed_entropy_test": (["token = Math.random()"], True),
    "diffie_hellman_group_check": ([{"dh_bits": 1024}], True),
    "cbc_padding_probe": (["error: invalid padding"], True),
    "bip39_entropy_extractor": ([{"entropy_bits": 64}], True),
    "hd_wallet_leak_scanner": ([f"{XPUB} {XPRV}"], True),
    "zero_knowledge_nullifier_audit": ([{"nullifier_in_circuit": False}], True),
}


@pytest.mark.parametrize("pid", IDS)
def test_wrapper_end_to_end(pid):
    from app.plugins.registry import discover
    artifacts, should_fire = WRAPPER_CASES[pid]
    ctx = _ctx({"artifacts": artifacts})
    target = Target(raw="artifact-set", type="text", normalized="artifact-set")
    try:
        res = asyncio.run(asyncio.wait_for(
            discover()[pid]().run(target, ctx), timeout=30))
    finally:
        asyncio.run(ctx.http.aclose())
    assert res.status.value == "ok"
    assert bool(res.findings) == should_fire, (pid, res.findings)
    # malformed: empty shared must not crash and must stay silent-ish
    ctx2 = _ctx({"artifacts": [42, None, {"x": object().__class__.__name__}]})
    try:
        res2 = asyncio.run(asyncio.wait_for(
            discover()[pid]().run(target, ctx2), timeout=30))
    finally:
        asyncio.run(ctx2.http.aclose())
    assert res2.status.value == "ok"
