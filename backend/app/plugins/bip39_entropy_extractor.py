"""VARIANT 88: derivation-procedure audit, not leaked-seed detection."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    eb = first(objs, "entropy_bits")
    try:
        if eb is not None and int(eb) < 128:
            out.append(("bip39_entropy_too_low",
                        f"Mnemonic is generated from only {eb} bits of entropy (< 128); the seed space is brute-forceable",
                        "high", "Generate mnemonics from at least 128 bits (256 preferred) of CSPRNG entropy."))
    except Exception:
        pass
    it = first(objs, "pbkdf2_iterations", "iterations")
    try:
        if it is not None and int(it) != 2048 and "bip39" in text.lower() or (it is not None and first(objs, "bip39") is True and int(it) != 2048):
            out.append(("bip39_kdf_altered",
                        f"BIP39 seed derivation uses {it} PBKDF2 iterations instead of the standard 2048; wallets will derive non-standard seeds",
                        "medium", "Use the BIP39 standard 2048 iterations of PBKDF2-HMAC-SHA512."))
    except Exception:
        pass
    wl = first(objs, "wordlist")
    if wl is not None and str(wl).lower() not in ("english", "standard", "bip39-english"):
        out.append(("bip39_nonstandard_wordlist",
                    f"Mnemonic uses a non-standard wordlist ('{wl}'); recovery in standard wallets is impossible and entropy mapping is unvetted",
                    "medium", "Use the official BIP39 wordlist for the language."))
    if has(text, "brain wallet", "brainwallet") or rx(text, r"mnemonic[^;\n]{0,80}(sha256|hash)\s*\(\s*(password|passphrase|user)"):
        out.append(("bip39_brain_wallet",
                    "Mnemonic/seed is derived from a hash of user data (brain-wallet shape); such seeds are brute-forced in the wild",
                    "high", "Generate the mnemonic from CSPRNG entropy, never from user-chosen data."))
    if rx(text, r"mnemonic[^;\n]{0,80}(math\.random|timestamp|time\(\))"):
        out.append(("bip39_predictable_entropy_source",
                    "Mnemonic entropy comes from a PRNG/timestamp source",
                    "high", "Use CSPRNG entropy for mnemonic generation."))
    return out[:8]


class Bip39EntropyExtractor(Plugin):
    id = "bip39_entropy_extractor"
    label = "BIP39 Entropy Procedure Audit"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Audits how supplied wallet code generates a BIP39 mnemonic: entropy size, brain-wallet derivations, non-standard wordlists, and altered PBKDF2 (2048) seed derivation."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
