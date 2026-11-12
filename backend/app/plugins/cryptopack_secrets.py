"""Crypto pack: leaked crypto secrets and API keys in served content.

Where `wallets` hunts secret *shapes* (raw hex keys near wallet
words, keystore stubs), this module hunts secret *assignments*: the
.env lines, Hardhat configs, hardcoded signers and exchange/RPC API
keys that ship inside the JS bundles and config files a target
serves. Plus the strongest mnemonic detector in the suite: full
BIP-39 checksum verification of word sequences in page text - a
12-word run of BIP-39 words with a valid checksum is a seed phrase,
not a coincidence. Full matches are shown in findings.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import PackPlugin, bech32_decode, collect_texts

B32 = r"qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _nsec(s: str) -> bool:
    dec = bech32_decode(s.lower())
    return bool(dec) and dec[0] == "nsec"


def _bip39_words_ok(words) -> bool:
    return all(w in BIP39_WORDSET for w in words)


def _solana_bytes(s: str) -> bool:
    try:
        parts = [int(x) for x in s.split(",")]
    except ValueError:
        return False
    return len(parts) == 64 and all(0 <= p <= 255 for p in parts)


class CpSecretNsec(PackPlugin):
    id = "cp_secret_nsec"
    label = "Leaked Nostr private key (nsec)"
    description = ("Bech32-verified nsec private keys in served "
                   "content - a full account compromise if real.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [(rf"\bnsec1[{B32}]{{58}}\b", "nostr_private_key",
                 "Nostr private key (nsec)", 98, _nsec)]


class CpSecretEnvMnemonic(PackPlugin):
    id = "cp_secret_env_mnemonic"
    label = "Leaked mnemonic in config assignment"
    description = ("MNEMONIC=/SEED_PHRASE= assignments in served JS or "
                   "config text, word-validated against the BIP-39 list.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?mi)(?:MNEMONIC|SEED_PHRASE|RECOVERY_PHRASE|WALLET_MNEMONIC|"
         r"HD_MNEMONIC)\s*[:=]\s*[\"']?([a-z]+(?:\s+[a-z]+){11,23})",
         "env_mnemonic", "Mnemonic in config assignment", 95,
         lambda s: _bip39_words_ok(s.split())),
    ]


class CpSecretEnvPrivkey(PackPlugin):
    id = "cp_secret_env_privkey"
    label = "Leaked private key in config assignment"
    description = ("PRIVATE_KEY-style assignments with 64-hex values "
                   "in served JS/config text.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?mi)(?:PRIVATE_KEY|DEPLOYER_PRIVATE_KEY|WALLET_PRIVATE_KEY|"
         r"SIGNER_PRIVATE_KEY|ACCOUNT_PRIVATE_KEY|OWNER_PRIVATE_KEY)"
         r"\s*[:=]\s*[\"']?(0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64})\b",
         "env_private_key", "Private key in config assignment", 95, None),
    ]


class CpSecretHardhatKey(PackPlugin):
    id = "cp_secret_hardhat_key"
    label = "Hardcoded key in Hardhat/Truffle config"
    description = ("Deployer keys hardcoded in smart-contract tooling "
                   "config (accounts arrays, privateKey fields) that "
                   "ended up in served JS/source.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"accounts\s*:\s*\[\s*[\"'](0x[0-9a-fA-F]{64})[\"']",
         "hardhat_account_key", "Hardcoded deployer key (accounts array)",
         95, None),
        (r"privateKey\s*:\s*[\"'](0x[0-9a-fA-F]{64})[\"']",
         "config_private_key", "Hardcoded privateKey field", 92, None),
    ]


class CpSecretEthersWallet(PackPlugin):
    id = "cp_secret_ethers_wallet"
    label = "Hardcoded signer in shipped JS"
    description = ("Live signer construction in production JS: "
                   "new ethers.Wallet('<key>'), privateKeyToAccount, "
                   "Wallet.fromMnemonic - keys baked into the bundle.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?:new\s+(?:ethers\.)?Wallet|privateKeyToAccount)\s*\(\s*"
         r"[\"'](0x[0-9a-fA-F]{64})[\"']",
         "hardcoded_signer_key", "Hardcoded signer private key", 95, None),
        (r"Wallet\.fromMnemonic\s*\(\s*[\"']([a-z]+(?: [a-z]+){11,23})[\"']",
         "hardcoded_signer_mnemonic", "Hardcoded signer mnemonic", 95,
         lambda s: _bip39_words_ok(s.split())),
    ]


class CpSecretSolanaKeypair(PackPlugin):
    id = "cp_secret_solana_keypair"
    label = "Leaked Solana keypair bytes"
    description = ("Solana secret keys as 64-byte arrays (id.json "
                   "format) assigned to secretKey in served content.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"secretKey\s*[:=]\s*(?:new\s+)?(?:Uint8Array\s*\(\s*)?\["
         r"((?:\s*\d{1,3}\s*,){63}\s*\d{1,3}\s*)\]",
         "solana_keypair_bytes", "Solana keypair byte array", 95,
         _solana_bytes),
    ]


class CpSecretKeystoreFile(PackPlugin):
    id = "cp_secret_keystore_file"
    label = "Served Ethereum keystore file body"
    description = ("A full Web3 keystore (version 3 + KDF + cipher "
                   "structure) in served content - brute-forceable "
                   "offline if the password is weak.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [
        (r"\{[^{}]*\"version\"\s*:\s*3[^{}]*\"crypto\"\s*:\s*\{[^{}]*"
         r"\"kdf\"\s*:\s*\"(?:scrypt|pbkdf2)\"",
         "keystore_file_body", "Served keystore file (v3, KDF)", 88, None),
    ]


class CpSecretWalletDatRef(PackPlugin):
    id = "cp_secret_wallet_dat_ref"
    label = "Wallet file references in served content"
    description = ("References to wallet.dat / Electrum wallet files / "
                   "MetaMask vault blobs in pages, listings or storage "
                   "dumps the target serves.")
    CATEGORY = "leak"
    PATTERNS = [
        (r"\bwallet\.dat\b", "wallet_dat_ref", "wallet.dat reference", 70,
         None),
        (r"\bdefault_wallet\b", "electrum_wallet_ref",
         "Electrum wallet file reference", 65, None),
        (r"\"vault\"\s*:\s*\"\{[^\"\\]{50,}", "metamask_vault_ref",
         "MetaMask vault blob reference", 75, None),
    ]


class CpApiKeyInfura(PackPlugin):
    id = "cp_apikey_infura"
    label = "Leaked Infura project key"
    description = "Infura RPC project IDs/secrets embedded in served content."
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"infura\.io/v3/([0-9a-f]{32})", "infura_project_id",
         "Infura project ID in RPC URL", 85, None),
        (r"(?:INFURA_API_KEY|INFURA_PROJECT_ID|NEXT_PUBLIC_INFURA_ID)"
         r"\s*[:=]\s*[\"']?([A-Za-z0-9]{32})",
         "infura_project_id", "Infura project ID assignment", 88, None),
    ]


class CpApiKeyAlchemy(PackPlugin):
    id = "cp_apikey_alchemy"
    label = "Leaked Alchemy API key"
    description = "Alchemy API keys embedded in RPC URLs or assignments."
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?:alchemy\.com/v2/|alchemyapi\.io/v2/|g\.alchemy\.com/v2/)"
         r"([A-Za-z0-9_\-]{24,})", "alchemy_api_key",
         "Alchemy API key in RPC URL", 85, None),
        (r"(?:ALCHEMY_API_KEY|NEXT_PUBLIC_ALCHEMY_KEY)\s*[:=]\s*"
         r"[\"']?([A-Za-z0-9_\-]{24,})", "alchemy_api_key",
         "Alchemy API key assignment", 88, None),
    ]


class CpApiKeyQuicknode(PackPlugin):
    id = "cp_apikey_quicknode"
    label = "Leaked QuickNode endpoint token"
    description = "QuickNode RPC endpoints with embedded auth tokens."
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"([a-z0-9\-]+\.(?:quiknode|quicknode)\.pro/[A-Za-z0-9]{32,})",
         "quicknode_endpoint", "QuickNode endpoint with token", 85, None),
    ]


class CpApiKeyEtherscan(PackPlugin):
    id = "cp_apikey_etherscan"
    label = "Leaked explorer API key (Etherscan family)"
    description = ("Etherscan/BscScan/PolygonScan/Snowtrace API keys "
                   "in URLs or assignments in served content.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?:etherscan\.io|bscscan\.com|polygonscan\.com|snowtrace\.io)"
         r"[^\s\"'<>]*?apikey=([A-Za-z0-9]{34})",
         "explorer_api_key", "Explorer API key in URL", 85, None),
        (r"(?:ETHERSCAN_API_KEY|BSCSCAN_API_KEY|POLYGONSCAN_API_KEY)"
         r"\s*[:=]\s*[\"']?([A-Za-z0-9]{34})",
         "explorer_api_key", "Explorer API key assignment", 88, None),
    ]


def _exchange(id_, label, brand, key_re, key_desc):
    return type(id_, (PackPlugin,), {
        "id": id_, "label": label,
        "description": f"{brand} API credentials in served content.",
        "CATEGORY": "leak", "SECRET": True, "VALUE_GROUP": 1,
        "__module__": __name__,
        "PATTERNS": [(key_re, id_.replace("cp_apikey_", "") + "_api_key",
                      key_desc, 88, None)],
    })


CpApiKeyBinance = _exchange(
    "cp_apikey_binance", "Leaked Binance API key", "Binance",
    r"(?:BINANCE_API_KEY|BINANCE_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9]{64})",
    "Binance API key assignment")

CpApiKeyCoinbase = _exchange(
    "cp_apikey_coinbase", "Leaked Coinbase API key", "Coinbase",
    r"(?:COINBASE_API_KEY|organizations/[a-f0-9\-]{36}/apiKeys/)"
    r"\s*[:=]?\s*[\"']?([A-Za-z0-9\-]{36,})",
    "Coinbase API key reference")

CpApiKeyKraken = _exchange(
    "cp_apikey_kraken", "Leaked Kraken API key", "Kraken",
    r"(?:KRAKEN_API_KEY|KRAKEN_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9+/=]{56,88})",
    "Kraken API key assignment")

CpApiKeyKucoin = _exchange(
    "cp_apikey_kucoin", "Leaked KuCoin API key", "KuCoin",
    r"(?:KUCOIN_API_KEY|KUCOIN_KEY)\s*[:=]\s*[\"']?([0-9a-f]{24})",
    "KuCoin API key assignment")

CpApiKeyBybit = _exchange(
    "cp_apikey_bybit", "Leaked Bybit API key", "Bybit",
    r"(?:BYBIT_API_KEY|BYBIT_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9]{36})",
    "Bybit API key assignment")

CpApiKeyOkx = _exchange(
    "cp_apikey_okx", "Leaked OKX API key", "OKX",
    r"(?:OKX_API_KEY|OK_ACCESS_KEY)\s*[:=]\s*[\"']?([0-9a-fA-F\-]{36})",
    "OKX API key assignment")

CpApiKeyMoralis = _exchange(
    "cp_apikey_moralis", "Leaked Moralis API key", "Moralis",
    r"(?:MORALIS_API_KEY|moralis[^\n]{0,25}?api[_\s]?key)\s*[:=]\s*"
    r"[\"']?(eyJ[A-Za-z0-9_\-]{40,}(?:\.[A-Za-z0-9_\-]*){1,2})",
    "Moralis API key (JWT) assignment")


_WORD_RUN = re.compile(r"[a-z]+(?:\s+[a-z]+){10,23}")


class CpSecretBip39Sequence(Plugin):
    id = "cp_secret_bip39_sequence"
    label = "Exposed BIP-39 seed phrase (checksum-verified)"
    description = ("Word sequences in served text that are valid "
                   "BIP-39 mnemonics - every word on the official "
                   "list AND a valid SHA-256 checksum. A verified "
                   "seed phrase is a full wallet compromise.")
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        findings: List[Finding] = []
        for where, text, url in texts:
            low = re.sub(r"<[^>]+>", " ", text.lower())
            for m in _WORD_RUN.finditer(low):
                words = m.group(0).split()
                for n in (24, 21, 18, 15, 12):
                    if len(words) < n:
                        continue
                    cand = words[:n]
                    if not all(w in BIP39_WORD_INDEX for w in cand):
                        continue
                    bits = "".join(
                        format(BIP39_WORD_INDEX[w], "011b") for w in cand)
                    ent_len = len(bits) * 32 // 33
                    ent = int(bits[:ent_len], 2).to_bytes(
                        ent_len // 8, "big")
                    cs = bits[ent_len:]
                    digest = hashlib.sha256(ent).digest()
                    cs_bits = format(digest[0], "08b")[:len(cs)]
                    if cs == cs_bits:
                        joined = " ".join(cand)
                        findings.append(self._f(
                            "leak", "bip39_seed_phrase",
                            f"BIP-39 seed phrase ({n} words, checksum "
                            f"valid): {joined}",
                            source=self.label, source_url=url,
                            confidence=99, passive=True,
                            evidence={"words": n, "where": where,
                                      "full_value": joined}))
                        break
            if findings:
                break
        res = self._ok(findings, f"{len(findings)} verified seed phrase(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# The official BIP-39 English wordlist (2048 words) is appended below
# by the build script; BIP39_WORDSET / BIP39_WORD_INDEX derive from it.
BIP39_WORDS = (
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
    "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
    "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
    "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
    "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
    "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
    "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
    "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
    "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
    "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
    "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
    "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
    "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
    "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
    "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
    "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
    "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
    "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
    "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
    "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
    "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
    "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
    "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
    "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
    "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
    "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
    "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
    "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
    "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
    "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
    "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
    "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
    "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
    "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field",
    "figure", "file", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
    "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
    "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
    "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
    "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
    "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
    "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
    "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
    "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
    "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
    "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
    "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
    "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
    "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group",
    "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
    "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
    "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
    "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
    "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
    "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband",
    "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill",
    "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
    "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
    "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
    "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
    "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
    "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
    "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
    "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
    "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb", "limit",
    "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
    "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
    "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
    "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
    "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
    "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
    "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
    "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
    "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
    "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
    "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
    "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
    "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
    "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
    "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay",
    "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
    "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
    "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
    "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
    "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
    "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
    "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
    "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
    "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
    "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
    "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
    "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
    "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
    "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
    "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
    "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
    "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
    "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
    "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
    "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
    "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
    "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
    "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
    "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
    "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
    "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
    "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
    "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
    "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
    "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
    "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
    "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
    "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
    "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
    "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
    "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
    "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
    "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
    "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
    "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
    "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
    "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
    "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
    "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
    "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
    "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
    "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
    "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
    "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
    "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
    "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
    "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
    "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
)
BIP39_WORDSET = frozenset(BIP39_WORDS)
BIP39_WORD_INDEX = {w: i for i, w in enumerate(BIP39_WORDS)}
