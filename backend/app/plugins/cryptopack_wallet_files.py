"""Crypto pack wave 2: EXPOSED WALLET material (Jay's priority).

Wave 1 found wallet *references* and secret *shapes* in page text.
This module hunts the actual wallet artifacts a target serves:

- wallet database/keystore files at their well-known paths
  (wallet.dat, Ethereum keystore JSON, Electrum wallet files),
  each validated by file structure, not just a 200;
- wallet/seed backup text files, validated by their CONTENT
  (a checksum-valid BIP-39 phrase, a labeled private key, or a
  checksum-valid address inside) - an SPA fallback page that
  returns 200 for every path produces nothing here;
- node config files (bitcoin.conf family) carrying RPC credentials;
- wallet backup archives and directory listings naming wallet files;
- browser-wallet vault dumps (MetaMask / Phantom encrypted vault
  blobs) sitting in served pages, JS or storage dumps;
- wallet addresses in source maps and in docs the target serves
  (README / DONATE / FUNDING files), and wallet filenames in the
  reflog of a served .git.

Detection only: read-only GETs of public paths, structure/content
validation, secrets redacted in findings.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Callable, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import (
    PackPlugin, b58check_verify, collect_texts, eip55_state,
    segwit_verify, xmr_verify,
)
from .injutil import same_domain

B58 = r"1-9A-HJ-NP-Za-km-z"


# ---------------------------------------------------------------------------
# Content helpers: what counts as wallet material inside a text file
# ---------------------------------------------------------------------------

def _bip39_phrases(text: str):
    """[(phrase, n_words)] with full BIP-39 checksum verification."""
    from .cryptopack_secrets import BIP39_WORD_INDEX
    out = []
    low = re.sub(r"<[^>]+>", " ", text.lower())
    for m in re.finditer(r"[a-z]+(?:\s+[a-z]+){10,30}", low):
        words = m.group(0).split()
        hit = False
        for start in range(0, len(words) - 11):
            for n in (24, 21, 18, 15, 12):
                cand = words[start:start + n]
                if len(cand) < n:
                    continue
                if not all(w in BIP39_WORD_INDEX for w in cand):
                    continue
                bits = "".join(format(BIP39_WORD_INDEX[w], "011b")
                               for w in cand)
                ent_len = len(bits) * 32 // 33
                ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
                import hashlib
                digest = hashlib.sha256(ent).digest()
                if bits[ent_len:] == format(
                        digest[0], "08b")[:len(bits) - ent_len]:
                    out.append((" ".join(cand), n))
                    hit = True
                    break
            if hit:
                break
    return out


def _validated_addresses(text: str) -> List[Tuple[str, str]]:
    """Checksum-validated public addresses of the major chains."""
    out: List[Tuple[str, str]] = []
    for m in re.finditer(rf"\b[13][{B58}]{{25,34}}\b", text):
        p = b58check_verify(m.group(0))
        if p and len(p) == 21 and p[0] in (0x00, 0x05):
            out.append(("Bitcoin", m.group(0)))
    for m in re.finditer(r"\bbc1[qp][a-z0-9]{38,58}\b", text):
        if segwit_verify(m.group(0), "bc", 0) or \
                segwit_verify(m.group(0), "bc", 1):
            out.append(("Bitcoin", m.group(0)))
    for m in re.finditer(r"\b0x[0-9a-fA-F]{40}\b", text):
        if eip55_state(m.group(0)) == "checksummed":
            out.append(("Ethereum", m.group(0)))
    for m in re.finditer(rf"\b4[{B58}]{{94}}\b", text):
        if xmr_verify(m.group(0), (0x12, 0x35)):
            out.append(("Monero", m.group(0)))
    return out[:10]


_LABELED_KEY_RE = re.compile(
    r"(?:private[ _-]?key|seed phrase|mnemonic|secret key)"
    r"[^0-9a-fA-F]{0,40}(?:0x)?[0-9a-fA-F]{64}", re.I)


def _wallet_material_detail(text: str) -> Optional[str]:
    """Why this text counts as wallet material (or None)."""
    phrases = _bip39_phrases(text)
    if phrases:
        from .secretutils import redact
        phrase, n = phrases[0]
        return (f"contains a checksum-valid BIP-39 seed phrase "
                f"({n} words): {redact(phrase, show=6)}")
    if _LABELED_KEY_RE.search(text):
        return "contains a labeled private key / seed entry"
    addrs = _validated_addresses(text)
    if addrs:
        chains = ", ".join(sorted({c for c, _ in addrs}))
        return f"contains checksum-validated address(es): {chains}"
    return None


# ---------------------------------------------------------------------------
# Probe base: one plugin per wallet file family, structural validation
# ---------------------------------------------------------------------------

class _WalletProbePlugin(Plugin):
    id = None  # abstract
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 60

    KEY = "wallet_file"
    PATHS: List[Tuple[str, str, int]] = []  # (path, label, confidence)

    def _validate(self, text: str, headers: dict,
                  length: int) -> Optional[str]:
        raise NotImplementedError

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        try:
            base = (await web_base(ctx, target, domain)).rstrip("/")
        except Exception:
            base = f"https://{domain}"
        findings: List[Finding] = []
        sem = asyncio.Semaphore(8)

        async def check(path, label, conf):
            full = base + path
            async with sem:
                try:
                    probed = await ctx.probe(full, timeout=8)
                except Exception:
                    return
            status = probed.get("status", 0)
            if status == 200:
                detail = None
                try:
                    detail = self._validate(probed.get("text", ""),
                                            probed.get("headers", {}),
                                            probed.get("length", 0))
                except Exception:
                    detail = None
                if detail:
                    findings.append(self._f(
                        "leak", self.KEY,
                        f"{path} is publicly served - {label}: {detail}",
                        source="direct probe", source_url=full,
                        confidence=conf, passive=False,
                        evidence={"path": path, "detail": detail,
                                  "severity": "high"}))
            elif status in (401, 403):
                findings.append(self._f(
                    "web", self.KEY + "_guarded",
                    f"{path} returned {status} (exists but guarded) - "
                    f"{label}",
                    source="direct probe", source_url=full,
                    confidence=55, passive=False,
                    evidence={"path": path, "status": status}))

        await asyncio.gather(*[check(*p) for p in self.PATHS])
        res = self._ok(findings,
                       f"checked {len(self.PATHS)} wallet file paths")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


def _looks_binary(text: str, headers: dict) -> bool:
    ctype = (headers.get("content-type") or "").lower()
    if "text/html" in ctype:
        return False
    head = text.lstrip()[:64]
    return not head.startswith("<")


class CpWalletDatFile(_WalletProbePlugin):
    id = "cp_wallet_dat_file"
    label = "Exposed wallet.dat file"
    description = ("A Bitcoin Core / fork wallet.dat database served "
                   "over HTTP - the wallet itself, keys included, "
                   "protected only by its passphrase (if any).")
    KEY = "wallet_dat_exposed"
    PATHS = [
        ("/wallet.dat", "Bitcoin Core wallet database", 80),
        ("/.bitcoin/wallet.dat", "Bitcoin Core wallet database", 85),
        ("/bitcoin/wallet.dat", "Bitcoin Core wallet database", 80),
        ("/wallet/wallet.dat", "wallet database", 78),
        ("/.dogecoin/wallet.dat", "Dogecoin wallet database", 82),
        ("/.litecoin/wallet.dat", "Litecoin wallet database", 82),
    ]

    def _validate(self, text, headers, length):
        if length < 200 or not _looks_binary(text, headers):
            return None
        return f"binary wallet database, {length} bytes"


class CpWalletKeystoreFile(_WalletProbePlugin):
    id = "cp_wallet_keystore_file"
    label = "Exposed Ethereum keystore file"
    description = ("A Web3 keystore JSON (version 3, KDF + cipher) "
                   "served at a well-known path - brute-forceable "
                   "offline against weak passphrases.")
    KEY = "keystore_file_exposed"
    PATHS = [
        ("/keystore.json", "Ethereum keystore", 88),
        ("/keystore", "Ethereum keystore", 85),
        ("/.ethereum/keystore", "Ethereum keystore", 85),
        ("/ethereum/keystore", "Ethereum keystore", 82),
        ("/wallet/keystore.json", "Ethereum keystore", 85),
    ]

    def _validate(self, text, headers, length):
        try:
            doc = json.loads(text)
        except Exception:
            return None
        if not isinstance(doc, dict):
            return None
        crypto = doc.get("crypto") or doc.get("Crypto") or {}
        if isinstance(crypto, dict) and "kdf" in crypto \
                and "ciphertext" in crypto:
            return (f"keystore JSON with kdf={crypto.get('kdf')}, "
                    f"address field present: {'address' in doc}")
        return None


class CpWalletElectrumFile(_WalletProbePlugin):
    id = "cp_wallet_electrum_file"
    label = "Exposed Electrum wallet file"
    description = ("An Electrum wallet file (JSON with wallet_type / "
                   "keystore structure) served publicly.")
    KEY = "electrum_wallet_exposed"
    PATHS = [
        ("/default_wallet", "Electrum wallet", 85),
        ("/.electrum/wallets/default_wallet", "Electrum wallet", 88),
        ("/electrum/default_wallet", "Electrum wallet", 85),
        ("/wallet/default_wallet", "Electrum wallet", 82),
        ("/electrum_wallet", "Electrum wallet", 80),
    ]

    def _validate(self, text, headers, length):
        try:
            doc = json.loads(text)
        except Exception:
            return None
        if not isinstance(doc, dict):
            return None
        if "wallet_type" in doc or ("seed_version" in doc
                                    and "keystore" in doc):
            return f"Electrum wallet JSON (type={doc.get('wallet_type')})"
        return None


class CpWalletBackupText(_WalletProbePlugin):
    id = "cp_wallet_backup_text"
    label = "Exposed wallet/seed backup text file"
    description = ("Seed/wallet backup text files at well-known "
                   "paths, validated by content: a served file only "
                   "counts when it actually contains a verified seed "
                   "phrase, a labeled key, or validated addresses.")
    KEY = "wallet_backup_text_exposed"
    PATHS = [
        ("/backup.txt", "wallet backup text", 92),
        ("/wallet-backup.txt", "wallet backup text", 94),
        ("/wallet_backup.txt", "wallet backup text", 94),
        ("/seed.txt", "seed backup text", 94),
        ("/seed-backup.txt", "seed backup text", 94),
        ("/seed_backup.txt", "seed backup text", 94),
        ("/mnemonic.txt", "mnemonic backup text", 94),
        ("/recovery-phrase.txt", "recovery phrase backup", 94),
        ("/private-key.txt", "private key backup", 92),
        ("/keys.txt", "keys backup text", 90),
        ("/wallet.txt", "wallet backup text", 90),
        ("/wallet-keys.txt", "wallet keys backup", 92),
    ]

    def _validate(self, text, headers, length):
        return _wallet_material_detail(text)


class CpWalletBtcConf(_WalletProbePlugin):
    id = "cp_wallet_btc_conf"
    label = "Exposed node config with RPC credentials (bitcoin.conf family)"
    description = ("bitcoin.conf / litecoin.conf / dogecoin.conf / "
                   "elements.conf served publicly AND containing RPC "
                   "credential lines - full node control if the RPC "
                   "port is reachable.")
    KEY = "node_conf_creds_exposed"
    PATHS = [
        ("/bitcoin.conf", "Bitcoin Core config", 90),
        ("/.bitcoin/bitcoin.conf", "Bitcoin Core config", 92),
        ("/bitcoin/bitcoin.conf", "Bitcoin Core config", 90),
        ("/litecoin.conf", "Litecoin config", 90),
        ("/.litecoin/litecoin.conf", "Litecoin config", 92),
        ("/dogecoin.conf", "Dogecoin config", 90),
        ("/.dogecoin/dogecoin.conf", "Dogecoin config", 92),
        ("/elements.conf", "Elements config", 88),
        ("/.elements/elements.conf", "Elements config", 90),
    ]

    def _validate(self, text, headers, length):
        low = text.lower()
        has_user = "rpcuser" in low
        has_pass = "rpcpassword" in low
        if has_user and has_pass:
            return "contains rpcuser AND rpcpassword lines"
        if has_pass:
            return "contains an rpcpassword line"
        if "rpcallowip" in low and has_user:
            return "contains rpcuser and rpcallowip lines"
        return None


class CpWalletArchiveFile(_WalletProbePlugin):
    id = "cp_wallet_archive_file"
    label = "Exposed wallet backup archive"
    description = ("Zip/tar archives named like wallet backups "
                   "served publicly - the classic 'backed up my "
                   "whole wallet folder to the web root' leak.")
    KEY = "wallet_archive_exposed"
    PATHS = [
        ("/wallet.zip", "wallet backup archive", 82),
        ("/wallet-backup.zip", "wallet backup archive", 85),
        ("/wallet_backup.zip", "wallet backup archive", 85),
        ("/backup-wallet.zip", "wallet backup archive", 85),
        ("/wallets.zip", "wallet backup archive", 82),
        ("/seed.zip", "seed backup archive", 85),
        ("/keys.zip", "keys backup archive", 82),
        ("/wallet.tar.gz", "wallet backup archive", 82),
        ("/wallet-backup.tar.gz", "wallet backup archive", 85),
    ]

    def _validate(self, text, headers, length):
        ctype = (headers.get("content-type") or "").lower()
        if "text/html" in ctype or text.lstrip().startswith("<"):
            return None
        if text.startswith("PK") or "zip" in ctype \
                or "gzip" in ctype or "octet-stream" in ctype:
            if length > 100:
                return f"archive download, {length} bytes"
        return None


_WALLET_FILENAME_RE = re.compile(
    r"(?:wallet\.dat|UTC--[\w.\-]{10,}|[\w.\-]*(?:seed|mnemonic|keystore|"
    r"wallet[ _\-]?backup|backup[ _\-]?wallet)[\w.\-]*)", re.I)


class CpWalletDirListing(_WalletProbePlugin):
    id = "cp_wallet_dir_listing"
    label = "Directory listing naming wallet files"
    description = ("Open directory listings (backup/upload/wallet "
                   "folders) whose index pages name wallet, seed or "
                   "keystore files - the files are one click away.")
    KEY = "wallet_files_in_listing"
    PATHS = [
        ("/backup/", "backup directory listing", 88),
        ("/backups/", "backup directory listing", 88),
        ("/wallet/", "wallet directory listing", 90),
        ("/wallets/", "wallet directory listing", 90),
        ("/uploads/", "uploads directory listing", 85),
        ("/files/", "files directory listing", 85),
        ("/download/", "download directory listing", 85),
        ("/downloads/", "download directory listing", 85),
        ("/keys/", "keys directory listing", 88),
        ("/private/", "private directory listing", 85),
    ]

    def _validate(self, text, headers, length):
        names = sorted(set(m.group(0) for m in
                           _WALLET_FILENAME_RE.finditer(text)))
        names = [n for n in names if "." in n and len(n) > 4]
        if names:
            return "listing names wallet file(s): " + ", ".join(names[:5])
        return None


# ---------------------------------------------------------------------------
# Served .git: wallet filenames in the reflog
# ---------------------------------------------------------------------------

_REFLOG_LINE = re.compile(
    r"^[0-9a-f]{40} [0-9a-f]{40} .+ \d{10} [+-]\d{4}\t(.*)$", re.M)
_WALLET_MSG_RE = re.compile(
    r"(wallet\.dat|seed|mnemonic|keystore|\.keys\b|UTC--|"
    r"wallet[ _\-]?backup|private[ _\-]?key)", re.I)


class CpWalletGitServed(Plugin):
    id = "cp_wallet_git_served"
    label = "Wallet files in served .git history"
    description = ("When a target serves its own .git, the reflog "
                   "commit messages reveal wallet/seed/key files that "
                   "were committed - even if later deleted from the "
                   "working tree.")
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        try:
            base = (await web_base(ctx, target, domain)).rstrip("/")
        except Exception:
            base = f"https://{domain}"
        findings: List[Finding] = []
        for path in ("/.git/logs/HEAD", "/.git/COMMIT_EDITMSG"):
            try:
                page = await ctx.fetch_page(base + path, timeout=10)
            except Exception:
                page = None
            if page is None:
                continue
            try:
                if page["status_code"] != 200:
                    continue
                text = page["text"][:200_000]
            except Exception:
                continue
            hits = set()
            if path.endswith("logs/HEAD"):
                for m in _REFLOG_LINE.finditer(text):
                    for w in _WALLET_MSG_RE.finditer(m.group(1)):
                        hits.add(w.group(0))
            else:
                for w in _WALLET_MSG_RE.finditer(text):
                    hits.add(w.group(0))
            if hits:
                findings.append(self._f(
                    "leak", "git_history_wallet_refs",
                    f"{path} references wallet material: "
                    + ", ".join(sorted(hits)[:5]),
                    source="served .git", source_url=base + path,
                    confidence=85, passive=True,
                    evidence={"path": path, "refs": sorted(hits)[:5],
                              "severity": "high"}))
        res = self._ok(findings, f"{len(findings)} .git wallet ref(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Donation/payment addresses in docs the target serves
# ---------------------------------------------------------------------------

_DOC_PATHS = ("/README.md", "/readme.md", "/DONATE.md", "/donate.md",
              "/donations.txt", "/DONATIONS.md", "/.github/FUNDING.yml",
              "/FUNDING.yml", "/SUPPORT.md", "/support.md")


class CpWalletServedDocs(Plugin):
    id = "cp_wallet_served_docs"
    label = "Wallet addresses in served docs (README/DONATE/FUNDING)"
    description = ("Donation and payment addresses published in "
                   "documents the target serves at its web root - "
                   "only checksum-validated addresses are reported.")
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        try:
            base = (await web_base(ctx, target, domain)).rstrip("/")
        except Exception:
            base = f"https://{domain}"
        findings: List[Finding] = []
        for path in _DOC_PATHS:
            try:
                page = await ctx.fetch_page(base + path, timeout=10)
            except Exception:
                page = None
            if page is None:
                continue
            try:
                if page["status_code"] != 200:
                    continue
                text = page["text"][:200_000]
            except Exception:
                continue
            for chain, addr in _validated_addresses(text):
                findings.append(self._f(
                    "crypto", "served_doc_address",
                    f"{chain} address in served doc {path}: {addr}",
                    source="served doc", source_url=base + path,
                    confidence=85, passive=True,
                    evidence={"doc": path, "chain": chain,
                              "address": addr}))
            if len(findings) >= 15:
                break
        res = self._ok(findings,
                       f"{len(findings)} address(es) in served docs")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Source maps: secrets and addresses in sourcesContent
# ---------------------------------------------------------------------------

_SOURCEMAP_URL_RE = re.compile(r"sourceMappingURL=([^\s'\"]+)")
_SIGNER_CTX_RE = re.compile(
    r"(?:private[ _]?key|signer|deployer|mnemonic|seed)"
    r"[^0-9a-fA-F]{0,40}(0x[0-9a-fA-F]{64})", re.I)


class CpWalletSourcemap(Plugin):
    id = "cp_wallet_sourcemap"
    label = "Secrets & addresses in JS source maps"
    description = ("Source maps ship the target's original sources "
                   "to every visitor; this checks sourcesContent for "
                   "seed phrases, context-labeled private keys and "
                   "checksum-validated wallet addresses.")
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        map_urls: List[str] = []
        for where, text, url in texts:
            if where != "JS bundle":
                continue
            m = _SOURCEMAP_URL_RE.search(text[-3000:])
            if m:
                map_urls.append(urljoin(url, m.group(1)))
            else:
                map_urls.append(url + ".map")
        findings: List[Finding] = []
        seen = set()
        for map_url in map_urls[:4]:
            if map_url in seen:
                continue
            seen.add(map_url)
            try:
                page = await ctx.fetch_page(map_url, timeout=15)
            except Exception:
                page = None
            if page is None:
                continue
            try:
                if page["status_code"] != 200:
                    continue
                raw = page["text"][:1_000_000]
            except Exception:
                continue
            content = raw
            try:
                doc = json.loads(raw)
                if isinstance(doc, dict) and doc.get("sourcesContent"):
                    content = "\n".join(
                        s for s in doc["sourcesContent"] if isinstance(s, str))
            except Exception:
                pass
            phrases = _bip39_phrases(content)
            if phrases:
                from .secretutils import redact
                phrase, n = phrases[0]
                findings.append(self._f(
                    "leak", "sourcemap_seed_phrase",
                    f"Seed phrase ({n} words) in source map "
                    f"{urlparse(map_url).path}: {redact(phrase, show=6)}",
                    source="source map", source_url=map_url,
                    confidence=97, passive=True,
                    evidence={"words": n, "severity": "high"}))
            km = _SIGNER_CTX_RE.search(content)
            if km:
                from .secretutils import redact
                findings.append(self._f(
                    "leak", "sourcemap_private_key",
                    f"Context-labeled private key in source map "
                    f"{urlparse(map_url).path}: {redact(km.group(1), show=4)}",
                    source="source map", source_url=map_url,
                    confidence=95, passive=True,
                    evidence={"severity": "high"}))
            for chain, addr in _validated_addresses(content)[:3]:
                findings.append(self._f(
                    "crypto", "sourcemap_address",
                    f"{chain} address in source map "
                    f"{urlparse(map_url).path}: {addr}",
                    source="source map", source_url=map_url,
                    confidence=82, passive=True,
                    evidence={"chain": chain, "address": addr}))
        res = self._ok(findings, f"{len(findings)} source map finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Content-pattern wallet plugins (homepage + JS surface)
# ---------------------------------------------------------------------------

class CpWalletMetamaskVault(PackPlugin):
    id = "cp_wallet_metamask_vault"
    label = "MetaMask vault data in served content"
    description = ("MetaMask encrypted vault blobs (KeyringController "
                   "state) inside pages, JS bundles or storage dumps "
                   "the target serves - the vault plus a weak "
                   "password is the whole wallet.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [
        (r"\"KeyringController\"\s*:\s*\{[^{}]{0,120}\"vault\"\s*:",
         "metamask_vault_state", "MetaMask KeyringController vault", 92,
         None),
        (r"\"vault\"\s*:\s*\{\s*\"data\"\s*:\s*\"[A-Za-z0-9+/=]{60,}\""
         r"[^{}]{0,200}\"iv\"\s*:",
         "metamask_vault_object", "MetaMask vault object (data+iv)",
         90, None),
        (r"\"vault\"\s*:\s*\"\{\\?\"data\\?\"\s*:\s*\\?\"[A-Za-z0-9+/=]{60,}",
         "metamask_vault_stringified",
         "MetaMask vault (stringified in storage dump)", 88, None),
    ]


class CpWalletPhantomVault(PackPlugin):
    id = "cp_wallet_phantom_vault"
    label = "Phantom/Solana wallet vault data in served content"
    description = ("Phantom wallet vault/seed structures inside "
                   "served storage dumps or JS - Solana wallet "
                   "compromise material if the password is weak.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [
        (r"\"phantom\"\s*:\s*\{\s*\"[^\"]+\"\s*:\s*\"[A-Za-z0-9+/=]{60,}\"",
         "phantom_vault_blob", "Phantom vault blob in storage dump",
         82, None),
        (r"(?:phantom[-_ ]?vault|vault[-_ ]?phantom|phantom.{0,30}"
         r"encrypted.{0,20}seed)",
         "phantom_vault_ref", "Phantom vault reference", 78, None),
    ]


class CpWalletSeedFileRefs(PackPlugin):
    id = "cp_wallet_seed_file_refs"
    label = "Links to wallet/seed backup files"
    description = ("Pages and JS that link or point at seed, "
                   "mnemonic, keystore or wallet-backup files hosted "
                   "on the target - the exposure path to the file "
                   "itself.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?:href|src)\s*=\s*[\"']([^\"']*(?:seed|mnemonic|keystore|"
         r"wallet)[^\"']*\.(?:txt|json|zip|dat|keys|pdf))[\"']",
         "wallet_file_link", "Link to wallet/seed file", 85, None),
        (r"[\"'](/[\w./\-]*(?:wallet[-_]?backup|seed[-_]?backup|"
         r"backup[-_]?wallet)[\w./\-]*\.(?:txt|json|zip|dat|keys))[\"']",
         "wallet_backup_path_ref", "Wallet backup path reference",
         85, None),
    ]


class CpWalletConfigCreds(PackPlugin):
    id = "cp_wallet_config_creds"
    label = "Wallet/node credentials in served config text"
    description = ("RPC usernames/passwords and wallet passphrases "
                   "inside config text the target serves (conf dumps, "
                   "env samples, JS config) - as opposed to wave 1's "
                   "key-shaped assignments.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"rpcpassword\s*[:=]\s*(\S{4,})", "rpc_password_value",
         "RPC password in served config", 92, None),
        (r"rpcuser\s*[:=]\s*(\S{3,})", "rpc_user_value",
         "RPC user in served config", 75, None),
        (r"(walletpassphrase|wallet_password|WALLET_PASSPHRASE)",
         "wallet_passphrase_ref", "Wallet passphrase reference", 80,
         None),
    ]


class CpWalletQrPayload(PackPlugin):
    id = "cp_wallet_qr_payload"
    label = "QR-code payment payloads"
    description = ("QR generator URLs (qrserver / Google Charts / "
                   "tec-it) whose payload parameter carries a crypto "
                   "payment URI or validated address - the target's "
                   "live payment destinations, decodable by anyone.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?:)?//(?:api\.qrserver\.com/v1/create-qr-code|"
         r"chart\.googleapis\.com/chart|qrcode\.tec-it\.com/API/QRCode)"
         r"[^\s\"'<>]+)", "qr_payment_payload",
         "QR code payment payload", 85, None),
    ]

    @staticmethod
    def _validator(url: str) -> bool:
        q = urlparse(url if url.startswith("http") else "https:" + url)
        from urllib.parse import parse_qs
        params = parse_qs(q.query)
        payload = ""
        for key in ("data", "chl", "text"):
            if params.get(key):
                payload = unquote(params[key][0])
                break
        if not payload:
            return False
        m = re.match(r"(?i)(bitcoin|ethereum|litecoin|bitcoincash|"
                     r"monero|solana|ripple|dogecoin|zcash):", payload)
        if m:
            # payment URI: the address part must itself validate -
            # a "bitcoin:" label on a broken address is a broken
            # link, not a payment payload
            addr = re.split(r"[?&]", payload[m.end():], 1)[0].strip()
            if _validated_addresses(addr):
                return True
            return payload.lower().startswith("ethereum:") and bool(
                re.fullmatch(r"0x[0-9a-fA-F]{40}", addr))
        addrs = _validated_addresses(payload)
        if addrs:
            return True
        return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", payload.strip()))


# Wire the QR validator into the pattern (kept as a staticmethod so
# the class body above stays declarative).
CpWalletQrPayload.PATTERNS = [
    (pat, key, label, conf, CpWalletQrPayload._validator)
    for (pat, key, label, conf, _v) in CpWalletQrPayload.PATTERNS
]
