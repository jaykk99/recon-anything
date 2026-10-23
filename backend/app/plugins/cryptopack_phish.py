"""Crypto pack: wallet drainers, phishing kits, clipboard hijackers.

These detect the *kit signatures* of crypto theft pages served from
(or injected into) the target: seed-phrase harvest forms, fake wallet
popups, approval-bait contract calls in JS, and clipboard address
swappers. Detection only - signatures and code patterns, nothing is
submitted anywhere.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qs, urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import PackPlugin, collect_texts


class CpDrainerSeedform(PackPlugin):
    id = "cp_drainer_seedform"
    label = "Phishing: seed phrase harvest form"
    description = ("Forms asking for a seed/recovery phrase or mnemonic "
                   "- no legitimate service ever does this in a browser.")
    PATTERNS = [
        (r"(?is)<form[^>]*>.{0,4000}?(?:seed phrase|recovery phrase|"
         r"secret phrase|mnemonic).{0,4000}?</form>",
         "seed_harvest_form", "Seed phrase harvest form", 95, None),
        (r"(?:name|id|placeholder)\s*=\s*[\"'][^\"']*"
         r"(?:seed[-_ ]?phrase|mnemonic|recovery[-_ ]?phrase)[^\"']*[\"']",
         "seed_harvest_input", "Seed phrase input field", 90, None),
    ]


class CpDrainerWalletconnectKit(PackPlugin):
    id = "cp_drainer_walletconnect_kit"
    label = "Phishing: fake WalletConnect / wallet modal kit"
    description = ("Wallet-connect modal clones that fall back to "
                   "asking for a seed phrase or private key - the "
                   "standard drainer-kit tell.")
    CONTEXT_RE = r"walletconnect|connect wallet|web3modal"
    PATTERNS = [
        (r"(?:import (?:your )?wallet|enter (?:your )?(?:seed|recovery|"
         r"private key)|restore (?:your )?wallet)",
         "fake_wallet_modal", "Fake wallet import prompt", 90, None),
    ]


class CpDrainerClaimKit(PackPlugin):
    id = "cp_drainer_claim_kit"
    label = "Phishing: fake airdrop / claim kit"
    description = ("'Claim your airdrop/reward' lures wired to a wallet "
                   "connect + approval flow - the dominant drainer funnel.")
    PATTERNS = [
        (r"(?:claim (?:your )?(?:airdrop|reward|tokens?|bonus)|"
         r"airdrop claim|free mint).{0,300}?(?:connect wallet|approve|sign)",
         "claim_kit", "Airdrop claim lure with wallet flow", 80, None),
    ]


class CpDrainerSetApproval(PackPlugin):
    id = "cp_drainer_setapproval"
    label = "Drainer pattern: setApprovalForAll bait"
    description = ("JS invoking setApprovalForAll - the one-call NFT "
                   "drain primitive. Legit marketplaces use it too, "
                   "so this inventories rather than accuses.")
    PATTERNS = [
        (r"setApprovalForAll\s*\(", "set_approval_for_all",
         "setApprovalForAll invocation", 75, None),
    ]


class CpDrainerEthSign(PackPlugin):
    id = "cp_drainer_ethsign"
    label = "Drainer pattern: eth_sign bait"
    description = ("JS requesting eth_sign / blind personal_sign with "
                   "'verify your wallet' framing - signs arbitrary "
                   "payloads the user cannot read.")
    PATTERNS = [
        (r"(?:eth_sign|\"personal_sign\")", "eth_sign_request",
         "eth_sign/personal_sign request in JS", 70, None),
    ]


class CpDrainerPermit(PackPlugin):
    id = "cp_drainer_permit"
    label = "Drainer pattern: permit signature bait"
    description = ("EIP-2612/Permit2 signature flows in JS "
                   "(permit, PermitSingle, signTypedData with Permit "
                   "types) - gasless approval theft's building blocks.")
    PATTERNS = [
        (r"(?:PermitSingle|PermitBatch|permit2|\"Permit\"\s*:\s*\[)",
         "permit_signature_flow", "Permit typed-data flow in JS", 75, None),
        (r"permit\s*\(\s*[^)]*owner[^)]*spender", "permit_call",
         "permit() call in JS", 70, None),
    ]


class CpClipboardCopySwap(PackPlugin):
    id = "cp_clipboard_copy_swap"
    label = "Clipboard hijacker: copy-event address swap"
    description = ("JS listening for copy events and rewriting "
                   "clipboard text with address-shaped replacements - "
                   "the classic address-swapper trojan pattern.")
    PATTERNS = [
        (r"addEventListener\(\s*['\"]copy['\"]", "copy_listener",
         "Clipboard copy listener in JS", 65, None),
        (r"document\.execCommand\(\s*['\"]copy['\"]", "copy_exec",
         "Programmatic copy in JS", 60, None),
    ]


class CpClipboardPasteSwap(PackPlugin):
    id = "cp_clipboard_paste_swap"
    label = "Clipboard hijacker: paste/input address rewrite"
    description = ("JS intercepting paste/input on address fields and "
                   "substituting a different address-shaped value.")
    PATTERNS = [
        (r"addEventListener\(\s*['\"]paste['\"]", "paste_listener",
         "Paste listener in JS", 65, None),
        (r"onpaste\s*=|addEventListener\(\s*['\"]beforeinput['\"]",
         "paste_handler", "Paste/beforeinput handler in JS", 60, None),
    ]


class CpPhishFakeMetamask(PackPlugin):
    id = "cp_phish_fake_metamask"
    label = "Phishing: fake MetaMask UI"
    description = ("MetaMask-branded unlock/import UI served by the "
                   "target (not metamask.io): password or seed fields "
                   "under the fox brand.")
    CONTEXT_RE = r"metamask"
    PATTERNS = [
        (r"(?:unlock (?:your )?wallet|import (?:an )?account|"
         r"secret recovery phrase|welcome back)",
         "fake_metamask_ui", "Fake MetaMask UI text", 85, None),
    ]


class CpPhishFakeExchange(PackPlugin):
    id = "cp_phish_fake_exchange"
    label = "Phishing: fake exchange login"
    description = ("Exchange-brand login/verification pages (Binance, "
                   "Coinbase, Kraken, KuCoin) served off-brand - "
                   "credential + 2FA harvest kits.")
    PATTERNS = [
        (r"(?is)(?:binance|coinbase|kraken|kucoin|bybit|okx).{0,200}?"
         r"(?:verify your (?:account|identity)|login to (?:your )?account|"
         r"secure your account).{0,400}?<form",
         "fake_exchange_login", "Fake exchange login page", 80, None),
    ]


_QR_APIS = ("api.qrserver.com", "chart.googleapis.com/chart",
            "qrcode.tec-it.com", "quickchart.io/qr")
_ADDR_IN_TEXT = re.compile(
    r"\b(?:[13][a-zA-HJ-NP-Z0-9]{25,34}|bc1[a-z0-9]{39,59}|"
    r"0x[0-9a-fA-F]{40})\b")


class CpPhishQrSwap(Plugin):
    id = "cp_phish_qr_swap"
    label = "Phishing: payment QR / displayed address mismatch"
    description = ("Cross-checks addresses embedded in QR-code image "
                   "URLs against the addresses shown as page text. A "
                   "mismatch is the signature of a QR-swap overlay: "
                   "the victim reads one address and pays another.")
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
            # "Shown" addresses must come from the page's readable
            # content - strip QR-code URLs first, or the embedded
            # (attacker) address would count as 'shown' too.
            readable = re.sub(
                r"https?://[^\s\"'<>]*(?:qrserver|chart\.googleapis|"
                r"quickchart|tec-it|qr-code)[^\s\"'<>]*", " ", text)
            shown = set(_ADDR_IN_TEXT.findall(readable))
            for m in re.finditer(r"https?://[^\s\"'<>]+", text):
                u = m.group(0)
                if not any(api in u for api in _QR_APIS):
                    continue
                qs = parse_qs(urlparse(u).query)
                payload = " ".join(
                    v for vals in qs.values() for v in vals)
                embedded = set(_ADDR_IN_TEXT.findall(payload))
                for addr in embedded:
                    if shown and addr not in shown:
                        findings.append(self._f(
                            "crypto", "qr_address_mismatch",
                            f"QR code pays {addr[:16]}... but the page "
                            f"text shows a different address",
                            source=self.label, source_url=url,
                            confidence=90, passive=True,
                            evidence={"qr_address": addr,
                                      "shown_addresses": sorted(shown)[:5],
                                      "where": where}))
        res = self._ok(findings, f"{len(findings)} QR mismatch(es)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
