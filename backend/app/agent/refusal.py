"""Hard boundaries for the agent, enforced in code AND the system prompt.

Detection only, on authorized targets only. Legit defensive security work
passes. These hard-limit topics are refused no matter how they are framed:
minors/sexual content, weapons, theft, fraud, unauthorized access, doxxing
or facial recognition, private-key/seed display or theft, wallet sweeping,
mixers, forged IDs, brute-forcing, auth bypass, exploit confirmation,
private-data access, person lookup, and any scan of crypto.com.
"""

from __future__ import annotations

import re

# (pattern, reason). Harm-purpose wording fires regardless of framing;
# bare defensive/research wording without a harm purpose is not in here.
HARD_PATTERNS: list[tuple[str, str]] = [
    (r"\b(child|minor|underage|kid)\b.{0,40}\b(sexual|nude|porn|explicit)\b", "minors/sexual content"),
    (r"\b(sexual|porn|explicit)\b.{0,40}\b(child|minor|underage|kid)\b", "minors/sexual content"),
    (r"\b(cs am|child sexual abuse)\b", "minors/sexual content"),
    (r"\b(build|make|create)\b.{0,50}\b(bioweapon|chemical weapon|dirty bomb|nuclear weapon)\b", "weapons"),
    (r"\bsteal\b.{0,40}\b(password|credential|account|wallet|session)\b", "theft"),
    (r"\bsteal\b.{0,40}\b(private key|seed phrase|mnemonic)\b", "private-key theft"),
    (r"\b(private key|seed phrase|mnemonic)\b.{0,30}\b(show|display|print|reveal|dump|give me|extract)\b", "private-key/seed display"),
    (r"\b(show|display|give me|reveal|print|dump)\b.{0,30}\b(private key|seed phrase|mnemonic)\b", "private-key/seed display"),
    (r"\bsweep\b.{0,40}\bwallet\b", "wallet sweeping"),
    (r"\bdrain\b.{0,40}\bwallet\b", "wallet sweeping"),
    (r"\b(mixer|tumbler)\b.{0,40}\b(launder|hide|obscure|clean)\b", "mixers/laundering"),
    (r"\blaunder\b", "mixers/laundering"),
    (r"\bforge[ds]?\b.{0,30}\b(id|passport|license|document)\b", "forged IDs"),
    (r"\bfake\b.{0,20}\b(passport|id card|driver'?s license)\b", "forged IDs"),
    (r"\bbrute[- ]?force\b.{0,40}\b(password|login|account)\b", "brute-forcing"),
    (r"\bbypass\b.{0,30}\b(auth|login|2fa|paywall)\b", "auth bypass"),
    (r"\bdox(x|ing)?\b", "doxxing"),
    (r"\bfacial recognition\b.{0,30}\b(identify|identify|find|lookup)\b", "facial recognition"),
    (r"\bidentify\b.{0,30}\b(person|someone)\b.{0,30}\b(photo|picture|image)\b", "facial recognition"),
    (r"\blookup\b.{0,30}\b(person|address|phone)\b", "person lookup"),
    (r"\bexploit\b.{0,40}\b(confirm|verify|prove|execute|run it)\b", "exploit confirmation"),
    (r"\b(confirm|verify|prove)\b.{0,40}\bexploit\b", "exploit confirmation"),
    (r"\bunauthorized access\b.{0,30}\b(someone else'?s|victim|third[- ]party)\b", "unauthorized access"),
    (r"\bhack into\b.{0,30}\b(someone|their|victim)\b", "unauthorized access"),
    (r"\bcrypto\.com\b", "crypto.com is never a scan target"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), r) for p, r in HARD_PATTERNS]

# Refusal phrasings the brain may emit; the detector spots them so the
# app can retry on the next model instead of showing a refusal.
REFUSAL_PHRASES = [
    "i can't help with that",
    "i cannot help with that",
    "i'm sorry, but i can't",
    "i am sorry, but i cannot",
    "as an ai, i cannot",
    "i'm not able to help",
    "against my policy",
    "i can't assist with",
    "i cannot assist with",
    "i refuse to",
    "i won't help with that",
    "not appropriate for me to help",
    "i'm unable to comply",
]


def hard_block_reason(text: str) -> str | None:
    """Reason string if the text trips a hard boundary, else None."""
    text = text or ""
    for pattern, reason in _COMPILED:
        if pattern.search(text):
            return reason
    return None


def is_refusal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(p in lowered for p in REFUSAL_PHRASES)
