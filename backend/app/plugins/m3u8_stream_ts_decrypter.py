"""M3U8 / HLS stream protection audit (list name: m3u8-stream-ts-
decrypter): parses an operator-supplied or target-served m3u8
playlist and flags stream-protection posture:

- METHOD=NONE: segments are cleartext
- METHOD=SAMPLE-AES: weaker, sample-only encryption
- a relative / same-directory key URI served alongside the
  playlist (key publicly fetchable with the playlist)
- an explicit static IV in EXT-X-KEY (IV reuse across segments)

BOUNDARY: posture analysis of playlists only. No third-party
content is collected or decrypted; decryption verification would
need an operator-supplied key + segment for the operator's own
stream and is not performed against third-party streams.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

_KEY_RE = re.compile(r"#EXT-X-KEY:([^\n\r]+)")
_ATTR_RE = re.compile(r"([A-Z\-]+)=(\"[^\"]*\"|[^\s,]+)")


def parse_keys(text: str) -> List[Dict[str, str]]:
    keys = []
    for m in _KEY_RE.finditer(text or ""):
        attrs = {}
        for am in _ATTR_RE.finditer(m.group(1)):
            attrs[am.group(1)] = am.group(2).strip('"')
        keys.append(attrs)
    return keys


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if "#EXTM3U" not in text:
        return hits
    keys = parse_keys(text)
    segments = [ln for ln in text.splitlines()
                if ln.strip() and not ln.startswith("#")]
    if not keys:
        if segments:
            hits.append({
                "key": "hls_no_encryption_directive",
                "severity": "medium",
                "value": f"HLS playlist has no EXT-X-KEY at all for "
                         f"{len(segments)} segment(s) - segments "
                         "are served unencrypted",
                "evidence": {"segments": len(segments),
                             "remediation": "Add AES-128 EXT-X-KEY "
                             "protection or treat the stream as "
                             "public content."}})
        return hits
    for attrs in keys:
        method = (attrs.get("METHOD") or "").upper()
        uri = attrs.get("URI", "")
        if method == "NONE":
            hits.append({
                "key": "hls_cleartext_segments", "severity": "high",
                "value": "HLS playlist declares METHOD=NONE - all "
                         "segments are cleartext",
                "evidence": {"remediation": "Use AES-128 (or "
                             "SAMPLE-AES only where DRM requires) "
                             "with keys served over authenticated "
                             "channels."}})
        elif method == "SAMPLE-AES":
            hits.append({
                "key": "hls_sample_aes_weakness",
                "severity": "medium",
                "value": "HLS playlist uses SAMPLE-AES - only media "
                         "samples are encrypted, headers/structure "
                         "remain cleartext",
                "evidence": {"remediation": "Prefer full-segment "
                             "AES-128 where the threat model needs "
                             "content protection."}})
        if method not in ("", "NONE") and uri:
            parsed = urlparse(uri)
            if not parsed.netloc:
                hits.append({
                    "key": "hls_key_uri_served_with_playlist",
                    "severity": "medium",
                    "value": f"HLS key URI '{uri[:100]}' is relative "
                             "- the decryption key is fetchable from "
                             "the same public location as the playlist",
                    "evidence": {"key_uri": uri[:200],
                                 "remediation": "Serve keys from an "
                                 "authenticated endpoint with short-"
                                 "lived tokens, separate from the "
                                 "playlist CDN path."}})
            if "IV" in attrs:
                hits.append({
                    "key": "hls_static_iv_reuse",
                    "severity": "medium",
                    "value": f"HLS EXT-X-KEY pins a static IV "
                             f"({attrs['IV'][:34]}) - the same IV "
                             "is reused for every segment",
                    "evidence": {"remediation": "Omit the IV "
                                 "attribute so the media sequence "
                                 "number is used per segment, or "
                                 "rotate keys/IVs per segment."}})
    # Dedupe by key.
    seen, out = set(), []
    for h in hits:
        if h["key"] not in seen:
            seen.add(h["key"])
            out.append(h)
    return out[:10]


class M3u8StreamTsDecrypterPlugin(Plugin):
    id = "m3u8_stream_ts_decrypter"
    label = "M3U8 Stream Protection Audit"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2
    description = ("HLS playlist posture: METHOD=NONE cleartext, "
                   "key URI publicly fetchable alongside playlist, "
                   "static IV reuse, SAMPLE-AES weakness. Playlist "
                   "analysis only - no third-party decryption.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "web",
                          ("playlists", "m3u8_data"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        url = target.normalized or ""
        if url.endswith(".m3u8"):
            try:
                page = await ctx.fetch_page(url)
            except Exception:
                page = None
            if page and page.get("text"):
                findings = []
                for hit in analyze(page["text"].encode(
                        "utf-8", "ignore"), url):
                    ev = {"severity": hit["severity"]}
                    ev.update(hit.get("evidence") or {})
                    findings.append(self._f(
                        "web", hit["key"], hit["value"],
                        source="served playlist", source_url=url,
                        confidence=85, evidence=ev))
                return self._ok(findings, "playlist analysed")
        return self._ok([], "no supplied playlist and target is "
                        "not an .m3u8 URL")
