"""Statistically-grounded timing + structural diff helpers.

Problem this solves: timing-based detection ("it was slow once, must be
vulnerable") produces false positives. These helpers require the observed
delay to MATCH the injected delay within statistical confidence before a
finding is raised - never "it was slow once".

Usage by timing-sensitive plugins (sqli, cmdi, ...):

    from ..timing_baseline import sample_baseline, is_timing_anomaly

    baseline = await sample_baseline(ctx.http, ctx.limiter, "GET", url, n=10)
    t0 = time.monotonic()
    r = await fetch(...)          # request carrying e.g. SLEEP(5) payload
    observed = time.monotonic() - t0
    if is_timing_anomaly(baseline, observed, injected_delay=5.0):
        ... raise finding ...

Also ships DOM structural diffing: hash the DOM structure of a baseline
response, then compare against the response to safe probe payloads.
Only significant structural changes (new elements, changed forms) are
flagged - cosmetic text/attribute differences are ignored.

All probes are SAFE: read-only requests and benign payloads. Nothing is
submitted, modified, or deleted on the target.
"""
from __future__ import annotations

import hashlib
import statistics
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Timing baseline
# ---------------------------------------------------------------------------

@dataclass
class TimingBaseline:
    url: str
    method: str
    n: int
    mean: float
    stdev: float
    samples: List[float]

    @property
    def reliable(self) -> bool:
        """Enough stable samples to reason about?"""
        return self.n >= 5 and self.stdev < self.mean * 2.0


async def sample_baseline(client: Any, limiter: Any, method: str, url: str,
                          n: int = 10, timeout: int = 10,
                          headers: Optional[Dict[str, str]] = None) -> TimingBaseline:
    """Sample n baseline response times for an endpoint.

    Sequential, benign GETs - this is calibration, not a load test.
    """
    from .ratelimit import fetch
    samples: List[float] = []
    for _ in range(n):
        try:
            t0 = time.monotonic()
            r = await fetch(client, limiter, method, url, timeout=timeout,
                            max_retries=0, headers=headers or {})
            dt = time.monotonic() - t0
            if r.status_code < 500:
                samples.append(dt)
        except Exception:
            continue
    mean = statistics.mean(samples) if samples else 0.0
    stdev = statistics.stdev(samples) if len(samples) > 1 else (mean or 1.0)
    return TimingBaseline(url=url, method=method, n=len(samples),
                          mean=mean, stdev=max(stdev, 0.01), samples=samples)


def is_timing_anomaly(baseline: TimingBaseline, observed: float,
                      injected_delay: float, k: float = 2.0) -> Tuple[bool, str]:
    """True only if the observed delay matches the injected delay.

    Two gates, both must pass:
    1. Signal above noise: injected_delay must exceed k * stdev, otherwise
       the delay is indistinguishable from normal jitter.
    2. Observed delay matches injected delay within confidence:
       |observed - (mean + injected_delay)| <= k * stdev.

    "It was slow once" can never pass gate 2 - random slowness does not
    land exactly on mean + injected_delay.
    """
    if not baseline.reliable:
        return False, (f"baseline unreliable (n={baseline.n}, "
                       f"stdev={baseline.stdev:.2f}s) - cannot judge timing")
    if injected_delay <= k * baseline.stdev:
        return False, (f"injected delay {injected_delay:.1f}s is within "
                       f"baseline noise (stdev={baseline.stdev:.2f}s) - "
                       "signal too weak to call")
    expected = baseline.mean + injected_delay
    delta = abs(observed - expected)
    if delta <= k * baseline.stdev:
        return True, (f"observed {observed:.2f}s matches injected "
                      f"{injected_delay:.1f}s + baseline "
                      f"{baseline.mean:.2f}s within {k} sigma")
    return False, (f"observed {observed:.2f}s does not match injected "
                   f"{injected_delay:.1f}s (expected ~{expected:.2f}s) - "
                   "likely random slowness, not a timing signal")


# ---------------------------------------------------------------------------
# Structural diffing
# ---------------------------------------------------------------------------

# Tags that carry interaction surface. New/changed ones are significant;
# everything else is noise.
INTERACTIVE_TAGS = {"form", "input", "button", "select", "textarea",
                    "a", "iframe", "script", "link", "meta"}


class _StructureParser(HTMLParser):
    """Records the DOM as a sequence of (tag, key attrs) - text ignored."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: List[str] = []
        self.forms: List[Tuple[str, str]] = []  # (action, method)
        self.inputs: List[str] = []            # input names

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.tags.append(tag)
        a = dict(attrs)
        if tag == "form":
            self.forms.append((a.get("action", ""), a.get("method", "get").lower()))
        elif tag == "input":
            self.inputs.append(a.get("name", "") or a.get("type", ""))


@dataclass
class StructureFingerprint:
    tag_sequence_hash: str
    tags: List[str]
    forms: List[Tuple[str, str]]
    inputs: List[str]


def dom_structure_hash(html: str) -> StructureFingerprint:
    """Fingerprint the DOM structure (tags only - text/attrs ignored)."""
    p = _StructureParser()
    try:
        p.feed(html[:1_000_000])
    except Exception:
        pass
    seq = "|".join(p.tags)
    h = hashlib.sha256(seq.encode("utf-8", "ignore")).hexdigest()[:16]
    return StructureFingerprint(tag_sequence_hash=h, tags=p.tags,
                                forms=p.forms, inputs=p.inputs)


def structural_diff(baseline_html: str, probe_html: str,
                    min_new_interactive: int = 1) -> Dict[str, Any]:
    """Compare probe response structure against baseline.

    Flags ONLY significant structural changes:
    - new interactive elements (forms, inputs, buttons, iframes, scripts)
      that were not in the baseline,
    - removed forms / changed form actions.

    Cosmetic differences (text, classes, styles, attributes) are ignored.
    """
    base = dom_structure_hash(baseline_html)
    probe = dom_structure_hash(probe_html)

    base_tags = set(base.tags)
    new_tags = [t for t in probe.tags if t not in base_tags]
    new_interactive = sorted({t for t in new_tags if t in INTERACTIVE_TAGS})

    base_forms = set(base.forms)
    probe_forms = set(probe.forms)
    added_forms = sorted(probe_forms - base_forms)
    removed_forms = sorted(base_forms - probe_forms)

    base_inputs = set(base.inputs)
    new_inputs = sorted(set(probe.inputs) - base_inputs)

    significant = (
        len(new_interactive) >= min_new_interactive
        or bool(added_forms)
        or bool(removed_forms)
    )
    return {
        "significant": significant,
        "structure_hash_changed": base.tag_sequence_hash != probe.tag_sequence_hash,
        "new_interactive_tags": new_interactive,
        "added_forms": added_forms,
        "removed_forms": removed_forms,
        "new_inputs": new_inputs,
        "baseline_tag_count": len(base.tags),
        "probe_tag_count": len(probe.tags),
    }


def summarize_structural_diff(diff: Dict[str, Any]) -> str:
    """One-line human summary for evidence."""
    if not diff.get("significant"):
        return "No significant structural change vs baseline."
    bits = []
    if diff.get("new_interactive_tags"):
        bits.append("new interactive elements: " + ", ".join(diff["new_interactive_tags"]))
    if diff.get("added_forms"):
        bits.append(f"added forms: {diff['added_forms']}")
    if diff.get("removed_forms"):
        bits.append(f"removed forms: {diff['removed_forms']}")
    if diff.get("new_inputs"):
        bits.append(f"new inputs: {diff['new_inputs']}")
    return "Significant structural change vs baseline - " + "; ".join(bits) + "."
