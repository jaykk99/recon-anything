"""Canary content for the AI-crawler surface pack (ai_*) tests / proof.

Planted values are assembled from fragments so no complete fake
secret ever sits in the repo (the lesson from the privfind canary,
which tripped GitHub Push Protection).
"""
from __future__ import annotations

# --- Fragments: assembled at import time, never literal in the file --
_SK_A = "sk_"
_SK_B = "live_"
_SK_C = "9f8e7d6c5b4a39281706f5e4d3c2b"
STRIPE_KEY = _SK_A + _SK_B + _SK_C

LLMS_TXT = """# Canary Site

> Documentation index for AI crawlers.

## Docs

- [Internal guide](/docs/internal.md)
- [Private guide](/private/guide.md)
- [External mirror](https://example.org/other.md)

## Optional

- [Public overview](/docs/overview.md)
"""

LLMS_FULL_TXT = """# Canary Site - Full Content

This is the full-content variant of the llms.txt index.
"""

ROBOTS_TXT = """User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /private/

User-agent: *
Disallow: /private/
tdm-reservation: 1
tdm-policy: /.well-known/tdmrep.json
"""

TDMREP_JSON = """{"tdm-reservation": true, "location": "/.well-known/tdmrep.json"}
"""

INTERNAL_MD = """# Internal Guide

This document is linked from llms.txt but reads like an internal
runbook. It carries a live-looking credential that must never reach
a Finding in full:

api_key = '""" + STRIPE_KEY + """'

Rotate it if it ever leaks.
"""

PRIVATE_MD = """# Private Guide

A guide that lives under a robots.txt-disallowed path.
"""

OVERVIEW_MD = """# Public Overview

Nothing sensitive here. Just an overview.
"""

CLEAN_LLMS_MISSING = True  # clean host serves no llms.txt at all

CLEAN_HTML = """<!doctype html><html><head><title>Clean</title></head>
<body><p>Clean site.</p></body></html>
"""

CLEAN_ROBOTS = """User-agent: *
Allow: /
"""

ROUTES = {
    "/llms.txt": ("text/markdown", LLMS_TXT),
    "/llms-full.txt": ("text/markdown", LLMS_FULL_TXT),
    "/robots.txt": ("text/plain", ROBOTS_TXT),
    "/.well-known/tdmrep.json": ("application/json", TDMREP_JSON),
    "/docs/internal.md": ("text/markdown", INTERNAL_MD),
    "/private/guide.md": ("text/markdown", PRIVATE_MD),
    "/docs/overview.md": ("text/markdown", OVERVIEW_MD),
}
