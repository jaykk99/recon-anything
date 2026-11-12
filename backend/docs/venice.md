# Venice (keyless analysis pack)

Backend-only. No API key, no network calls, no new routes, no
frontend. The heuristic advisor (`app/vuln_advisor.py:advise`)
stays the built-in default.

## The honest limit

There is **no free keyless programmatic way to call Venice**,
checked 2026-11-12 against Venice's own docs:

- The API needs an API key (`Authorization: Bearer $VENICE_API_KEY`),
  or x402 per-request USDC payment from a crypto wallet (no key, no
  signup, but real money per call).
- The free tier is **web chat only**: venice.ai as a guest gives
  ~10 text prompts/day on base models with a ~2,000-token context
  window, no account needed. That chat is a browser UI with no
  public endpoint. Driving it from the backend would be scraping
  the web app to dodge the API's auth, so the backend does not do
  that.

## What this does instead

`app/venice_pack.py` turns a completed run into a complete,
self-contained markdown pack: the advisor's ranked candidates with
evidence, top raw findings, and optional repo code excerpts. The
operator pastes it into venice.ai guest chat and Venice writes the
plain-English attack-path analysis. The backend does the hard work
(ranking, evidence); Venice does the synthesis.

```python
from app.vuln_advisor import advise_with_pack

result = advise_with_pack(findings, run_summary,
                          code_context=collect_repo_context(
                              ["path/to/relevant/file.py"]))
print(result["venice_pack"])   # paste into venice.ai
print(result["how_to_use"])
```

Suggested model for the paste-in step: `venice-uncensored-1-2`
(Venice Uncensored 1.2, verified live via Venice's public
GET /models on 2026-11-12; the older `venice-uncensored` id is no
longer listed).

## Limits

- The pack is capped at ~6,000 chars (~1,500 tokens) by default so
  it fits the free guest chat's ~2,000-token window with room for
  the answer. Bigger runs get truncated from the bottom up (lowest
  ranked candidates first to go).
- It is a manual step: copy, paste, read the analysis. One pack
  per guest prompt, ~10 prompts/day as a guest.
- Detection only: the pack instructs the model not to write
  executable exploit code or instructions to take funds.

## If live Venice calling is ever wanted

Set `VENICE_API_KEY` (from venice.ai/settings/api, needs a paid
plan) and add a thin client over the OpenAI-compatible
`POST https://api.venice.ai/api/v1/chat/completions` -- or settle
per-request in USDC over x402 with no key. Neither is built here
on purpose: this PR is keyless only.
