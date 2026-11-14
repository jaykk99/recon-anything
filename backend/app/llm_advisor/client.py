"""LLM advisor client for ReconAnything. Stdlib only, zero new dependencies.

Calls the model directly first, in the order measured live on
2026-11-14 (meromero-26b first), then through Jay's Bro gateway
(http://127.0.0.1:8898, model ``bro``) as a final fallback — the gateway
runs its own chain with refusal retries and picks up any free-key
backends Jay enables later. No API keys, no cards, no paid sign-ups
anywhere in the keyless chain.

Gated free-key backends (Groq, OpenRouter, ...) are NOT called here: they
need a free key from Jay. If he sets one, the Bro gateway picks it up
itself (see the gateway README); this client needs no change.

Environment:
  RECON_BRO_URL       Bro gateway base URL (default http://127.0.0.1:8898)
  RECON_LLM_CHAIN     comma-separated backend labels overriding the default
                      direct-fallback order (labels in DEFAULT_CHAIN)
  RECON_LLM_TIMEOUT   seconds per backend attempt (default 180)
  RECON_LLM_OFF       set to 1 to disable all LLM calls (heuristic only)

The client never claims a finding is verified and never writes exploit
code. It only analyses findings and writes read-only detection code.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import time
import urllib.error
import urllib.request

BRO_URL = os.environ.get("RECON_BRO_URL", "http://127.0.0.1:8898")
TIMEOUT = float(os.environ.get("RECON_LLM_TIMEOUT", "180"))

# Direct-fallback backends, in measured order (live eval 2026-11-14).
# Each entry: (label, kind, target). kind "horde" = AI Horde text API,
# kind "openai" = OpenAI-compatible /v1/chat/completions, keyless.
# "local" is last resort only: Dolphin 3B runs ~0.23 t/s on this VM.
DEFAULT_CHAIN = [
    {"label": "meromero-26b", "kind": "horde",
     "model": "koboldcpp/G4-MeroMero-26B-A4B-it-uncensored-heretic"},
    {"label": "heretic-31b", "kind": "horde",
     "model": "koboldcpp/gemma-4-31B-it-heretic"},
    {"label": "rocinante-12b", "kind": "horde",
     "model": "koboldcpp/Rocinante-X-12B-v1"},
    {"label": "ovh-gpt-oss-120b", "kind": "openai",
     "base": "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
     "model": "gpt-oss-120b"},
    {"label": "kilo-free", "kind": "openai",
     "base": "https://api.kilo.ai/api/gateway", "model": "kilo-auto/free"},
    {"label": "llm7-gpt-oss-20b", "kind": "openai",
     "base": "https://api.llm7.io/v1", "model": "gpt-oss:20b"},
    {"label": "dolphin-3b", "kind": "local"},
]

LOCAL_URL = "http://127.0.0.1:8899/v1/chat/completions"
HORDE = "https://stablehorde.net/api/v2"
HORDE_KEY = "0000000000"  # anonymous, keyless

REFUSAL_RES = [
    re.compile(r"\bi can't help\b", re.I),
    re.compile(r"\bi cannot help\b", re.I),
    re.compile(r"\bi'm sorry,? i can't\b", re.I),
    re.compile(r"\bi'm unable to\b", re.I),
    re.compile(r"\bi (cannot|can't|won't) (assist|help|provide|comply)", re.I),
    re.compile(r"\bnot here for\b", re.I),
    re.compile(r"\bi'?m not going to (write|do|help)", re.I),
    re.compile(r"\bi won'?t write\b", re.I),
    re.compile(r"\bi don'?t (write|do that)\b", re.I),
]


def is_refusal(text: str) -> bool:
    """True if the text is a refusal/deflection (any = fail, retry next)."""
    t = (text or "").strip()
    if len(t) < 40:
        return False
    return any(rx.search(t) for rx in REFUSAL_RES)


def _strip_artifacts(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    for marker in ("<|im_end|>", "<|im_start|>", "<|end_of_turn|>",
                   "<start_of_turn>"):
        if marker in text:
            text = text.split(marker)[0]
    return text.strip()


def _post_json(url: str, body: dict, headers: dict | None = None,
               timeout: float = 120) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except http.client.IncompleteRead as e:
        # Some keyless providers close the connection mid-body; the
        # partial bytes are usually the complete JSON.
        return json.loads(e.partial)
    except Exception:
        raise


def _chatml(messages) -> str:
    out = ""
    for m in messages:
        out += f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n"
    return out + "<|im_start|>assistant\n"


def _call_horde(model: str, messages, max_tokens: int,
                temperature: float) -> str:
    body = {"prompt": _chatml(messages), "models": [model],
            "params": {"max_context_length": 8192, "max_length": max_tokens,
                       "temperature": temperature, "top_p": 0.9}}
    job = _post_json(HORDE + "/generate/text/async", body,
                     {"apikey": HORDE_KEY}, timeout=60)
    jid = job["id"]
    t0 = time.time()
    while time.time() - t0 < TIMEOUT:
        req = urllib.request.Request(HORDE + f"/generate/text/status/{jid}",
                                     headers={"apikey": HORDE_KEY})
        with urllib.request.urlopen(req, timeout=60) as r:
            st = json.load(r)
        if st.get("faulted"):
            raise RuntimeError(f"horde job faulted: {json.dumps(st)[:200]}")
        if st.get("done"):
            gens = st.get("generations") or []
            if not gens:
                raise RuntimeError("horde returned no generations")
            return _strip_artifacts(gens[0].get("text", ""))
        time.sleep(3)
    raise TimeoutError("horde job timed out")


def _call_openai(base: str, model: str, messages, max_tokens: int,
                 temperature: float, api_key: str | None = None) -> str:
    body = {"model": model, "messages": messages,
            "max_tokens": max_tokens, "temperature": temperature,
            "stream": False}
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    d = _post_json(base.rstrip("/") + "/chat/completions", body,
                   headers, timeout=120)
    choice = (d.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    text = msg.get("content") or ""
    return _strip_artifacts(text)


def _call_local(messages, max_tokens: int, temperature: float) -> str:
    slim = [m for m in messages if m.get("role") != "system"]
    d = _post_json(LOCAL_URL,
                   {"model": "dolphin-3b", "messages": slim,
                    "max_tokens": min(max_tokens, 100),
                    "temperature": temperature, "stream": False},
                   timeout=600)
    return (d["choices"][0]["message"]["content"] or "").strip()


def _chain() -> list:
    wanted = os.environ.get("RECON_LLM_CHAIN")
    if not wanted:
        return list(DEFAULT_CHAIN)
    by_label = {b["label"]: b for b in DEFAULT_CHAIN}
    out = [by_label[w.strip()] for w in wanted.split(",")
           if w.strip() in by_label]
    return out or list(DEFAULT_CHAIN)


def _call_direct(backend: dict, messages, max_tokens: int,
                 temperature: float) -> str:
    kind = backend["kind"]
    if kind == "horde":
        return _call_horde(backend["model"], messages, max_tokens,
                           temperature)
    if kind == "openai":
        return _call_openai(backend["base"], backend["model"], messages,
                            max_tokens, temperature)
    return _call_local(messages, max_tokens, temperature)


def chat(messages, max_tokens: int = 600, temperature: float = 0.2,
         timeout: float | None = None):
    """One chat completion. Returns (text, model_label, tried).

    Tries the direct backends first, in the order measured live
    (meromero-26b first: it was the smartest reliable model on
    2026-11-14), then the Bro gateway (the gateway runs its own chain
    with refusal retries, and picks up any free-key backends Jay
    enables later), then local Dolphin 3B last of all. Raises
    RuntimeError only if every backend fails or refuses. Never returns
    a refusal as an answer.
    """
    if os.environ.get("RECON_LLM_OFF") == "1":
        raise RuntimeError("LLM disabled by RECON_LLM_OFF=1")
    tried = []
    # 1. Direct backends, best first (local Dolphin held back: it runs
    # ~0.23 t/s on this VM, so it goes after the gateway, not before).
    for backend in _chain():
        if backend["kind"] == "local":
            continue
        t0 = time.time()
        try:
            text = _call_direct(backend, messages, max_tokens, temperature)
            tried.append({"backend": backend["label"],
                          "seconds": round(time.time() - t0, 1),
                          "chars": len(text or "")})
            if text and text.strip() and not is_refusal(text):
                return text, backend["label"], tried
        except Exception as e:  # noqa: BLE001 - one dead backend must not kill it
            tried.append({"backend": backend["label"],
                          "error": str(e)[:150],
                          "seconds": round(time.time() - t0, 1)})
    # 2. Bro gateway (its own chain + refusal retries).
    t0 = time.time()
    try:
        d = _post_json(BRO_URL.rstrip("/") + "/v1/chat/completions",
                       {"model": "bro", "messages": messages,
                        "max_tokens": max_tokens, "temperature": temperature},
                       timeout=timeout or TIMEOUT)
        text = (d.get("choices") or [{}])[0].get("message", {}).get("content", "")
        text = _strip_artifacts(text)
        tried.append({"backend": "bro-gateway",
                      "model": d.get("model", "bro"),
                      "seconds": round(time.time() - t0, 1),
                      "chars": len(text)})
        if text.strip() and not is_refusal(text):
            return text, d.get("model", "bro"), tried
    except Exception as e:  # noqa: BLE001 - gateway down: try local last
        tried.append({"backend": "bro-gateway", "error": str(e)[:150],
                      "seconds": round(time.time() - t0, 1)})
    # 3. Local Dolphin 3B, last resort only.
    for backend in _chain():
        if backend["kind"] != "local":
            continue
        t0 = time.time()
        try:
            text = _call_direct(backend, messages, max_tokens, temperature)
            tried.append({"backend": backend["label"],
                          "seconds": round(time.time() - t0, 1),
                          "chars": len(text or "")})
            if text and text.strip() and not is_refusal(text):
                return text, backend["label"], tried
        except Exception as e:  # noqa: BLE001
            tried.append({"backend": backend["label"],
                          "error": str(e)[:150],
                          "seconds": round(time.time() - t0, 1)})
    raise RuntimeError(f"all LLM backends failed or refused: {tried}")
