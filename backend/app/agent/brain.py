"""Uncensored AI brain: Horde-first, keyless, never GPT/Claude/Gemini.

AI Horde workers (koboldcpp serving Stheno, Heretic, Rocinante) do not
do native function calling, so tool use is emulated the ReAct way: the
model is told to emit fenced ```tool_call JSON blocks, which the chat
loop parses and executes. Fallback is Pollinations keyless text (an
availability fallback, not an aligned brain). If both fail, the brain
says so plainly instead of faking an answer.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse

from .http_client import client as http_client

HORDE_API = "https://stablehorde.net/api/v2"
HORDE_KEY = os.environ.get("HORDE_API_KEY", "").strip() or "0000000000"

UNCENSORED_MODELS = [
    "koboldcpp/L3-8B-Stheno-v3.2",
    "koboldcpp/Rocinante-X-12B-v1",
    "koboldcpp/gemma-4-31B-it-heretic",
    "koboldcpp/gemma-4-26B-A4B-it-heretic",
]

TOOL_CALL_RE = re.compile(r"```tool_call\s*(\{.*?\})\s*```", re.DOTALL)


def parse_tool_calls(text: str) -> list[dict]:
    """Parse fenced tool_call JSON blocks into [{name, args}]."""
    out = []
    for m in TOOL_CALL_RE.finditer(text or ""):
        try:
            obj = json.loads(m.group(1))
            name = obj.get("name") or obj.get("tool")
            if name:
                out.append({"name": name, "args": obj.get("args", {}) or {}})
        except Exception:
            continue
    return out


def strip_tool_calls(text: str) -> str:
    return TOOL_CALL_RE.sub("", text or "").strip()


def _horde_generate(prompt: str, timeout_s: int = 150) -> str | None:
    try:
        with http_client(30) as c:
            r = c.post(f"{HORDE_API}/generate/text/async",
                       json={"prompt": prompt, "params": {
                           "models": UNCENSORED_MODELS,
                           "max_context_length": 8192, "max_length": 800,
                           "temperature": 0.7}},
                       headers={"apikey": HORDE_KEY,
                                "User-Agent": "recon-anything-agent/1.0"})
            if r.status_code != 202:
                return None
            job_id = r.json().get("id")
            if not job_id:
                return None
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                s = c.get(f"{HORDE_API}/generate/text/status/{job_id}",
                          headers={"apikey": HORDE_KEY}, timeout=30)
                data = s.json()
                if data.get("done"):
                    gens = data.get("generations") or []
                    if gens:
                        return gens[0].get("text", "")
                    return ""
                time.sleep(5)
            return None
    except Exception:
        return None


def _pollinations_generate(prompt: str) -> str | None:
    try:
        url = "https://text.pollinations.ai/" + urllib.parse.quote(prompt[:3000])
        with http_client(60) as c:
            r = c.get(url, headers={"User-Agent": "recon-anything-agent/1.0"})
        if r.status_code == 200 and r.text.strip():
            return r.text
        return None
    except Exception:
        return None


def generate(prompt: str) -> tuple[str, str]:
    """Returns (text, source). Source is 'horde', 'pollinations', or 'degraded'."""
    text = _horde_generate(prompt)
    if text is not None and text.strip():
        return text, "horde"
    text = _pollinations_generate(prompt)
    if text is not None and text.strip():
        return text, "pollinations"
    return ("The AI brain is unreachable right now (Horde and the fallback "
            "both failed). No answer was faked; try again in a minute."), "degraded"
