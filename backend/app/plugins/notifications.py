"""Scan notifications (Notify-style): alerts when a scan finishes.

Sends a summary to Discord / Slack / Telegram when a run completes.
Webhooks come from env vars (or the Keys store, same names):

  DISCORD_WEBHOOK, SLACK_WEBHOOK,
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID

No webhooks configured -> ok(0) with a note, never an error. Webhook
URLs are masked in every finding; they are never logged or echoed.

Phase 2 so it fires near the end of a run. It queries the run's own
findings table for real counts - nothing is estimated.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target

RESULTS_URL = "https://recon-anything.onrender.com"


class NotificationsPlugin(Plugin):
    id = "notifications"
    label = "Scan Notifications"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2
    description = ("Sends scan-complete alerts to Discord / Slack / Telegram "
                   "webhooks when configured.")
    timeout_s = 30

    # -- config ----------------------------------------------------------
    def _channels(self, ctx: Ctx) -> List[Tuple[str, Dict[str, str]]]:
        """(name, config) for every configured channel. Webhook values
        stay in this local list; findings only record channel names."""
        def val(name: str) -> str:
            return (ctx.keys.get(name) or os.environ.get(name) or "").strip()

        out: List[Tuple[str, Dict[str, str]]] = []
        discord = val("DISCORD_WEBHOOK")
        if discord.startswith("https://"):
            out.append(("discord", {"webhook": discord}))
        slack = val("SLACK_WEBHOOK")
        if slack.startswith("https://"):
            out.append(("slack", {"webhook": slack}))
        tg_token = val("TELEGRAM_BOT_TOKEN")
        tg_chat = val("TELEGRAM_CHAT_ID")
        if tg_token and tg_chat:
            out.append(("telegram", {"token": tg_token, "chat_id": tg_chat}))
        return out

    # -- run stats (real DB counts) --------------------------------------
    def _run_stats(self, ctx: Ctx) -> Dict[str, int]:
        stats = {"total": 0, "high": 0, "medium": 0, "low": 0}
        try:
            from ..models import Finding as FindingModel, get_session
            session = get_session()
            try:
                rows = (session.query(FindingModel)
                        .filter_by(run_id=ctx.run_id).all())
                for r in rows:
                    stats["total"] += 1
                    sev = ""
                    try:
                        ev = r.evidence or {}
                        if isinstance(ev, str):
                            ev = json.loads(ev)
                        sev = str(ev.get("severity", "")).lower()
                    except Exception:
                        pass
                    if sev == "high":
                        stats["high"] += 1
                    elif sev == "medium":
                        stats["medium"] += 1
                    else:
                        stats["low"] += 1
            finally:
                try:
                    session.close()
                except Exception:
                    pass
        except Exception:
            pass
        return stats

    # -- senders ---------------------------------------------------------
    def _post(self, url: str, payload: Dict, timeout: int = 10) -> bool:
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json",
                         "User-Agent": "recon-anything/notify"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def _send(self, name: str, cfg: Dict[str, str], text: str) -> bool:
        if name == "discord":
            return self._post(cfg["webhook"], {"content": text[:1900]})
        if name == "slack":
            return self._post(cfg["webhook"], {"text": text[:3000]})
        if name == "telegram":
            url = (f"https://api.telegram.org/bot{cfg['token']}"
                   f"/sendMessage")
            return self._post(url, {"chat_id": cfg["chat_id"],
                                    "text": text[:4000]})
        return False

    # -- run -------------------------------------------------------------
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        channels = self._channels(ctx)
        if not channels:
            return self._ok(
                [], reason=("no notification webhooks configured "
                            "(DISCORD_WEBHOOK / SLACK_WEBHOOK / "
                            "TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID)"))

        stats = self._run_stats(ctx)
        link = f"{RESULTS_URL}/runs/{ctx.run_id}"
        text = (
            f"ReconAnything scan finished\n"
            f"Target: {target.normalized}\n"
            f"Findings: {stats['total']} "
            f"(high {stats['high']}, medium {stats['medium']}, "
            f"low {stats['low']})\n"
            f"Results: {link}"
        )

        sent: List[str] = []
        failed: List[str] = []
        for name, cfg in channels:
            if self._send(name, cfg, text):
                sent.append(name)
            else:
                failed.append(name)

        findings = []
        if sent:
            findings.append(self._f(
                "web", "notification_sent",
                f"scan alert sent via: {', '.join(sent)}",
                source="notifications",
                confidence=100,
                evidence={
                    "severity": "low",
                    "channels": sent,  # names only, never URLs/tokens
                    "target": target.normalized,
                    "findings_total": stats["total"],
                    "remediation": "Informational. No action needed.",
                },
            ))
        reason = f"alerts sent: {', '.join(sent)}" if sent else "no alerts delivered"
        if failed:
            reason += f"; failed: {', '.join(failed)}"
        return self._ok(findings, reason=reason)
