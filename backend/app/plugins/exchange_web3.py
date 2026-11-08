"""Exchange-web detectors, block 3: WebSocket / realtime surface.

Ten detectors for realtime trading-stream mistakes visible in a
site's own client code: private channels without auth, stream
tokens in URLs, staging sockets in production, realtime-provider
key confusion. Detection only (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web3"

SPECS = [
    S("exch_ws_private_channel_no_auth", "Private Stream Channel Subscribed Without Auth in Client Code",
      "high",
      "Client code subscribes to a private/user account channel with no auth token in the subscription flow, suggesting the stream may accept private-channel subscriptions without proving account ownership.",
      "Require a per-session auth token on private channel subscribe, issued only after login, and reject unauthenticated private subscriptions server-side.",
      patterns=[r"(?:subscribe|channel|listen)\s*\(\s*['\"](?:private|user|account)[^'\"]*['\"]\s*\)",
                r"new\s+WebSocket\s*\(\s*[^)]*['\"]wss?://[^'\"]*(?:private|userstream|user-data)[^'\"]*['\"]"],
      negatives=[r"auth\s*[:=]|token\s*[:=]|Authorization|listenKey"],
      category="api"),
    S("exch_user_stream_endpoint_hardcoded", "User Data Stream Endpoint Hardcoded in Bundle",
      "medium",
      "The bundle hardcodes the user-data-stream endpoint (the account-events socket path), mapping the private streaming surface for anyone who reads the code.",
      "Build stream URLs from the authenticated session response instead of shipping the private endpoint map in static code.",
      patterns=[r"['\"]wss?://[^'\"]*(?:userDataStream|user-data-stream|/ws/user|stream\.private)[^'\"]*['\"]",
                r"(?:userStreamUrl|userDataStreamUrl|privateStreamUrl)\s*[:=]\s*['\"]wss?://[^'\"]+['\"]"],
      category="api"),
    S("exch_ws_debug_mode_enabled", "Trading Socket Debug Mode Enabled in Production Config",
      "medium",
      "The trading socket is configured with debug mode on in shipped config, which typically logs frames - including account and order data - to the browser console of every visitor.",
      "Ship production socket config with debug off and strip frame logging from production builds.",
      patterns=[r"(?:socket|ws|websocket|realtime)[A-Za-z_]*\s*[:=]\s*\{[^}]{0,200}?debug\s*:\s*true",
                r"(?:debug\s*:\s*true)[^}]{0,200}?(?:socket|websocket|wss?://)"],
      category="api"),
    S("exch_ws_token_in_url", "Stream Token Passed in WebSocket URL",
      "high",
      "Client code builds a WebSocket URL with a token in the query string. URL tokens are logged by proxies, CDNs and browser history, so stream credentials leak wherever URLs are recorded.",
      "Authenticate sockets with a header or a first-frame auth message, never a URL query token, and rotate any token that has appeared in URLs.",
      patterns=[r"wss?://[^'\"\s]+[?&](?:token|auth|api[_-]?key|listenKey)=[A-Za-z0-9+/=_~\-]{8,}",
                r"new\s+WebSocket\s*\(\s*`[^`]*\$\{[^}]*token[^}]*\}`"],
      category="api"),
    S("exch_staging_socket_in_prod", "Staging/Testnet WebSocket Endpoint Shipped in Production Bundle",
      "medium",
      "The production bundle carries a staging, dev or testnet WebSocket endpoint, showing environment config is mixed across builds - the same mix-up class that ships test credentials to production.",
      "Inject socket endpoints per environment at build time and fail the production build if a staging/testnet host is present.",
      patterns=[r"['\"]wss://[^'\"]*(?:staging|dev\.|testnet|stage\.)[^'\"]*['\"]",
                r"(?:staging|testnet)(?:Socket|Ws|Stream)(?:Url|Endpoint)\s*[:=]\s*['\"]wss://[^'\"]+['\"]"],
      category="api"),
    S("exch_pusher_secret_client", "Pusher Secret in Client Code",
      "high",
      "A Pusher secret (the server-side signing secret, not the public app key) is assigned in client code, so anyone can sign auth responses for private/presence channels.",
      "Rotate the Pusher secret, keep it only on the auth server, and ship only the public app key to the browser.",
      patterns=[r"(?:pusher|PUSHER)[A-Za-z_]*[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"new\s+Pusher\s*\([\s\S]{0,300}?secret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_ably_root_key_client", "Ably Root/API Key With Secret Part in Client Code",
      "high",
      "An Ably API key including its secret component (appId.keyId:keySecret form) is embedded in client code, granting full control of the realtime app to anyone who extracts it.",
      "Rotate the Ably key, issue a subscribe-only capability token server-side per session, and never ship a key with a secret part to a browser.",
      patterns=[r"(?:ably|ABLY)[A-Za-z_]*\s*[:=]\s*\{[^}]{0,200}?(?:key|apiKey)\s*[:=]\s*['\"][A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+:[A-Za-z0-9+/=_~\-]{10,}['\"]",
                r"new\s+Ably\.Realtime\s*\(\s*\{[^}]{0,200}?key\s*[:=]\s*['\"][A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+:[A-Za-z0-9+/=_~\-]{10,}['\"]"],
      category="leak"),
    S("exch_ws_token_persisted_storage", "Socket/Stream Token Persisted to Web Storage",
      "medium",
      "Client code persists a socket/stream token to localStorage, where it survives logout and is readable by any script running on the page.",
      "Keep stream tokens in memory, bind them to the session, and clear them on logout.",
      patterns=[r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:socket|stream|ws)[^'\"]*token[^'\"]*['\"]",
                r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*token[^'\"]*['\"][\s\S]{0,200}?(?:socket|wss?://)"],
      category="api"),
    S("exch_ws_admin_channel_reference", "Admin/Internal Stream Channel Referenced in Client Code",
      "medium",
      "Client code references an admin or internal realtime channel, disclosing that the channel exists and how it is named - the first step an attacker needs to test whether it is protected.",
      "Never name internal channels in client code; deliver channel names for the signed-in user's role only, from the server.",
      patterns=[r"(?:subscribe|channel|join)\s*\(\s*['\"](?:admin|internal|ops|treasury)[^'\"]*['\"]\s*\)",
                r"['\"](?:admin|internal)-channel[^'\"]*['\"][\s\S]{0,120}?(?:subscribe|channel)"],
      category="api"),
    S("exch_socketio_auth_disabled", "Socket.IO Configured With Auth Disabled",
      "medium",
      "The Socket.IO client/server config in shipped code disables auth, suggesting the realtime gateway may accept connections without proving identity.",
      "Enable Socket.IO auth with per-session tokens and reject unauthenticated connections at the handshake.",
      patterns=[r"(?:io|socket)\s*\([\s\S]{0,200}?auth\s*:\s*(?:false|null|undefined)",
                r"socketio[\s\S]{0,120}?auth(?:entication)?\s*[:=]\s*false"],
      negatives=[r"auth\s*:\s*\{"],
      category="api"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web3(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
