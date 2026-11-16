import socket

# RFC 5737 TEST-NET-1 (guaranteed non-routable / closed on real networks)
CANARY_HOSTS = [
    ("192.0.2.1", 443),
    ("198.51.100.1", 80),
]


def can_port_scan(timeout: float = 2.0) -> tuple[bool, str]:
    """Return (True, 'ok') only if closed canary ports actually fail to connect."""
    for host, port in CANARY_HOSTS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return (
                    False,
                    f"Transparent TCP interception detected ({host}:{port} connected); "
                    "aborting port scan from this host.",
                )
        except OSError:
            continue
    return True, "ok"
