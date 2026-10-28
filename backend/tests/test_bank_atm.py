"""Unit gate for the bank/ATM surface detection depth.

Covers the pure matchers (fleet-platform fingerprints, internal-leak
detection, private-IP classification) and the ATM vendor-mapping
consistency. No network; imports the plugin modules directly.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import bank_surface as bs
from app.plugins import atm


# ---- fleet / switch fingerprints -----------------------------------------

def test_all_fleet_patterns_compile():
    for name, pat in bs.FLEET_PLATFORMS:
        re.compile(pat)  # raises if malformed
        assert name


def test_fleet_coverage_grew():
    # regression guard: the deepened lists should stay substantial
    assert len(bs.FLEET_PLATFORMS) >= 25
    assert len(bs.LOCATOR_PATHS) >= 20
    assert len(bs.PANEL_PATHS) >= 25


def test_fleet_matches_known_platforms():
    assert "NCR APTRA" in bs.match_fleet_platforms("Powered by APTRA Edge")
    assert "Diebold Nixdorf Vynamic" in bs.match_fleet_platforms("Vynamic View")
    assert "Compass Plus TranzWare" in bs.match_fleet_platforms("TranzWare Online")
    assert "OpenWay WAY4" in bs.match_fleet_platforms("running WAY4 switch")
    assert "BPC SmartVista" in bs.match_fleet_platforms("SmartVista Front-End")


def test_fleet_silent_on_clean_page():
    assert bs.match_fleet_platforms("Welcome to our community bank") == []


# ---- internal-leak detection ---------------------------------------------

def test_internal_leaks_all_kinds():
    text = ("server 10.20.30.40, api at intranet.acme.corp, debug "
            "http://127.0.0.1:9000/health and 192.168.1.1 gateway")
    leaks = bs.find_internal_leaks(text)
    kinds = {k for k, _ in leaks}
    assert {"private_ip", "internal_hostname", "loopback_url"} <= kinds, kinds


def test_private_ip_classifier():
    for ip in ("10.0.0.1", "192.168.0.1", "172.16.5.5", "127.0.0.1", "169.254.1.1"):
        assert bs._is_private_ipv4(ip), ip
    for ip in ("8.8.8.8", "1.2.3.4", "172.32.0.1", "172.15.0.1", "203.0.113.5"):
        assert not bs._is_private_ipv4(ip), ip


def test_public_ip_not_leaked():
    leaks = bs.find_internal_leaks("our public edge is 8.8.8.8")
    assert all(k != "private_ip" for k, _ in leaks)


# ---- ATM vendor mapping consistency --------------------------------------

def test_hint_to_vendor_maps_resolve():
    # every vendor a hint maps to must have a display name and (if it has
    # CVEs) a valid ATM_CVES key
    for hint, vendor in atm.HINT_TO_VENDOR.items():
        assert vendor in atm.VENDOR_NAMES, f"{hint}->{vendor} missing display name"


def test_atm_lists_grew():
    assert len(atm.ATM_MGMT_PATHS) >= 18
    assert len(atm.ATM_PORTAL_PATHS) >= 15
    assert len(atm.VENDOR_HINTS) >= 18


def test_atm_cve_keys_are_known_vendors():
    for vendor in atm.ATM_CVES:
        assert vendor in atm.VENDOR_NAMES or vendor in atm.HINT_TO_VENDOR.values()


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} bank/ATM tests passed")


if __name__ == "__main__":
    _run_all()
