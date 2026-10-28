"""Never run a silent empty scan.

A plugin selection that matched no registered plugin (stale/mismatched
ids from the client, a renamed or removed plugin) used to enqueue zero
jobs, so the run finalized instantly with 0 findings and no explanation -
the "it's not running anything" symptom. _select_run_plugins guarantees a
website run always gets an applicable plugin set when the registry has
one, and returns a human note when it had to fall back.

Network-free: just exercises the pure selection helper over the real
registry.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.runner import _select_run_plugins  # noqa: E402


def test_default_website_set_is_nonempty_and_excludes_source_plugins():
    plugins, note = _select_run_plugins(None, None, "website")
    ids = {p.id for p in plugins}
    assert len(plugins) > 50
    # atm/bank are silent on website scans
    assert "atm" not in ids and "bank" not in ids
    assert note == ""


def test_bogus_selection_falls_back_to_default_with_note():
    plugins, note = _select_run_plugins(["no_such_plugin_xyz"], None,
                                        "website")
    assert len(plugins) > 50, "must not run an empty scan on a bad selection"
    assert "matched nothing" in note


def test_valid_selection_runs_exactly_those():
    plugins, note = _select_run_plugins(["dns", "tls"], None, "website")
    assert {p.id for p in plugins} == {"dns", "tls"}
    assert note == ""


def test_website_selection_of_only_source_plugin_falls_back():
    # atm is stripped on website scans, leaving the selection empty -> the
    # helper falls back rather than enqueueing nothing.
    plugins, note = _select_run_plugins(["atm"], None, "website")
    assert len(plugins) > 50 and note


def test_exclusions_are_respected_in_fallback():
    # A bogus selection falls back to the default set, but plan exclusions
    # must still be honored in that fallback (never grant an excluded id).
    plugins, _note = _select_run_plugins(["bogus"], ["dns", "tls"],
                                         "website")
    ids = {p.id for p in plugins}
    assert "dns" not in ids and "tls" not in ids
    assert len(plugins) > 50


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok - {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL - {fn.__name__}")
            traceback.print_exc()
    raise SystemExit(1 if failed else 0)
