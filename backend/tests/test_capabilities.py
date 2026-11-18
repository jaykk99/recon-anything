"""Unit gate for the capability doctor (app/capabilities.py).

No network, no real binaries: the probes take injected `which` / `runner` /
client factories, so the drift classification is tested deterministically.
Checks that:
  * an absent binary is "missing" (a stage that degrades, not a failure),
  * a working binary is "ok" and its version is parsed,
  * a renamed flag / unparseable version output is "drift", not "missing",
  * an upstream that answers in the wrong SHAPE is "drift", while a 5xx or a
    timeout is "degraded",
  * the doctor summarises which features lost a dependency.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import capabilities as caps  # noqa: E402


class _CP:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _spec(name="slither"):
    return {"name": name, "args": ["--version"],
            "version_re": r"\d+\.\d+\.\d+", "used_by": ["audit_toolbox"]}


def test_missing_binary():
    out = caps.probe_tool(_spec(), which=lambda _n: None)
    assert out["status"] == "missing" and out["used_by"] == ["audit_toolbox"]


def test_ok_binary_parses_version():
    out = caps.probe_tool(
        _spec(), which=lambda _n: "/usr/bin/slither",
        runner=lambda *a, **k: _CP(0, "slither 0.10.4\n"))
    assert out["status"] == "ok" and out["version"] == "0.10.4"


def test_renamed_flag_is_drift_not_missing():
    out = caps.probe_tool(
        _spec(), which=lambda _n: "/usr/bin/slither",
        runner=lambda *a, **k: _CP(2, "", "Error: Unknown option: --version\n"))
    assert out["status"] == "drift", out
    assert "flag" in out["detail"].lower() or "unknown" in out["detail"].lower()


def test_version_shape_change_is_drift():
    out = caps.probe_tool(
        _spec(), which=lambda _n: "/usr/bin/slither",
        runner=lambda *a, **k: _CP(0, "slither (python module) ready\n"))
    assert out["status"] == "drift"


def test_probe_timeout_is_degraded():
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["slither"], timeout=1)
    out = caps.probe_tool(_spec(), which=lambda _n: "/x/slither",
                          runner=_boom)
    assert out["status"] == "degraded"


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def _client(resp=None, raises=None):
    class _C:
        def get(self, url, timeout=None):
            if raises:
                raise raises
            return resp

        def close(self):
            pass
    return lambda: _C()


_CRT = {"name": "crt.sh", "url": "https://crt.sh/x", "expect": "json-list",
        "used_by": ["subdomains"]}


def test_upstream_ok():
    out = caps.probe_upstream(_CRT, client_factory=_client(
        _Resp(200, json.dumps([{"name_value": "a.example.com"}]))))
    assert out["status"] == "ok" and out["http_status"] == 200


def test_upstream_schema_change_is_drift():
    out = caps.probe_upstream(_CRT, client_factory=_client(
        _Resp(200, "<html>maintenance</html>")))
    assert out["status"] == "drift" and "JSON" in out["detail"]


def test_upstream_retired_route_is_drift():
    out = caps.probe_upstream(_CRT, client_factory=_client(_Resp(404, "")))
    assert out["status"] == "drift"


def test_upstream_outage_is_degraded_not_drift():
    assert caps.probe_upstream(
        _CRT, client_factory=_client(_Resp(503, "")))["status"] == "degraded"
    assert caps.probe_upstream(
        _CRT, client_factory=_client(raises=RuntimeError("dns"))
    )["status"] == "degraded"


def test_doctor_summarises_degraded_features():
    def which(name):
        return "/usr/bin/slither" if name == "slither" else None

    def runner(cmd, **kw):
        if cmd[0].endswith("slither"):
            return _CP(2, "", "Unknown option: --version")
        return _CP(0, "tool 1.2.3")

    report = caps.doctor(network=True, client_factory=_client(
        _Resp(200, "<html>nope</html>")), which=which, runner=runner)
    assert report["network_probed"] is True
    assert report["counts"].get("missing", 0) >= 1
    assert report["counts"].get("drift", 0) >= 2
    assert "audit_toolbox" in report["degraded_features"]
    assert "slither" in report["degraded_features"]["audit_toolbox"]


def test_health_summary_is_local_only():
    summary = caps.health_summary()
    assert summary["tool_count"] == len(caps.CLI_TOOLS)
    assert set(summary["tools_present"]) | set(summary["tools_absent"]) == {
        spec["name"] for spec in caps.CLI_TOOLS}


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} capability tests passed")


if __name__ == "__main__":
    _run_all()
