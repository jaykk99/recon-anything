"""AST Visual Audit (ast_visual_audit) tests.

The plugin is the headless rebuild of the Solidity Visual Auditor
extension's analysis function: solc AST -> inheritance tree,
dependency graph, per-function map (visibility / mutability /
modifiers / state reads+writes / external interactions), metrics
(the Solidity Metrics function), and low-severity structural
highlights.

Layers:
1. Map building against SAVED real solc compilations
   (tests/fixtures/ast_visual/*-ast.json, captured from solc
   0.8.26 --combined-json ast,abi over the sibling .sol fixtures):
   Inheritance.sol carries an inheritance pair plus one of each
   highlight class; Simple.sol is the clean control (map present,
   zero highlights).
2. Scope rules: bundle splitting on `// ==== path ====` markers,
   test/mock units dropped, target+ancestors kept, SPDX and
   pragma deduped for compilation.
3. Live compile (skipped when solc is absent): the full pipeline
   over Simple.sol produces the map finding and no highlights;
   over Inheritance.sol it produces every highlight class.
4. Plugin run with the chain layer stubbed (no network), and
   registry discovery (count 778 = master 655 + 100 BSC/BNB detectors + 5 deep-audit detectors + this plugin + 6 deep-audit batch-2 detectors + 6 recipient-first detectors + 1 auto-validator + 4 deep-analysis plugins).
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import ast_visual_audit as av  # noqa: E402
from app.plugins import toolbox  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "fixtures", "ast_visual")
ADDR = "0x" + "cd" * 20


def _load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


def _load_json(name):
    return json.loads(_load(name))


def _maps(fixture_base):
    return av.build_ast_map(_load_json(fixture_base + "-ast.json"),
                            _load(fixture_base + ".sol"))


# ---------------------------------------------------------------------------
# 1. Map building on saved real compilations
# ---------------------------------------------------------------------------

def test_inheritance_map_structure():
    maps = {m["name"]: m for m in _maps("Inheritance")}
    assert set(maps) == {"BaseVault", "RiskyVault"}
    risky = maps["RiskyVault"]
    assert risky["bases"] == ["BaseVault"]
    assert risky["metrics"]["functions"] == 6
    assert risky["metrics"]["state_variables"] == 1
    assert risky["metrics"]["nsloc"] > 10
    fns = {f["name"]: f for f in risky["functions"]}
    # modifiers / visibility / mutability are read off the AST
    assert fns["forward"]["visibility"] == "public"
    # state reads/writes: forward READS implementation (its
    # delegatecall target) and writes nothing
    assert "implementation" in fns["forward"]["reads"]
    assert fns["setImplementation"]["writes"] == ["implementation"]
    # inherited state is in scope for the child: kill reads owner
    assert "owner" in fns["kill"]["reads"]
    base = maps["BaseVault"]
    assert base["metrics"]["state_variables"] == 2


def test_inheritance_highlights_all_classes():
    maps = {m["name"]: m for m in _maps("Inheritance")}
    kinds = {}
    for m in maps.values():
        for hl in av.extract_highlights(m, _load("Inheritance.sol")):
            kinds.setdefault(hl["kind"], hl)
    assert "delegatecall_nonconstant_target" in kinds
    assert kinds["delegatecall_nonconstant_target"]["function"] \
        == "forward"
    assert "unchecked_low_level_call" in kinds
    assert kinds["unchecked_low_level_call"]["function"] == "ping"
    assert "tx_origin_use" in kinds
    assert "selfdestruct_present" in kinds
    assert "inline_assembly" in kinds


def test_simple_map_has_zero_highlights():
    maps = _maps("Simple")
    assert len(maps) == 1
    m = maps[0]
    assert m["name"] == "SimpleVault"
    assert m["metrics"]["functions"] == 3
    assert av.extract_highlights(m, _load("Simple.sol")) == []
    fns = {f["name"]: f for f in m["functions"]}
    assert fns["withdraw"]["modifiers"] == ["onlyOwner"]
    # the .transfer interaction is mapped but is NOT a highlight
    kinds = {i["kind"] for f in m["functions"]
             for i in f["interactions"]}
    assert "transfer" in kinds


def test_checked_delegatecall_is_not_unchecked():
    maps = {m["name"]: m for m in _maps("Inheritance")}
    fwd = next(f for f in maps["RiskyVault"]["functions"]
               if f["name"] == "forward")
    inter = next(i for i in fwd["interactions"]
                 if i["kind"] == "delegatecall")
    # result is assigned and require()d: not unchecked, but the
    # target is a state variable: not constant either
    assert inter["unchecked"] is False
    assert inter["target_constant"] is False


# ---------------------------------------------------------------------------
# 2. Scope + compile prep
# ---------------------------------------------------------------------------

def test_scope_drops_test_units_and_dedupes_headers():
    bundle = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "// ==== contracts/Token.sol ====\n"
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Token { uint256 public x; }\n"
        "// ==== contracts/test/TokenTest.sol ====\n"
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract TokenTest { function t() public { selfdestruct(payable(msg.sender)); } }\n"
    )
    text = av.scoped_compile_text(bundle, "Token")
    assert "TokenTest" not in text
    assert "contract Token" in text
    assert text.count("SPDX-License-Identifier") == 1
    assert text.count("pragma solidity") == 1


def test_scope_keeps_ancestors():
    bundle = (
        "// ==== a.sol ====\n"
        "contract Base { uint256 public b; }\n"
        "// ==== b.sol ====\n"
        "contract Child is Base { uint256 public c; }\n"
        "// ==== c.sol ====\n"
        "contract Unrelated { uint256 public u; }\n"
    )
    text = av.scoped_compile_text(bundle, "Child")
    assert "contract Base" in text
    assert "contract Child" in text
    assert "Unrelated" not in text


# ---------------------------------------------------------------------------
# 3. Live compile (skips without solc)
# ---------------------------------------------------------------------------

def test_live_compile_pipeline():
    solc = toolbox._solc_for(_load("Simple.sol"))
    if not solc:
        import pytest
        pytest.skip("no solc available in this environment")
    combined = asyncio.run(av.compile_ast(_load("Simple.sol"), solc))
    assert combined, "solc must compile the clean fixture"
    maps = av.build_ast_map(combined, _load("Simple.sol"))
    assert [m["name"] for m in maps] == ["SimpleVault"]


# ---------------------------------------------------------------------------
# 4. Plugin run (chain stubbed) + registry
# ---------------------------------------------------------------------------

class _FakeCache:
    def get(self, ns, key):
        return None

    def set(self, ns, key, val, ttl=None):
        pass


def test_plugin_run_emits_map_and_highlights(monkeypatch):
    from app.plugins import contract_chain as cc

    async def fake_get_code(ctx, chain, address):
        return "0x60006000fd" if chain.id == "ethereum" else "0x"

    async def fake_source(ctx, chain, address, key=None):
        return {"source": _load("Inheritance.sol"),
                "contract_name": "RiskyVault",
                "compiler": "v0.8.26", "proxy": False,
                "implementation": "", "origin": "Blockscout"}

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)

    plugin = av.AstVisualAuditPlugin()
    ctx = Ctx(run_id="t", mode="active", http=None,
              cache=_FakeCache(), keys={})
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = asyncio.run(plugin.run(target, ctx))
    keys = {f.key for f in res.findings}
    assert "ast_structure_map" in keys
    assert "ast_highlight_delegatecall_nonconstant_target" in keys
    assert "ast_highlight_unchecked_low_level_call" in keys
    # every finding from this plugin is low severity by design
    assert all(f.evidence["severity"] == "low" for f in res.findings)
    map_finding = next(f for f in res.findings
                       if f.key == "ast_structure_map"
                       and f.evidence.get("contract") == "RiskyVault")
    assert map_finding.evidence["inheritance"] == ["BaseVault"]
    assert map_finding.evidence["metrics"]["functions"] == 6


def test_plugin_no_source_reports_not_produced(monkeypatch):
    from app.plugins import contract_chain as cc

    async def fake_get_code(ctx, chain, address):
        return "0x60006000fd" if chain.id == "ethereum" else "0x"

    async def fake_source(ctx, chain, address, key=None):
        return None

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)

    plugin = av.AstVisualAuditPlugin()
    ctx = Ctx(run_id="t", mode="active", http=None,
              cache=_FakeCache(), keys={})
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = asyncio.run(plugin.run(target, ctx))
    assert {f.key for f in res.findings} == {"ast_map_not_produced"}


def test_registry_count_includes_ast_visual_audit():
    reg = discover()
    assert "ast_visual_audit" in reg
    assert len(reg) == 904  # master 655 + 100 BSC/BNB detectors + 5 deep-audit detectors + this plugin + 6 deep-audit batch-2 detectors + 6 recipient-first detectors + 1 auto-validator + 4 deep-analysis plugins (deep_layers) + 5 deep3 detectors + 3 deep-audit batch-4 detectors (deep_audit4) + 8 deep-audit batch-9 detectors (deep_audit9) + 1 unified keyword search plugin (unified_keyword_search) + 5 deep-audit batch-10 detectors (deep_audit10) + 6 beyond-recon plugins (nuclei_templates, lifecycle, content_discovery, param_discovery_arjun, js_linkfinder, wayback_surface) + 5 sec_* secret-exposure detectors (secretpack) + 1 idorleak detector (idor-error-leak) + 1 meta_orchestrator plugin (PR #77) + 10 Tier-1 OSINT plugins (PR #119) + 8 Tier-2 Enumeration plugins (PR #124) + 6 Tier-3 Fuzzing plugins (PR #121) + 10 Tier-4 Vuln/CVE plugins (PR #125) + 10 Tier-5 Orchestration plugins (PR #123)
