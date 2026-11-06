"""Depth-2 guard-aware path tracing (2026-11-05).

Covers the guard inventory / path trace added to contract_logic,
the hand-rolled reentrancy lock, the entitlement-vs-gate and
bare-ecrecover-vs-gate distinctions in the shared gate read
(crypto_drain._is_gated, which the auto-validator reaches through
contract_logic._gated_deep), helper-split reentrancy, and the
scope-aware gate suppression in crypto_drain.
"""
from app.plugins import contract_logic as cl
from app.plugins import crypto_drain as cd
from app.plugins import auto_validator as av


CUSTOM_LOCK = """
contract CleanCustomLock {
    mapping(address => uint256) public balances;
    uint256 private _status;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawBalance() public {
        require(_status == 0, "locked");
        _status = 1;
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        _status = 0;
    }
}
"""

HELPER_AUTH = """
contract CleanHelperAuth {
    address public owner;
    constructor() { owner = msg.sender; }
    function _authorize() internal view {
        require(msg.sender == owner, "not owner");
    }
    function withdrawTo(address to, uint256 amount) public {
        _authorize();
        payable(to).transfer(amount);
    }
    receive() external payable {}
}
"""

HELPER_SPLIT = """
contract VulnReentrantSplit {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        _sendOut(amt);
        balances[msg.sender] = 0;
    }
    function _sendOut(uint256 amt) internal {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }
}
"""

HELPER_SPLIT_CEI = """
contract CleanSplitCei {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        _sendOut(amt);
    }
    function _sendOut(uint256 amt) internal {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }
}
"""

CLAIM_REPEAT = """
contract VulnClaim {
    mapping(address => uint256) public entitlement;
    function claim() public {
        uint256 amt = entitlement[msg.sender];
        require(amt > 0, "nothing to claim");
        payable(msg.sender).transfer(amt);
    }
    receive() external payable {}
}
"""

REGISTRY_GATE = """
contract RegistryGate {
    struct Supply { uint256 cap; uint256 total; }
    mapping(address => Supply) public bridges;
    uint256 public totalSupply;
    function mint(address to, uint256 amount) external {
        Supply storage b = bridges[msg.sender];
        require(b.cap > 0, "invalid caller");
        totalSupply += amount;
    }
}
"""

SIG_SELF = """
contract VulnSigClaim {
    function claimWithSig(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0), "bad sig");
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

SIG_STORED = """
contract SigStored {
    address public owner;
    function claimSigned(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "not owner");
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

SIG_PARAM = """
contract SigParam {
    function claimFor(address signer_, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = ecrecover(h, v, r, s);
        require(signer == signer_, "bad signer");
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""


def _fn(src, cname, fname):
    scope = cl._Scope(src, cname)
    fn = next(f for f in scope.functions if f["name"] == fname)
    return scope, fn


def _candidates(src, cname, kind=None):
    out = []
    for f in cl.analyze_logic_source(src, "", cname):
        if kind and f["kind"] != kind:
            continue
        if f["severity"] in ("high", "critical") and \
                f.get("report_class") != "trigger_only":
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Path trace + guard inventory
# ---------------------------------------------------------------------------

def test_path_trace_helper_split_order():
    scope, fn = _fn(HELPER_SPLIT, "VulnReentrantSplit", "withdraw")
    path = cl.path_trace(scope, fn)
    kinds = [s["kind"] for s in path]
    assert kinds[0] == "entry"
    assert "internal_call" in kinds
    call_step = next(s for s in path if s["kind"] == "internal_call")
    assert call_step["function"] == "_sendOut"
    vt = next(s for s in path if s["kind"] == "value_transfer")
    assert vt["function"] == "_sendOut"
    assert kinds.index("internal_call") < kinds.index("value_transfer")


def test_guard_inventory_helper_gate():
    scope, fn = _fn(HELPER_AUTH, "CleanHelperAuth", "withdrawTo")
    guards = cl.guard_inventory(scope, fn)
    kinds = {g["kind"] for g in guards}
    assert "helper_gate" in kinds
    assert "sender_comparison" in kinds
    hg = next(g for g in guards if g["kind"] == "helper_gate")
    assert "_authorize" in hg["evidence"]


def test_guard_inventory_custom_lock():
    scope, fn = _fn(CUSTOM_LOCK, "CleanCustomLock", "withdrawBalance")
    guards = cl.guard_inventory(scope, fn)
    locks = [g for g in guards if g["kind"] == "reentrancy_lock"]
    assert locks and "_status" in locks[0]["evidence"]


def test_guard_inventory_signature_stored_vs_bare():
    scope, fn = _fn(SIG_STORED, "SigStored", "claimSigned")
    kinds = {g["kind"] for g in cl.guard_inventory(scope, fn)}
    assert "signature_gate" in kinds
    scope, fn = _fn(SIG_SELF, "VulnSigClaim", "claimWithSig")
    kinds = {g["kind"] for g in cl.guard_inventory(scope, fn)}
    assert "signature_gate" not in kinds


def test_findings_carry_path_and_guards():
    hits = _candidates(HELPER_SPLIT, "VulnReentrantSplit",
                        kind="reentrancy")
    assert hits and hits[0]["function"] == "withdraw"
    assert hits[0]["path"] and isinstance(hits[0]["guards"], list)


# ---------------------------------------------------------------------------
# Hand-rolled reentrancy lock
# ---------------------------------------------------------------------------

def test_custom_lock_no_candidate():
    assert _candidates(CUSTOM_LOCK, "CleanCustomLock",
                       kind="reentrancy") == []
    lows = [f for f in cl.analyze_logic_source(
        CUSTOM_LOCK, "", "CleanCustomLock")
        if f["kind"] == "reentrancy"]
    for f in lows:  # if anything is emitted it names the lock, low
        assert f["severity"] == "low"
        assert "_status" in f["detail"]


# ---------------------------------------------------------------------------
# Entitlement is not a gate; membership / registry fields are
# ---------------------------------------------------------------------------

def test_entitlement_require_is_not_a_gate():
    scope, fn = _fn(CLAIM_REPEAT, "VulnClaim", "claim")
    assert cd._is_gated(fn["signature"], fn["text"]) is False
    assert cl._gated_deep(fn, scope) is False


def test_registry_struct_field_is_a_gate():
    scope, fn = _fn(REGISTRY_GATE, "RegistryGate", "mint")
    assert cd._is_gated(fn["signature"], fn["text"]) is True
    assert cl._gated_deep(fn, scope) is True


def test_bool_membership_is_a_gate():
    sig = "function mint(address to, uint256 amount) external"
    text = ("function mint(address to, uint256 amount) external {\n"
            "require(isMinter[msg.sender], \"not minter\");\n}")
    assert cd._is_gated(sig, text) is True
    text2 = ("function mint(address to, uint256 amount) external {\n"
             "require(hasRole(MINTER, msg.sender), \"no role\");\n}")
    assert cd._is_gated(sig, text2) is True


def test_inline_uint_entitlement_is_not_a_gate():
    sig = "function claim() public"
    text = ("function claim() public {\n"
            "require(entitlement[msg.sender] > 0, \"none\");\n}")
    assert cd._is_gated(sig, text) is False
    text2 = ("function withdraw(uint256 amount) public {\n"
             "require(balances[msg.sender] >= amount, \"insufficient\");\n}")
    assert cd._is_gated("function withdraw(uint256 amount) public",
                        text2) is False


# ---------------------------------------------------------------------------
# Bare ecrecover is not a gate; stored-signer comparison is
# ---------------------------------------------------------------------------

def test_bare_ecrecover_is_not_a_gate():
    scope, fn = _fn(SIG_SELF, "VulnSigClaim", "claimWithSig")
    assert cd._is_gated(fn["signature"], fn["text"]) is False
    assert cl._gated_deep(fn, scope) is False


def test_stored_signer_comparison_is_a_gate():
    scope, fn = _fn(SIG_STORED, "SigStored", "claimSigned")
    assert cd._is_gated(fn["signature"], fn["text"]) is True
    assert cl._gated_deep(fn, scope) is True


def test_param_signer_comparison_is_not_a_gate():
    scope, fn = _fn(SIG_PARAM, "SigParam", "claimFor")
    assert cd._is_gated(fn["signature"], fn["text"]) is False


def test_ecdsa_recover_stored_comparison_is_a_gate():
    sig = "function claimSigned(uint256 amount) public"
    text = ("function claimSigned(uint256 amount) public {\n"
            "address recovered = ECDSA.recover(h, v, r, s);\n"
            "require(recovered == owner, \"not owner\");\n}")
    assert cd._is_gated(sig, text) is True


# ---------------------------------------------------------------------------
# Helper-split reentrancy
# ---------------------------------------------------------------------------

def test_helper_split_reentrancy_fires_on_entry():
    hits = _candidates(HELPER_SPLIT, "VulnReentrantSplit",
                       kind="reentrancy")
    assert len(hits) == 1
    assert hits[0]["function"] == "withdraw"
    assert hits[0]["logic_kind"] == "cei_violation"
    fns = [s["function"] for s in hits[0]["path"]]
    assert "_sendOut" in fns


def test_helper_split_cei_correct_stays_silent():
    assert _candidates(HELPER_SPLIT_CEI, "CleanSplitCei",
                       kind="reentrancy") == []


# ---------------------------------------------------------------------------
# crypto_drain scope-aware gate suppression
# ---------------------------------------------------------------------------

def test_drain_helper_gate_suppressed():
    hits = cd.analyze_drain_source(HELPER_AUTH)
    assert [h for h in hits
            if h["function"] == "withdrawTo"] == []


def test_drain_ungated_still_fires():
    src = """
    contract VulnWithdrawParam {
        function withdrawTo(address to, uint256 amount) public {
            payable(to).transfer(amount);
        }
        receive() external payable {}
    }
    """
    hits = cd.analyze_drain_source(src)
    assert any(h["function"] == "withdrawTo" for h in hits)


# ---------------------------------------------------------------------------
# Validator gate read (the benchmark's BAD cases)
# ---------------------------------------------------------------------------

def _validate(src, cname, fn_name):
    cand = {"address": "0x00000000000000000000000000000000000000aa",
            "chain": "ethereum", "function": fn_name,
            "kind": "access_control_flaw", "source": src,
            "contract_name": cname,
            "probe": {"status": "success", "via": "test"},
            "balances": {"native_wei": 10 ** 18}}
    return av.validate_candidate(cand)


def test_validator_claim_repeat_verified_real():
    v = _validate(CLAIM_REPEAT, "VulnClaim", "claim")
    assert v["gated"] is False
    assert v["verdict"] == "VERIFIED_REAL"


def test_validator_sig_self_verified_real():
    v = _validate(SIG_SELF, "VulnSigClaim", "claimWithSig")
    assert v["gated"] is False
    assert v["verdict"] == "VERIFIED_REAL"
