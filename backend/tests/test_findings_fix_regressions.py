"""Regression tests for the 2026-11-15 findings-fix lane.

Pins the detector fixes that closed the systematic-misfire classes
in the ReconAnything findings backlog (candidates.jsonl, 747 rows):

- unchecked_math_user_input (66% of rows): the internal/private
  skip (fix-zero-verified), plus the findings-fix suppressions -
  try* checked wrappers, pure sqrt/log helpers, division/modulo/
  shift-only unchecked blocks, and call-wrapped parameters
  (`log10(value) + 1` in Strings.toString).
- uups_authorize_upgrade_missing (35 rows, all ERC1967 proxies):
  `requires*` modifiers count as gates (DFSM `requiresAdmin`),
  and the "missing" shape is gone - a deployed UUPS contract
  MUST override _authorizeUpgrade to compile, so a missing
  definition in scope only ever meant the wrong source (proxy
  shell / sibling bundle).
- bls_sig_aggregator_audit: bare "aggregate" no longer fires.
- zero_knowledge_nullifier_audit: bare "withdraw" no longer fires.
- eof_container_code_section_verifier: legacy bytecode no longer
  fires; only 0xEF00 bytes are EOF candidates.

OZ excerpts below are verbatim OpenZeppelin v4.9.6 / v5.0.0
(Math.sol, Strings.sol). Full-file corpus check (OZ Math v4.9 +
v5, Strings, ECDSA, WCRO, C1 implementation, GENI, ZEUM, HTEAX,
ZOOMER, SPARTA, ARB848E, REAL, JEUR, DFSM impl) is 0 findings
for both detectors; see the lane report.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins import deep_audit6 as d6  # noqa: E402
from app.plugins import deep_audit7 as d7  # noqa: E402
from app.plugins import deep_lowlevel as dll  # noqa: E402
from app.plugins import bls_sig_aggregator_audit as bls  # noqa: E402
from app.plugins import zero_knowledge_nullifier_audit as zk  # noqa: E402

UM_SPEC = next(s for s in d6.SPECS if s.id == "unchecked_math_user_input")
UUPS_SPEC = next(s for s in d7.SPECS
                 if s.id == "uups_authorize_upgrade_missing")
EOF_SPEC = next(s for s in dll.SPECS
                if s.id == "eof_container_code_section_verifier")


def um(src, name=""):
    return d6._analyze_unchecked_math(src, UM_SPEC, contract_name=name)


def uu(src, name=""):
    return d7._analyze_uups(src, UUPS_SPEC, contract_name=name)


# --- unchecked_math: C1 shape (internal, require-guarded) -----------

C1_SHAPE = """
contract BackedToken {
    mapping(address => uint256) private _shares;
    function _transferShares(address from, address to,
                             uint256 sharesAmount) internal virtual {
        require(from != address(0), "zero");
        require(to != address(0), "zero");
        uint256 currentSenderShares = _shares[from];
        require(currentSenderShares >= sharesAmount, "exceeds");
        unchecked {
            _shares[from] = currentSenderShares - (sharesAmount);
        }
        _shares[to] = _shares[to] + (sharesAmount);
    }
}
"""


def test_internal_transfer_shares_silent():
    assert um(C1_SHAPE, "BackedToken") == []


# --- unchecked_math: true positive preserved ------------------------

REAL_DRAIN = """
contract Vault {
    mapping(address => uint256) public balances;
    uint256 public total;
    function credit(uint256 amount) external {
        unchecked {
            balances[msg.sender] += amount;
            total += amount;
        }
    }
}
"""


def test_public_unchecked_add_on_param_still_fires():
    found = um(REAL_DRAIN, "Vault")
    assert len(found) >= 1
    assert found[0]["function"] == "credit"


# --- unchecked_math: verbatim OpenZeppelin excerpts ----------------

OZ_TRYMUL = """
library Math {
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }
}
"""

OZ_SQRT = """
library Math {
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 result = 1 << (log2(a) >> 1);
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }
}
"""

OZ_TOSTRING = """
library Strings {
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }
}
"""


def test_oz_trymul_silent():
    assert um(OZ_TRYMUL, "Math") == []


def test_oz_sqrt_silent():
    assert um(OZ_SQRT, "Math") == []


def test_oz_tostring_silent():
    assert um(OZ_TOSTRING, "Strings") == []


DIV_ONLY = """
library Math {
    function half(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 q = a / b;
            return q;
        }
    }
}
"""


def test_division_only_unchecked_silent():
    assert um(DIV_ONLY, "Math") == []


# --- unchecked_math: OZ burn shape (maxSupply sibling) ------------

OZ_BURN = """
contract E2EssenceToken {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    uint256 private _maxSupply;
    function burn(uint256 value) public virtual returns (bool) {
        address account = msg.sender;
        uint256 balance = _balances[account];
        if (balance < value) {
            revert ERC20InsufficientBalance(account, balance, value);
        }
        unchecked {
            _balances[account] = balance - value;
            _totalSupply -= value;
            _maxSupply -= value;
        }
        emit Transfer(account, address(0), value);
        return true;
    }
}
"""

UNGARDED_BURN = """
contract Bad {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    uint256 private _maxSupply;
    function burn(uint256 value) public virtual returns (bool) {
        unchecked {
            _balances[msg.sender] -= value;
            _totalSupply -= value;
            _maxSupply -= value;
        }
        return true;
    }
}
"""


def test_oz_burn_shape_silent():
    assert um(OZ_BURN, "E2EssenceToken") == []


def test_unguarded_burn_still_fires():
    # No balance check anywhere: the same decrements ARE a hazard.
    found = um(UNGARDED_BURN, "Bad")
    assert len(found) >= 1


# --- UUPS ------------------------------------------------------------

UUPS_BASE = """
abstract contract UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal virtual;
}
contract Token is UUPSUpgradeable {
    modifier requiresAdmin() { _; }
    function _authorizeUpgrade(address) internal override %s {}
}
"""


def test_uups_onlyowner_gated_silent():
    src = UUPS_BASE % "onlyOwner"
    assert uu(src, "Token") == []


def test_uups_requires_admin_gated_silent():
    # DFSM shape: custom requiresAdmin modifier, empty body.
    src = UUPS_BASE % "requiresAdmin"
    assert uu(src, "Token") == []


def test_uups_onlyrole_gated_silent():
    src = UUPS_BASE % "onlyRole(UPGRADER_ROLE)"
    assert uu(src, "Token") == []


def test_uups_empty_ungated_still_fires():
    src = UUPS_BASE % ""
    found = uu(src, "Token")
    assert len(found) >= 1
    assert found[0]["function"] == "_authorizeUpgrade"


PROXY_BUNDLE = """
abstract contract UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal virtual;
}
contract ZeumToken is ERC20, AccessControlEnumerable {
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}
"""


def test_uups_missing_shape_silent_on_non_upgradeable():
    # ZEUM shape: the deployed contract does not inherit UUPS at
    # all; the string only appears in bundled OZ text.
    assert uu(PROXY_BUNDLE, "ZeumToken") == []


# --- BLS --------------------------------------------------------------

def test_bls_aggregate_without_bls_silent():
    text = "function aggregateSignatures(bytes[] sigs) { return aggregate(sigs); }"
    assert bls.analyze(text, {}) == []


def test_bls_without_pop_still_fires():
    text = "BLS aggregate signature verification, blsAggregate(pubkeys, sigs)"
    found = bls.analyze(text, {})
    assert len(found) >= 1


# --- ZK nullifier ------------------------------------------------------

def test_zk_bare_withdraw_silent():
    text = "function withdraw(uint256 amount) external { payable(msg.sender).transfer(amount); }"
    assert zk.analyze(text, {}) == []


def test_zk_shielded_withdraw_without_nullifier_still_fires():
    text = ("shielded pool circuit withdraw: verify zk proof then "
            "transfer, no nullifier stored anywhere")
    found = zk.analyze(text, {})
    assert len(found) >= 1


# --- EOF ---------------------------------------------------------------

LEGACY_BYTECODE = ("0x60806040526004361061004e5760003560e01c80635c60da1b"
                   "146100535780638f2839701461007d578063f851a4401461"
                   "009d575b600080fd5b6100a0600480360381019080803590"
                   "602001909291905050506100e0565b005b6100a0600480")


def test_eof_legacy_bytecode_silent():
    found = dll._analyze_eof(LEGACY_BYTECODE, EOF_SPEC)
    assert found == []


def test_eof_bad_container_still_fires():
    found = dll._analyze_eof("0xef000101000000", EOF_SPEC)
    assert len(found) >= 1
