"""Round-1 crypto.com false-positive gates (2026-11-19).

Round 1 of the crypto.com 20-target full-registry scan found 36
candidates: 34 FALSE_POSITIVE, 2 UNVERIFIED, 0 VERIFIED_REAL. Each
test below pins one plugin-side fix for a false-positive family,
in the real source shape, with a paired ungated control that must
STILL fire:

- evm_cfg_basic_block_reconstructor / symbolic_z3_storage_taint_
  tracer: DSAuth `auth` modifier on CronosCRC20 setOwner (gated
  on isAuthorized(msg.sender, msg.sig) in the modifier
  definition) and the ERC721A `approve` local declaration
  (`address owner = ownerOf(tokenId);` is not a state write).
- recipient_mint_to_caller: a public mint entry that delegates
  to a gated mint (CronosCRC20 `mint(uint)` -> `mint(address,
  uint)` public `auth`; child `mint` -> `super.mint` to a
  minter-gated parent).
- unchecked_math_user_input: internal `_mint` / `_mintERC2309` /
  `_safeMint` reachable only through gated entries (or through
  no entry at all).
- symbolic_z3_storage_taint_tracer: genuinely ungated
  `updateMaxSupply` (require-only, no identity gate) must keep
  firing - it is one of the 2 UNVERIFIED Round-1 rows, which no
  detector fix can close.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins.deep_lowlevel import (  # noqa: E402
    SPECS_BY_ID as LL_SPECS, analyze_deep_lowlevel_source)
from app.plugins.deep_audit6 import (  # noqa: E402
    SPECS_BY_ID as D6_SPECS, analyze_deep6_source)
from app.plugins.recipient_first import (  # noqa: E402
    analyze_recipient_source)


def _cfg(src, contract="Token"):
    return analyze_deep_lowlevel_source(
        src, LL_SPECS["evm_cfg_basic_block_reconstructor"], "", contract)


def _z3(src, contract="Token"):
    return analyze_deep_lowlevel_source(
        src, LL_SPECS["symbolic_z3_storage_taint_tracer"], "", contract)


def _mint_cands(src, contract="Token"):
    return [f for f in analyze_recipient_source(
        src, "recipient_mint_to_caller", "", contract)
        if f.get("report_class") == "candidate"]


def _unm(src, contract="Token"):
    return analyze_deep6_source(
        src, D6_SPECS["unchecked_math_user_input"], "", contract)


DSAUTH_SRC = """
contract DSAuth {
    address public owner;
    modifier auth {
        require(isAuthorized(msg.sender, msg.sig), "ds-auth-unauthorized");
        _;
    }
    function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
        if (src == owner) return true;
        return false;
    }
    function setOwner(address owner_) public auth {
        owner = owner_;
    }
}
contract CronosCRC20 is DSAuth {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function mint(uint wad) external {
        mint(msg.sender, wad);
    }
    function mint(address guy, uint wad) public auth {
        balanceOf[guy] += wad;
        totalSupply += wad;
    }
}
"""

UNGATED_OWNER_SRC = """
contract Bad {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function setOwner(address owner_) public {
        owner = owner_;
    }
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

APPROVE_SRC = """
contract ERC721A {
    mapping(uint256 => address) owners;
    mapping(uint256 => address) approvals;
    function ownerOf(uint256 tokenId) public view returns (address) {
        return owners[tokenId];
    }
    function isApprovedForAll(address o, address op) public view returns (bool) {
        return false;
    }
    function _msgSenderERC721A() internal view returns (address) {
        return msg.sender;
    }
    function approve(address to, uint256 tokenId) public virtual {
        address owner = ownerOf(tokenId);
        if (_msgSenderERC721A() != owner)
            if (!isApprovedForAll(owner, _msgSenderERC721A())) {
                revert("not approved");
            }
        approvals[tokenId] = to;
    }
}
"""

SUPER_GATED_SRC = """
contract ERC20 {
    mapping(address => bool) minters;
    mapping(address => uint256) balances;
    function mint(address to, uint256 amount) public {
        require(minters[msg.sender], "not minter");
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
}
contract Child is ERC20 {
    function mint(address to, uint256 amount) public override {
        super.mint(to, amount);
    }
}
"""

SUPER_UNGATED_SRC = """
contract ERC20 {
    mapping(address => uint256) balances;
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
}
contract Child is ERC20 {
    function mint(address to, uint256 amount) public override {
        super.mint(to, amount);
    }
}
"""

# Ungated override that never delegates: a gated same-arity
# overload in the parent must NOT silence it (the old
# signature-scanning shape did exactly that).
OVERLOAD_TRAP_SRC = """
contract Base {
    mapping(address => uint256) balances;
    mapping(address => bool) minters;
    function mint(address to, uint256 amount) public {
        require(minters[msg.sender], "not minter");
        balances[to] += amount;
    }
}
contract Child is Base {
    function mint(address to, uint256 amount) public override {
        balances[to] += amount;
    }
}
"""

NFT_GATED_SRC = """
contract BasicERC721A {
    mapping(address => uint256) public _packedAddressData;
    uint256 public _currentIndex;
    uint256 public maxSupply;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER");
    mapping(bytes32 => mapping(address => bool)) roles;
    function hasRole(bytes32 r, address a) public view returns (bool) {
        return roles[r][a];
    }
    function totalSupply() public view returns (uint256) {
        return _currentIndex;
    }
    function safeMint(address to) external {
        require(hasRole(MINTER_ROLE, msg.sender), "no permission");
        require(totalSupply() < maxSupply, "max supply");
        _mint(to, 1);
    }
    function batchMint(address to, uint256 quantity) external {
        require(hasRole(MINTER_ROLE, msg.sender), "no permission");
        _mint(to, quantity);
    }
    function _mint(address to, uint256 quantity) internal virtual {
        unchecked {
            _packedAddressData[to] += quantity * 3;
        }
        _currentIndex += quantity;
    }
    function _safeMint(address to, uint256 quantity) internal virtual {
        _mint(to, quantity);
        unchecked {
            uint256 index = _currentIndex - quantity;
            _currentIndex = index;
        }
    }
    function _mintERC2309(address to, uint256 quantity) internal virtual {
        unchecked {
            _packedAddressData[to] += quantity * 3;
        }
    }
}
"""

NFT_UNGATED_ENTRY_SRC = NFT_GATED_SRC.replace(
    'function safeMint(address to) external {\n'
    '        require(hasRole(MINTER_ROLE, msg.sender), "no permission");',
    'function safeMint(address to) external {')

UPDATE_MAX_SUPPLY_SRC = """
contract BasicERC721A {
    uint256 public maxSupply;
    function totalSupply() public view returns (uint256) {
        return 50000;
    }
    function updateMaxSupply(uint256 _newMaxSupply) public {
        require(_newMaxSupply >= totalSupply(), "invalid maxSupply");
        maxSupply = _newMaxSupply;
    }
}
"""

PUBLIC_GATED_UNCHECKED_SRC = """
contract Settle {
    uint256 public totalSettled;
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    function settle(uint256 amount, uint256 feeBps) public onlyOwner {
        uint256 payout;
        unchecked {
            uint256 fee = amount * feeBps / 10000;
            payout = amount - fee;
        }
        totalSettled += payout;
    }
}
"""


def test_cfg_dsauth_setOwner_silenced():
    assert _cfg(DSAUTH_SRC, "CronosCRC20") == []


def test_cfg_ungated_setOwner_still_fires():
    hits = _cfg(UNGATED_OWNER_SRC, "Bad")
    assert [h["function"] for h in hits] == ["setOwner"]


def test_z3_dsauth_setOwner_silenced():
    assert _z3(DSAUTH_SRC, "CronosCRC20") == []


def test_z3_ungated_setOwner_still_fires():
    hits = _z3(UNGATED_OWNER_SRC, "Bad")
    assert [h["function"] for h in hits] == ["setOwner"]


def test_z3_updateMaxSupply_still_fires():
    # Genuinely ungated public write (require-only bound): one of
    # the 2 UNVERIFIED Round-1 rows. No detector fix may close it.
    hits = _z3(UPDATE_MAX_SUPPLY_SRC, "BasicERC721A")
    assert [h["function"] for h in hits] == ["updateMaxSupply"]


def test_cfg_approve_local_declaration_silenced():
    assert _cfg(APPROVE_SRC, "ERC721A") == []


def test_mint_delegated_to_auth_mint_silenced():
    assert _mint_cands(DSAUTH_SRC, "CronosCRC20") == []


def test_mint_ungated_still_fires():
    assert len(_mint_cands(UNGATED_OWNER_SRC, "Bad")) >= 1


def test_mint_super_delegated_gated_silenced():
    assert _mint_cands(SUPER_GATED_SRC, "Child") == []


def test_mint_super_delegated_ungated_still_fires():
    assert len(_mint_cands(SUPER_UNGATED_SRC, "Child")) >= 1


def test_mint_gated_overload_elsewhere_does_not_silence():
    hits = _mint_cands(OVERLOAD_TRAP_SRC, "Child")
    assert [h["function"] for h in hits] == ["mint"]


def test_unchecked_gated_entry_mint_silenced():
    # _mint (gated entries only), _safeMint (internal callers
    # only) and _mintERC2309 (no callers at all) all stay silent.
    assert _unm(NFT_GATED_SRC, "BasicERC721A") == []


def test_unchecked_ungated_entry_mint_still_fires():
    hits = _unm(NFT_UNGATED_ENTRY_SRC, "BasicERC721A")
    assert [h["function"] for h in hits] == ["_mint"]


def test_unchecked_public_gated_function_still_fires():
    # A gate does not bound the arithmetic for the callers who
    # ARE allowed through, so a public gated function still fires.
    hits = _unm(PUBLIC_GATED_UNCHECKED_SRC, "Settle")
    assert [h["function"] for h in hits] == ["settle"]
