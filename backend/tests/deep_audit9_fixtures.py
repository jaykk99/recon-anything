"""Fixtures for the deep-audit batch-9 detectors (system
architecture slices).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, gate analysis, and the honest recipient
classification for these classes - report_class
"trigger_only" with recipient "NONE" (no stranger value
destination exists in any of the eight classes), at the spec
severity; CLEAN[id] (the protected shape of the same class)
MUST stay silent under ALL eight detectors; every other
plugin's vulnerable fixture MUST stay silent under this one
(no cross-talk).

Fixture hygiene for cross-talk: only the state_change
fixtures define events (so detector 4 cannot fire elsewhere),
only the assembly fixtures contain assembly, only the
coinbase fixtures mention block.coinbase, and only the
block-number fixtures mention block.number.
"""

# ---------------------------------------------------------------------------
# 1. growable_array_loop_no_pagination
# ---------------------------------------------------------------------------

_GROW_LOOP_VULN = """
contract GrowLoopVuln {
    address[] public members;
    uint256 public totalWeight;

    function join() public {
        members.push(msg.sender);
    }

    function settleAll() public {
        for (uint256 i = 0; i < members.length; i++) {
            totalWeight += 1;
        }
    }
}
"""

_GROW_LOOP_CLEAN_PAGINATED = """
contract GrowLoopPaginatedClean {
    address[] public members;
    uint256 public totalWeight;

    function join() public {
        members.push(msg.sender);
    }

    function settleRange(uint256 start, uint256 end) public {
        for (uint256 i = start; i < end && i < members.length; i++) {
            totalWeight += 1;
        }
    }
}
"""

_GROW_LOOP_CLEAN_FIXED = """
contract FixedLoopClean {
    uint256[] public scores;
    uint256 public total;

    function tally() public {
        for (uint256 i = 0; i < scores.length; i++) {
            total += scores[i];
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 2. block_number_as_time
# ---------------------------------------------------------------------------

_BLOCK_TIME_VULN = """
contract BlockTimeVuln {
    uint256 public unlockTime;
    uint256 public lastBlock;

    function setUnlock() public {
        unlockTime = block.number * 12;
        lastBlock = block.number;
    }

    function isExpired() public view returns (bool) {
        return block.number > 1700000000;
    }
}
"""

_BLOCK_TIME_CLEAN = """
contract BlockHeightClean {
    uint256 public lastBlock;
    uint256 public unlockBlock;

    function mark() public {
        require(block.number > lastBlock + 10, "too early");
        unlockBlock = block.number + 100;
        lastBlock = block.number;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. hardcoded_zero_role_address
# ---------------------------------------------------------------------------

_ZERO_ROLE_VULN = """
contract ZeroRoleVuln {
    address public router;
    address public treasury;

    constructor() {
        router = address(0);
    }

    function setTreasury(address t) public {
        treasury = 0x0000000000000000000000000000000000000000;
    }
}
"""

_ZERO_ROLE_CLEAN = """
contract RoleClean {
    address public router;
    address public token;

    constructor(address _router, address _token) {
        require(_router != address(0), "zero router");
        router = _router;
        token = _token;
    }

    function setRouter(address r) public {
        require(r != address(0), "zero router");
        router = r;
    }

    function routerUnset() public view returns (bool) {
        return router == address(0);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. state_change_without_event
# ---------------------------------------------------------------------------

_NO_EVENT_VULN = """
contract NoEventVuln {
    uint256 public fee;
    uint256 public cap;
    uint256 public rate;
    uint256 public bonus;

    event ConfigUpdated(uint256 fee);

    function setFee(uint256 v) public {
        fee = v;
    }

    function setCap(uint256 v) public {
        cap = v;
    }

    function setRate(uint256 v) public {
        rate = v;
    }

    function setBonus(uint256 v) public {
        bonus = v;
    }
}
"""

_NO_EVENT_CLEAN_EMIT = """
contract EventEmitClean {
    uint256 public fee;

    event FeeUpdated(uint256 oldFee, uint256 newFee);

    function setFee(uint256 v) public {
        uint256 old = fee;
        fee = v;
        emit FeeUpdated(old, v);
    }
}
"""

_NO_EVENT_CLEAN_NO_EVENTS = """
contract NoEventsAtAllClean {
    uint256 public level;

    function setLevel(uint256 v) public {
        level = v;
    }
}
"""

# ---------------------------------------------------------------------------
# 5. private_sensitive_state_var
# ---------------------------------------------------------------------------

_PRIVATE_SENSITIVE_VULN = """
contract PrivateSensitiveVuln {
    string private apiKey;
    uint256 private mnemonicIndex;
    address public operator;

    constructor(address _operator) {
        operator = _operator;
    }
}
"""

_PRIVATE_SENSITIVE_CLEAN = """
contract PrivateClean {
    uint256 private _feeBps;
    string private label;
    string public apiEndpoint;

    function setFee(uint256 v) public {
        _feeBps = v;
    }
}
"""

# ---------------------------------------------------------------------------
# 6. assembly_fmp_literal_corruption
# ---------------------------------------------------------------------------

_FMP_VULN = """
contract FmpLiteralVuln {
    uint256 public marker;

    function corrupt() public {
        assembly {
            mstore(0x40, 0x20)
        }
        marker = 1;
    }
}
"""

_FMP_CLEAN = """
contract FmpComputedClean {
    function alloc(uint256 size) public pure returns (uint256 ptr) {
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, size))
            mstore(0x40, 0x80)
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 7. assembly_returndatacopy_unbounded
# ---------------------------------------------------------------------------

_RDCOPY_VULN = """
contract RdCopyVuln {
    uint256 public marker;

    function forward(address target, bytes memory data) public {
        assembly {
            let ok := call(gas(), target, 0, add(data, 0x20), mload(data), 0, 0)
            returndatacopy(0, 0, 0xFFFF)
        }
        marker = 1;
    }
}
"""

_RDCOPY_CLEAN = """
contract RdCopyGuardedClean {
    function forward(address target) public {
        assembly {
            let ok := call(gas(), target, 0, 0, 0, 0, 0)
            let size := returndatasize()
            returndatacopy(0, 0, size)
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 8. coinbase_decision_input
# ---------------------------------------------------------------------------

_COINBASE_VULN = """
contract CoinbaseDecisionVuln {
    address public lastMiner;
    uint256 public rounds;

    function pick() public {
        require(block.coinbase != address(0), "no miner");
        lastMiner = block.coinbase;
        rounds += 1;
    }
}
"""

_COINBASE_CLEAN = """
contract CoinbaseTipClean {
    uint256 public tips;

    function tipMiner() public payable {
        payable(block.coinbase).transfer(msg.value);
    }
}
"""

VULN = {
    "growable_array_loop_no_pagination": _GROW_LOOP_VULN,
    "block_number_as_time": _BLOCK_TIME_VULN,
    "hardcoded_zero_role_address": _ZERO_ROLE_VULN,
    "state_change_without_event": _NO_EVENT_VULN,
    "private_sensitive_state_var": _PRIVATE_SENSITIVE_VULN,
    "assembly_fmp_literal_corruption": _FMP_VULN,
    "assembly_returndatacopy_unbounded": _RDCOPY_VULN,
    "coinbase_decision_input": _COINBASE_VULN,
}

CLEAN = {
    "growable_array_loop_no_pagination": _GROW_LOOP_CLEAN_PAGINATED,
    "growable_array_loop_not_growable": _GROW_LOOP_CLEAN_FIXED,
    "block_number_as_time": _BLOCK_TIME_CLEAN,
    "hardcoded_zero_role_address": _ZERO_ROLE_CLEAN,
    "state_change_without_event": _NO_EVENT_CLEAN_EMIT,
    "state_change_without_event_no_events": _NO_EVENT_CLEAN_NO_EVENTS,
    "private_sensitive_state_var": _PRIVATE_SENSITIVE_CLEAN,
    "assembly_fmp_literal_corruption": _FMP_CLEAN,
    "assembly_returndatacopy_unbounded": _RDCOPY_CLEAN,
    "coinbase_decision_input": _COINBASE_CLEAN,
}
