"""Fixtures for deep-audit batch-32 detectors.

Per detector:
- VULN: the vulnerable shape, MUST fire under its own detector as a
  candidate (tx.origin, selfdestruct, initializer, delegatecall) or
  without a recipient classification (blacklist, medium).
- VARIANT: the FIXED-recipient shape, MUST fire trigger-only at low
  severity, never a candidate (tx.origin paying a fixed treasury;
  selfdestruct to a fixed treasury).
- CLEAN: the protected shape, MUST stay silent under all five.
- EXTRA_CLEAN: further controls (timelocked selfdestruct, gated
  initializer, allowlisted / immutable / gated delegatecall, a
  blacklist setter with no enforcement on the transfer path, a
  tx.origin that is only logged, a contract with no selfdestruct).
- EXTRA_VULN: a second firing shape for the delegatecall detector
  (storage target with an ungated setter).
- BLACKLIST_UNGATED: a blacklist setter with NO access gate. It
  MUST stay silent under owner_blacklist_freeze (that detector
  requires the setter to be gated) and MUST fire under
  bep20_blacklist_authority_check (the ungated-admin class) -
  the two detectors own opposite shapes of the same feature.
"""
import textwrap

TX_ORIGIN_VULN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract TxOriginVault {
        address public owner;

        constructor() {
            owner = msg.sender;
        }

        function sweep(uint256 amount) public {
            require(tx.origin == owner, "not owner");
            payable(msg.sender).transfer(amount);
        }
    }
    """)

TX_ORIGIN_FIXED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract TxOriginTreasury {
        address public owner;
        address public treasury;

        constructor(address _treasury) {
            owner = msg.sender;
            treasury = _treasury;
        }

        function sweep(uint256 amount) public {
            require(tx.origin == owner, "not owner");
            payable(treasury).transfer(amount);
        }
    }
    """)

TX_ORIGIN_CLEAN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract TxOriginClean {
        address public owner;
        mapping(address => uint256) public balances;

        constructor() {
            owner = msg.sender;
        }

        function withdraw(uint256 amount) public {
            require(msg.sender == owner, "not owner");
            require(balances[msg.sender] >= amount, "insufficient");
            balances[msg.sender] -= amount;
            payable(msg.sender).transfer(amount);
        }
    }
    """)

TX_ORIGIN_LOGGED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract TxOriginLogged {
        address public owner;
        event Checked(address origin);

        constructor() {
            owner = msg.sender;
        }

        function withdraw(uint256 amount) public {
            require(msg.sender == owner, "not owner");
            emit Checked(tx.origin);
            payable(msg.sender).transfer(amount);
        }
    }
    """)

SELFDESTRUCT_VULN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract KillSwitch {
        address public owner;

        constructor() {
            owner = msg.sender;
        }

        function kill(address payable to) public {
            selfdestruct(to);
        }
    }
    """)

SELFDESTRUCT_FIXED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract KillTreasury {
        address public owner;
        address public treasury;

        constructor(address _treasury) {
            owner = msg.sender;
            treasury = _treasury;
        }

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        function kill() public onlyOwner {
            selfdestruct(payable(treasury));
        }
    }
    """)

SELFDESTRUCT_TIMELOCKED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract KillTimelocked {
        address public owner;
        address public treasury;
        uint256 public killTime;

        constructor(address _treasury) {
            owner = msg.sender;
            treasury = _treasury;
            killTime = block.timestamp + 30 days;
        }

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        function kill() public onlyOwner {
            require(block.timestamp > killTime, "locked");
            selfdestruct(payable(treasury));
        }
    }
    """)

SELFDESTRUCT_ABSENT = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract NoKillSwitch {
        address public owner;
        mapping(address => uint256) public balances;

        constructor() {
            owner = msg.sender;
        }

        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "insufficient");
            balances[msg.sender] -= amount;
            payable(msg.sender).transfer(amount);
        }
    }
    """)

INIT_VULN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract UpgradeableVault {
        address public owner;
        uint256 public totalDeposits;

        function initialize(address _owner) public {
            owner = _owner;
        }

        function deposit() public payable {
            totalDeposits += msg.value;
        }
    }
    """)

INIT_MODIFIER = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract UpgradeableVaultGuarded {
        address public owner;
        bool private _initialized;

        modifier initializer() {
            require(!_initialized, "already initialized");
            _;
            _initialized = true;
        }

        function initialize(address _owner) public initializer {
            owner = _owner;
        }
    }
    """)

INIT_GATED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract UpgradeableVaultOwned {
        address public owner;

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        function initialize(address _owner) public onlyOwner {
            owner = _owner;
        }
    }
    """)

DELEGATECALL_VULN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract Executor {
        function execute(address target, bytes calldata data)
            public
            returns (bool)
        {
            (bool ok, ) = target.delegatecall(data);
            return ok;
        }
    }
    """)

DELEGATECALL_SETTER = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract SetterExecutor {
        address public target;

        function setTarget(address _target) public {
            target = _target;
        }

        function execute(bytes calldata data)
            public
            returns (bool)
        {
            (bool ok, ) = target.delegatecall(data);
            return ok;
        }
    }
    """)

DELEGATECALL_IMMUTABLE = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract FixedExecutor {
        address public immutable implementation;

        constructor(address _impl) {
            implementation = _impl;
        }

        function execute(bytes calldata data)
            public
            returns (bool)
        {
            (bool ok, ) = implementation.delegatecall(data);
            return ok;
        }
    }
    """)

DELEGATECALL_ALLOWLIST = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract AllowlistedExecutor {
        mapping(address => bool) public allowedTargets;
        address public owner;

        constructor() {
            owner = msg.sender;
        }

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        function allow(address t) public onlyOwner {
            allowedTargets[t] = true;
        }

        function execute(address target, bytes calldata data)
            public
            returns (bool)
        {
            require(allowedTargets[target], "not allowed");
            (bool ok, ) = target.delegatecall(data);
            return ok;
        }
    }
    """)

DELEGATECALL_GATED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract OwnedExecutor {
        address public owner;

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        constructor() {
            owner = msg.sender;
        }

        function execute(address target, bytes calldata data)
            public
            onlyOwner
            returns (bool)
        {
            (bool ok, ) = target.delegatecall(data);
            return ok;
        }
    }
    """)

BLACKLIST_VULN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract FreezableToken {
        address public owner;
        mapping(address => uint256) public balances;
        mapping(address => bool) public blacklisted;

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        constructor() {
            owner = msg.sender;
        }

        function addToBlacklist(address account) public onlyOwner {
            blacklisted[account] = true;
        }

        function removeFromBlacklist(address account)
            public
            onlyOwner
        {
            blacklisted[account] = false;
        }

        function transfer(address to, uint256 amount)
            public
            returns (bool)
        {
            require(!blacklisted[msg.sender], "sender blacklisted");
            require(!blacklisted[to], "recipient blacklisted");
            require(balances[msg.sender] >= amount, "insufficient");
            balances[msg.sender] -= amount;
            balances[to] += amount;
            return true;
        }

        function transferFrom(address from, address to, uint256 amount)
            public
            returns (bool)
        {
            require(!blacklisted[from], "sender blacklisted");
            require(!blacklisted[to], "recipient blacklisted");
            require(balances[from] >= amount, "insufficient");
            balances[from] -= amount;
            balances[to] += amount;
            return true;
        }
    }
    """)

BLACKLIST_NO_ENFORCE = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract BlacklistNoEnforce {
        address public owner;
        mapping(address => bool) public blacklisted;

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        constructor() {
            owner = msg.sender;
        }

        function addToBlacklist(address account) public onlyOwner {
            blacklisted[account] = true;
        }

        function transfer(address to, uint256 amount)
            public
            returns (bool)
        {
            return true;
        }
    }
    """)

BLACKLIST_UNGATED = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract BlacklistUngated {
        mapping(address => bool) public blacklisted;

        function addToBlacklist(address account) public {
            blacklisted[account] = true;
        }

        function transfer(address to, uint256 amount)
            public
            returns (bool)
        {
            require(!blacklisted[msg.sender], "blacklisted");
            return true;
        }
    }
    """)

PLAIN_TOKEN = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract PlainToken {
        address public owner;
        mapping(address => uint256) public balances;

        constructor() {
            owner = msg.sender;
        }

        function transfer(address to, uint256 amount)
            public
            returns (bool)
        {
            require(balances[msg.sender] >= amount, "insufficient");
            balances[msg.sender] -= amount;
            balances[to] += amount;
            return true;
        }
    }
    """)

VULN = {
    "tx_origin_authorization": TX_ORIGIN_VULN,
    "selfdestruct_present": SELFDESTRUCT_VULN,
    "unprotected_initializer": INIT_VULN,
    "delegatecall_user_controlled_target": DELEGATECALL_VULN,
    "owner_blacklist_freeze": BLACKLIST_VULN,
}

VARIANT = {
    "tx_origin_authorization": TX_ORIGIN_FIXED,
    "selfdestruct_present": SELFDESTRUCT_FIXED,
}

CLEAN = {
    "tx_origin_authorization": TX_ORIGIN_CLEAN,
    "selfdestruct_present": SELFDESTRUCT_TIMELOCKED,
    "unprotected_initializer": INIT_MODIFIER,
    "delegatecall_user_controlled_target": DELEGATECALL_IMMUTABLE,
    "owner_blacklist_freeze": BLACKLIST_NO_ENFORCE,
}

EXTRA_CLEAN = {
    "tx_origin_logged": TX_ORIGIN_LOGGED,
    "selfdestruct_absent": SELFDESTRUCT_ABSENT,
    "init_gated": INIT_GATED,
    "delegatecall_allowlist": DELEGATECALL_ALLOWLIST,
    "delegatecall_gated": DELEGATECALL_GATED,
    "plain_token": PLAIN_TOKEN,
}

EXTRA_VULN = {
    "delegatecall_user_controlled_target": DELEGATECALL_SETTER,
}
