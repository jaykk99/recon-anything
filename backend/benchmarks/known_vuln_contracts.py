"""Labeled ground-truth: canonical smart-contract vulnerability patterns
drawn from well-documented, already-exploited historical incidents.

Every case here is a minimal textbook reproduction of a bug class that has
a public post-mortem (Parity, DAO-style reentrancy drains, tx.origin
phishing, delegatecall hijacks). The funds in the real incidents are long
gone; these are teaching fixtures used to measure whether the deep analyzer
flags the drain path, NOT live targets. Each carries the finding ``kind``s
the analyzer should emit, so the benchmark can score precision/recall and
calibrate confidence tiers against known answers.

This is the ground-truth set referenced by tests/test_detection_benchmark.py.
"""
from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class VulnCase:
    name: str
    reference: str           # the public incident / SWC class
    drainable: bool          # did the real incident allow fund loss
    expect_any: Set[str] = field(default_factory=set)  # >=1 of these kinds
    source: str = ""


CASES: List[VulnCase] = [
    VulnCase(
        name="unprotected_selfdestruct",
        reference="Parity multisig 2017 (SWC-106) - anyone could kill it",
        drainable=True,
        expect_any={"selfdestruct", "ownership_takeover_path",
                    "privileged_function"},
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Wallet {
    address owner;
    function initWallet(address _owner) public { owner = _owner; }
    function kill() public { selfdestruct(payable(msg.sender)); }
    receive() external payable {}
}
""",
    ),
    VulnCase(
        name="unprotected_ownership_init",
        reference="Parity init (SWC-105) - unguarded owner set = takeover",
        drainable=True,
        expect_any={"ownership_takeover_path", "privileged_function"},
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Fund {
    address public owner;
    mapping(address=>uint) bal;
    function initialize(address _owner) public { owner = _owner; }
    function withdrawAll(address payable to) external {
        require(msg.sender == owner);
        to.transfer(address(this).balance);
    }
    receive() external payable {}
}
""",
    ),
    VulnCase(
        name="reentrancy_drain",
        reference="DAO-style reentrancy (SWC-107) - external call before "
                  "state update drains the balance",
        drainable=True,
        expect_any={"full_balance_withdraw", "unchecked_call",
                    "privileged_function"},
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Bank {
    mapping(address=>uint) public balances;
    function deposit() external payable { balances[msg.sender]+=msg.value; }
    function withdraw() external {
        uint amt = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
""",
    ),
    VulnCase(
        name="txorigin_auth",
        reference="tx.origin phishing (SWC-115) - auth bypass",
        drainable=True,
        expect_any={"tx_origin"},
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address owner;
    constructor(){ owner = msg.sender; }
    function transferTo(address payable to, uint amt) external {
        require(tx.origin == owner);
        to.transfer(amt);
    }
    receive() external payable {}
}
""",
    ),
    VulnCase(
        name="delegatecall_hijack",
        reference="Parity lib delegatecall (SWC-112) - arbitrary delegatecall",
        drainable=True,
        expect_any={"delegatecall"},
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Proxy {
    function forward(address impl, bytes calldata data) external {
        (bool ok,) = impl.delegatecall(data);
        require(ok);
    }
    receive() external payable {}
}
""",
    ),
    VulnCase(
        name="unprotected_withdraw",
        reference="Ungated full-balance withdraw (SWC-105) - anyone drains",
        drainable=True,
        expect_any={"full_balance_withdraw", "privileged_function"},
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Pool {
    function withdraw(address payable to) external {
        to.transfer(address(this).balance);
    }
    receive() external payable {}
}
""",
    ),
    # A clean, safe contract: the benchmark must NOT flag a drain here
    # (false-positive control).
    VulnCase(
        name="safe_gated_control",
        reference="control: properly access-gated, no drain path",
        drainable=False,
        expect_any=set(),
        source="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Safe {
    address immutable owner;
    constructor(){ owner = msg.sender; }
    modifier onlyOwner(){ require(msg.sender==owner,"no"); _; }
    function ping() external view returns(uint){ return block.number; }
}
""",
    ),
]
