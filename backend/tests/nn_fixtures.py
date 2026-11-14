"""Small labeled fixtures for the NN tests, shaped exactly like the
real rows (trimmed from recon-continuous/results/candidates.jsonl +
batches.jsonl, 2026-11-04 runs; value text truncated). The full
training test uses the real files when present and skips otherwise.
"""
# (finding dict, label) with 1 = worth-validating, 0 = likely-FP.
ROWS = [
    ({
        "plugin": "bridge_replay_unbound_digest",
        "key": "bridge_replay_unbound_digest",
        "severity": "high", "bounty_value": "high", "confidence": 80,
        "value": "HIGH: Bridge Replay Unbound Digest: function "
                 "'claimTokens' in contract 0x2cab3abfc1670d1a452df502e21"
                 "6a66883cdf079 on Arbitrum",
        "recipient_class": "CALLER-SUPPLIED", "chain": "arbitrum",
        "function": "claimTokens",
        "evidence": {
            "chain": "arbitrum", "contract_role": "standalone",
            "detector_outcome": "a", "function": "claimTokens",
            "bytecode_only": "false", "source_origin": "Sourcify v2",
            "report_class": "candidate", "recipient": "UNRESOLVED",
            "gate_analysis": "caller gate present, but it binds the "
                             "submitter, not the message - the replay stands",
            "risk": "high",
        },
    }, 1),
    ({
        "plugin": "contract_logic",
        "key": "access_control_flaw",
        "severity": "high", "bounty_value": "high", "confidence": 85,
        "value": "HIGH: ungated sensitive function: function 'mint' in "
                 "contract 0x086f405146ce90135750bbec9a063a8b20a8bffb on Base",
        "recipient_class": "CALLER-SUPPLIED", "chain": "base",
        "function": "mint",
        "evidence": {
            "chain": "base", "contract_role": "standalone",
            "function": "mint", "bytecode_only": "false",
            "source_origin": "Sourcify v2", "report_class": "candidate",
            "recipient": "CALLER-SUPPLIED", "risk": "high",
        },
    }, 0),
    ({
        "plugin": "unchecked_math_user_input",
        "key": "unchecked_math_user_input",
        "severity": "high", "bounty_value": "high", "confidence": 80,
        "value": "HIGH: unchecked arithmetic on user input in 'transfer'",
        "recipient_class": "CALLER-SUPPLIED", "chain": "bsc",
        "function": "transfer",
        "evidence": {
            "chain": "bsc", "contract_role": "implementation",
            "detector_outcome": "a", "function": "transfer",
            "bytecode_only": "false", "source_origin": "Sourcify v2",
            "report_class": "candidate", "recipient": "CALLER-SUPPLIED",
            "gate_analysis": "no caller gate on the function; unchecked "
                             "arithmetic on a function parameter",
            "risk": "high",
            "proxy_address": "0x0000000000000000000000000000000000000001",
            "implementation_address":
                "0x0000000000000000000000000000000000000002",
        },
    }, 1),
    ({
        "plugin": "recipient_mint_to_caller",
        "key": "recipient_mint_to_caller",
        "severity": "high", "bounty_value": "high", "confidence": 80,
        "value": "HIGH: mint sends tokens to the caller",
        "recipient_class": "CALLER", "chain": "bsc",
        "function": "mint",
        "evidence": {
            "chain": "bsc", "function": "mint",
            "source_origin": "Blockscout", "report_class": "candidate",
            "recipient": "CALLER", "risk": "high",
        },
    }, 0),
    ({
        "plugin": "uups_authorize_upgrade_missing",
        "key": "uups_authorize_upgrade_missing",
        "severity": "high", "bounty_value": "high", "confidence": 80,
        "value": "HIGH: _authorizeUpgrade has no access gate",
        "recipient_class": "CALLER-SUPPLIED", "chain": "bsc",
        "function": "_authorizeUpgrade",
        "evidence": {
            "chain": "bsc", "contract_role": "implementation",
            "detector_outcome": "a", "function": "_authorizeUpgrade",
            "bytecode_only": "false", "source_origin": "Sourcify v2",
            "report_class": "candidate", "recipient": "CALLER-SUPPLIED",
            "gate_analysis": "_authorizeUpgrade body is empty: no gate "
                             "statement of any kind",
            "risk": "high",
        },
    }, 1),
    ({
        "plugin": "recipient_bridge_release_unproven",
        "key": "recipient_bridge_release_unproven",
        "severity": "low", "bounty_value": "low", "confidence": 80,
        "value": "LOW: bridge release with unproven claim",
        "recipient_class": "CALLER-SUPPLIED", "chain": "bsc",
        "function": "release",
        "evidence": {
            "chain": "bsc", "function": "release",
            "source_origin": "Sourcify v2", "report_class": "trigger_only",
            "recipient": "CALLER-SUPPLIED", "risk": "low",
        },
    }, 0),
]
