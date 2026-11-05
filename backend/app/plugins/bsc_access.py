"""BSC detectors: access control & signatures (10 plugins).

Dedupe map (outcome per ID, also in the PR body). The three
ECDSA detectors are ingredient-specific: each fixture isolates
ONE missing ingredient so they never double-fire -
- ecdsa_signature_malleability: raw ecrecover with no s-range
  check (fixture HAS nonce + chain id).
- ecdsa_signature_replay_cross_chain: signed payload with no
  chain/domain binding (fixture HAS nonce + s-range check).
- ecdsa_nonce_reuse_vulnerability: signed payload with no
  nonce at all (fixture HAS chain binding + s-range check).
- access_control_tx_origin_reliance: (c) shared routine
  restricted to the tx.origin comparison pattern.
- access_control_role_revocation_hole: (a) NEW - grant exists,
  no revocation path anywhere in the contract.
- access_control_unprotected_initializer: (c) shared
  initializer routine for NON-proxy contracts (delegatecall
  bundles are suppressed here and covered by the proxy
  module's implementation-specific detector).
- access_control_ownership_renunciation_trap: (a) NEW -
  renounce-to-zero while fund-moving owner functions remain.
- access_control_multi_sig_threshold_bypass: (a) NEW -
  multisig execution without a threshold comparison.
- access_control_hierarchical_privilege_leak: (a) NEW -
  grantRole authorized by membership in the very role being
  granted instead of its admin role.
- access_control_arbitrary_call_injection: (b) BSC variant -
  ungated executor calling a caller-supplied target (custom
  receiver analysis; delegatecall variant is in
  contract_logic's generic lane, this one covers plain CALL
  executors and requires the call receiver to be a parameter).
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "access"

SPECS = [
    S("access_control_tx_origin_reliance", FAMILY,
      severity="high", outcome="c",
      need=(r"tx\.origin",),
      need_any=(r"tx\.origin\s*(==|!=)", r"(==|!=)\s*tx\.origin",
                r"require\s*\([^)]*tx\.origin",
                r"if\s*\([^)]*tx\.origin"),
      detail="tx.origin authorization: the function "
             "authorizes on tx.origin, so any contract the "
             "privileged account is tricked into calling "
             "inherits its identity - the classic phishing "
             "primitive. Authorization must compare msg.sender "
             "(the immediate caller), never tx.origin."),
    S("access_control_role_revocation_hole", FAMILY,
      severity="medium", outcome="a", scope="contract",
      need_any=(r"grantRole|_grantRole|addMinter|addOperator|"
                r"grantAccess",),
      forbid=(r"revokeRole|_revokeRole|removeMinter|"
              r"removeOperator|renounceRole|revokeAccess",),
      detail="Role revocation hole: the contract can GRANT "
             "roles (grantRole / addMinter / addOperator "
             "surface exists) but has NO revocation path "
             "anywhere, so a compromised or rogue role holder "
             "can never be removed - incident response is "
             "impossible without redeploying."),
    S("ecdsa_signature_malleability", FAMILY, severity="medium",
      outcome="a", fn_re=r"claim|permit|withdraw|verify",
      need=(r"ecrecover\s*\(",),
      forbid=(r"ECDSA", r"_INVALID_SIG_S|MAX_SIG_S|"
              r"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
              r"s\s*>\s*0x7F|s\s*<=",),
      detail="ECDSA malleability: the signature is recovered "
             "with raw ecrecover and the s value is never range-"
             "checked, so for every valid signature (v, r, s) a "
             "second valid signature (v^1, r, -s) exists. Any "
             "logic keyed on the signature bytes (rather than "
             "the signer) can be replayed with the twin "
             "signature. OpenZeppelin ECDSA (which rejects "
             "high-s) does not flag."),
    S("ecdsa_signature_replay_cross_chain", FAMILY,
      severity="high", outcome="c",
      fn_re=r"claim|permit|withdraw|verify",
      need=(r"ecrecover\s*\(",),
      forbid=(r"chainid|chainId|CHAIN_ID|DOMAIN_SEPARATOR|"
              r"domainSeparator|EIP712|block\.chainid",),
      detail="Cross-chain signature replay: the signed payload "
             "is not bound to this chain (no chain id, no "
             "EIP-712 domain separator), so a signature gathered "
             "on one chain replays verbatim on every other "
             "chain where the contract is deployed - BNB Chain "
             "and its forks/testnets included."),
    S("ecdsa_nonce_reuse_vulnerability", FAMILY, severity="high",
      outcome="a", fn_re=r"claim|permit|withdraw|verify",
      need=(r"ecrecover\s*\(",),
      forbid=(r"nonce|usedSignatures|consumedHashes|"
              r"usedDigests|replayGuard",),
      detail="Signature nonce reuse: the signed payload carries "
             "no nonce and no used-signature registry exists, "
             "so one valid signature authorizes its action "
             "unlimited times - the signer signs once, the "
             "bearer replays forever."),
    S("access_control_unprotected_initializer", FAMILY,
      severity="high", outcome="c",
      fn_re=r"^initialize$|^init$|^setup$",
      contract_forbid=(r"delegatecall",),
      need_any=(r"\]\s*(\+|-)?=", r"owner\s*=", r"\w+\s*=\s*"
                r"msg\.sender"),
      forbid=(r"initializer", r"reinitializer"),
      gated_suppresses=True,
      detail="Unprotected initializer: a public initialize() "
             "sets owner/state with no initializer modifier and "
             "no gate, so the first stranger to call it (or "
             "anyone, if it can be re-called) owns the contract. "
             "This is the non-proxy form; proxy implementations "
             "are covered by the proxy module's detector."),
    S("access_control_ownership_renunciation_trap", FAMILY,
      severity="low", outcome="a", fn_re=r"renounceOwnership",
      contract_need=(r"onlyOwner",),
      contract_need_any=(r"rescue", r"sweep",
                         r"emergencyWithdraw", r"recoverTokens",
                         r"withdrawFees", r"ownerWithdraw"),
      need=(r"address\s*\(\s*0\s*\)",),
      detail="Ownership renunciation trap: renounceOwnership "
             "sets the owner to the zero address while OTHER "
             "onlyOwner functions (withdraw / rescue / config) "
             "remain live. After renunciation those functions "
             "are unreachable forever - any funds or config "
             "they guard are permanently locked, a trap for "
             "buyers who read 'renounced' as 'safe'."),
    S("access_control_multi_sig_threshold_bypass", FAMILY,
      severity="high", outcome="a", fn_re=r"execute",
      contract_need_any=(r"threshold\s*(=|;)",
                         r"requiredConfirmations",
                         r"owners\s*(\[|;)"),
      need_any=(r"\.call\s*\{", r"\.call\s*\(", r"executed\s*="),
      forbid=(r">=\s*threshold|confirmations\s*>=|"
              r"approvalCount\s*>=|count\s*>=\s*required|"
              r">=\s*required"),
      detail="Multisig threshold bypass: the multisig's "
             "execute path performs the call without ever "
             "comparing the approval count against the "
             "threshold, so a transaction confirmed by a single "
             "owner (or none) executes as if the full quorum "
             "had approved."),
    S("access_control_hierarchical_privilege_leak", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"grantRole|addRole|giveRole",
      need=(r"hasRole\s*\(\s*role\b",),
      forbid=(r"getRoleAdmin|DEFAULT_ADMIN|adminRole",),
      detail="Hierarchical privilege leak: grantRole is "
             "authorized by membership in the VERY role being "
             "granted (hasRole(role, msg.sender)) instead of "
             "that role's admin role, so any holder of a role "
             "can mint unlimited new holders of it - the role "
             "hierarchy leaks sideways and revocation can never "
             "keep up."),
    S("access_control_arbitrary_call_injection", FAMILY,
      severity="high", outcome="b", custom="arbitrary_call",
      fn_re=r"^exec$|^execCall$|^invoke|^forward|^runCall$",
      recipient=True,
      detail="Arbitrary call injection: an ungated function "
             "makes an external call to a CALLER-SUPPLIED "
             "target (receiver expression is a function "
             "parameter), so anyone can make this contract "
             "call anything - including token contracts, where "
             "the call arrives with this contract's identity "
             "and balances behind it."),
]

register_family(globals(), SPECS)
