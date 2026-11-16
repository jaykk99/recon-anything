"""BSC detectors: governance & timelocks (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- timelock_delay_bypass: (a) NEW - queue/execute with no
  minimum-delay or eta enforcement.
- timelock_queue_transaction_collision: (a) NEW - queue hash
  omits eta/data/signature, so distinct transactions collide.
- governance_proposal_threshold_gaming: (a) NEW - propose()
  threshold read from current balance (the vote-weight site is
  the lending module's flash_loan_governance_takeover).
- governance_quorum_calculation_flaw: (a) NEW - quorum from
  current totalSupply instead of the proposal snapshot.
- governance_early_execution_race: (a) NEW - execute() with no
  proposal-state gate.
- governance_vote_double_delegation: (a) NEW - delegate()
  overwrites the delegatee without moving voting power off the
  old one.
- governance_cancel_privilege_abuse: (c) shared gate routine
  restricted to proposal cancellation.
- timelock_execution_gas_exhaustion: (a) NEW - unbounded batch
  execution loop of external calls inside a timelock.
- governance_state_staleness: (a) NEW - voting-window setters
  that rewrite the rules for already-live proposals.
- governance_signature_replay: (c) shared signature routine
  restricted to vote-by-signature (the access module's ECDSA
  detectors cover claim/permit sites; this one requires the
  BySig voting shape).
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "governance"

SPECS = [
    S("timelock_delay_bypass", FAMILY, severity="high",
      outcome="a", fn_re=r"queue|execute",
      need_any=(r"eta", r"queuedTransactions|queueTransaction"),
      forbid=(r"minDelay|delay\s*\)|eta\s*>=\s*block\.timestamp"
              r"|block\.timestamp\s*>=\s*[\w.]*eta|"
              r"getBlockTimestamp|block\.timestamp\s*\+\s*delay"),
      detail="Timelock delay bypass: queue/execute handles the "
             "eta without enforcing a minimum delay between "
             "queueing and execution (no minDelay comparison "
             "anywhere in the path), so a queued transaction "
             "can execute immediately - the timelock's whole "
             "purpose (a public waiting period) is void."),
    S("timelock_queue_transaction_collision", FAMILY,
      severity="medium", outcome="a", fn_re=r"queue",
      need=(r"keccak256\s*\(",),
      need_any=(r"abi\.encode", r"encodePacked"),
      forbid=(r"encode\w*\s*\([^)]*\beta\b",
              r"encode\w*\s*\([^)]*\bdata\b",
              r"encode\w*\s*\([^)]*\bsignature\b"),
      detail="Timelock queue collision: the queued-transaction "
             "hash is computed WITHOUT the eta, the call data, "
             "or the signature, so two genuinely different "
             "transactions (same target/value, different data "
             "or timing) hash to the same queue entry - one "
             "can be queued innocuously and executed as the "
             "other."),
    S("governance_proposal_threshold_gaming", FAMILY,
      severity="medium", outcome="a", fn_re=r"propose",
      need_any=(r"balanceOf\s*\(", r"getVotes\s*\("),
      forbid=(r"getPastVotes|getPriorVotes|block\.number\s*-",),
      detail="Proposal threshold gaming: propose() checks the "
             "proposer's CURRENT token balance against the "
             "proposal threshold, so the threshold can be met "
             "with tokens held for a single transaction "
             "(borrowed or flash-borrowed) instead of a real "
             "stake at a past block."),
    S("governance_quorum_calculation_flaw", FAMILY,
      severity="medium", outcome="a", include_view=True,
      fn_re=r"quorum|state|execute",
      need=(r"totalSupply\s*\(\s*\)",),
      forbid=(r"totalSupplyAt|getPastTotalSupply|snapshot",),
      contract_forbid=(r"getPastTotalSupply|totalSupplyAt",),
      detail="Quorum calculation flaw: quorum is computed from "
             "the CURRENT totalSupply at decision/execution "
             "time rather than the supply at the proposal's "
             "snapshot block, so minting or burning between "
             "voting and execution moves the goalposts - "
             "proposals can be made to pass (or fail) after "
             "the vote is over."),
    S("governance_early_execution_race", FAMILY, severity="high",
      outcome="a",
      fn_re=r"^execute$|^executeProposal$|^executeTransaction$",
      contract_need_any=(r"proposal|Proposal",),
      need_any=(r"\.call\s*\{", r"\.call\s*\(", r"executed\s*=",
                r"executed\s*\["),
      forbid=(r"state\s*\([^)]*\)\s*==|ProposalState\.",
              r"require\s*\([^)]*eta|queued\s*\["),
      detail="Early execution race: execute() performs the "
             "proposal's call without checking the proposal "
             "state (Succeeded/Queued) or its eta, so a "
             "proposal can be executed while voting is still "
             "open - or before it has passed at all."),
    S("governance_vote_double_delegation", FAMILY,
      severity="medium", outcome="a", fn_re=r"^delegate$|delegate",
      need=(r"delegates\s*\[\s*msg\.sender\s*\]\s*=",),
      need_any=(r"votes\s*\[|votingPower|_moveDelegates",),
      forbid=(r"_moveDelegates|moveVotingPower|oldDelegate|"
              r"currentDelegate|previousDelegate"),
      detail="Double delegation: delegate() overwrites the "
             "caller's delegatee and credits the new delegatee "
             "WITHOUT removing the voting power from the "
             "previous one (no move-delegates step), so the "
             "same tokens vote twice - once through each "
             "delegatee."),
    S("governance_cancel_privilege_abuse", FAMILY,
      severity="medium", outcome="c", fn_re=r"cancel",
      need_any=(r"canceled\s*=\s*true|cancelled\s*=\s*true",
                r"\.canceled\s*=|state\s*="),
      gated_suppresses=True,
      forbid=(r"proposer|guardian",),
      detail="Cancel privilege abuse: cancel() marks a "
             "proposal canceled with NO check that the caller "
             "is the proposer, a guardian, or anyone privileged "
             "- any stranger can cancel any live proposal at "
             "any time, a permanent governance DoS."),
    S("timelock_execution_gas_exhaustion", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"execute|batch",
      need=(r"for\s*\(",),
      need_any=(r"\.call\s*\{", r"\.call\s*\("),
      forbid=(r"gasleft|MAX_|length\s*<=|require\s*\([^)]*<=",),
      detail="Timelock execution gas exhaustion: batch "
             "execution loops over an unbounded array of queued "
             "transactions making an external call per item, "
             "with no length cap or gas accounting - past a "
             "certain batch size the execution can never fit "
             "in a block and the queued transactions are "
             "bricked."),
    S("governance_state_staleness", FAMILY, severity="medium",
      outcome="a",
      fn_re=r"setVoting|setDelay|setPeriod|setQuorum",
      need=(r"voting\w*\s*=|quorum\w*\s*=",),
      detail="Governance state staleness (retroactive rule "
             "change): a setter rewrites the voting delay / "
             "period / quorum parameters that LIVE proposals "
             "are being judged against, so proposals created "
             "under one ruleset are decided under another - "
             "the parameters are treated as immutable by "
             "voters but are silently mutable mid-flight."),
    S("governance_signature_replay", FAMILY, severity="high",
      outcome="c", fn_re=r"BySig",
      need=(r"ecrecover",),
      forbid=(r"nonce", r"chainid|chainId|DOMAIN_SEPARATOR|"
              r"deadline"),
      detail="Governance signature replay: vote-by-signature "
             "recovers the signer with ecrecover but the signed "
             "payload carries no nonce, no deadline and no "
             "chain/domain binding, so one signed vote can be "
             "replayed - on other proposals, other chains, or "
             "in later rounds - as often as the relayer likes."),
]

register_family(globals(), SPECS)
