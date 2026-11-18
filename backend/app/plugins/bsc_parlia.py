"""Parlia / BNB system-contract detectors (bsc100 family: parlia).

Source-verified against bnb-chain/bsc-genesis-contract (main
branch): BSCValidatorSet.sol, SlashIndicator.sol, StakeHub.sol,
plus the BEP-126/590/648/667/714 design (0.45s slot, 2s
InitialBackOffTime, block-denominated jail, BLS vote layer
decoupled from production).

The flaws here are design properties of the system contracts, not
single-line bugs, so the detectors are deliberately narrow: each
one keys on the exact code shape in the verified source and names
the live mainnet value it is checking. A firing detector means
"this code shape is present in the contract under test", with the
live-state values confirmed separately by the read-only
bnb_system_state plugin (live mainnet, 2026-11-17) and the
standalone live-probe script.

Ground truth corrections found while writing these (verified
first-hand in the source, not assumed from the analysis):
- MISDEMEANOR_THRESHOLD = 50, FELONY_THRESHOLD = 150,
  INIT_FELONY_SLASH_SCOPE = 28800 ("1 days(block number)").
- The shuffle seed is `block.number / _shuffleInterval`
  (_shuffleInterval = 200) in getMiningValidators, hashed with
  keccak256(abi.encodePacked(shuffleNumber, startIdx + i)).
- The slash amounts live in StakeHub.initialize(), not init():
  downtime 10 ether / 2 days, felony 200 ether / 30 days.
- _downtimeSlash returns NOTHING; failure is swallowed by a
  try/catch that only emits failedFelony.
- There is no checkMaintenance function; epoch recompute is
  updateValidatorSetV2 + the getMiningValidators shuffle.
- updateParam is onlyGov in all three contracts (no timelock in
  the contract itself).

NOTE on P-02 live state (2026-11-17, verified first-hand via
eth_call): mainnet governance has already re-denominated the
thresholds - misdemeanor 333, felony 1000 blocks, felonySlashScope
192000 blocks (= 24h at 0.45s), i.e. the same wall-clock values
the 3s-era constants encoded. The detectors still fire on the
code shape (block-counted thresholds with no wall-clock scaling);
the live-state reader reports the condition as NOT present live.

Dedupe map (outcome per ID):
- parlia_block_denominated_jail: (a) NEW - no existing detector
  looks at block-counted jail thresholds.
- parlia_stale_block_time_scope: (a) NEW - block-counted
  evidence window with a stale day comment.
- parlia_no_vote_participation_penalty: (a) NEW - slashing
  surface with no participation accounting anywhere.
- parlia_deterministic_mining_shuffle: (a) NEW - shuffle seed
  is block.number-derived.
- parlia_slash_asymmetry: (a) NEW - hard-coded 20x/15x slash
  asymmetry in initialize().
- parlia_malicious_vote_slash_toggle: (a) NEW - vote slash
  gated on a governable boolean.
- parlia_silent_downtime_slash_failure: (a) NEW - try/catch
  swallowing a failed downtime slash.
- parlia_candidate_churn_no_reliability_gate: (a) NEW -
  candidate rotation with no reliability gate.
- parlia_governable_consensus_params: (a) NEW - consensus
  params mutable via updateParam.
"""
from __future__ import annotations

from .bsc_common import S, register_family

FAMILY = "parlia"

SYS = r"contract\s+(BSCValidatorSet|SlashIndicator|StakeHub)\b"
SLASH_IND = r"contract\s+SlashIndicator\b"
VALIDATOR_SET = r"contract\s+BSCValidatorSet\b"
STAKE_HUB = r"contract\s+StakeHub\b"

SPECS = [
    # ------------------------------------------------------------------
    # P-02 — Block-denominated jail. slash() counts missed blocks
    # toward jail in bare blocks (50 / 150) with no wall-clock
    # scaling; at the 0.45s slot the felony wall is ~67s of missed
    # blocks, not the ~450s the 3s-era constants encoded.
    # ------------------------------------------------------------------
    S("parlia_block_denominated_jail", FAMILY, severity="high",
      outcome="a", fn_re=r"^slash$",
      contract_need=(SLASH_IND,),
      need=(r"misdemeanorThreshold", r"felonyThreshold"),
      need_absent=(r"block\.timestamp",),
      detail="ANALYSIS (system contract): SlashIndicator.slash "
             "counts missed blocks toward jail in bare blocks "
             "(misdemeanorThreshold 50, felonyThreshold 150) with "
             "no wall-clock scaling, so at the 0.45s slot the "
             "felony wall is ~67s of missed blocks, not the ~450s "
             "the 3s-era constants encoded. Live mainnet has "
             "re-denominated via governance (333/1000 blocks, see "
             "bnb_system_state); the code shape itself carries no "
             "scaling."),
    # ------------------------------------------------------------------
    # P-02 (scope) — the felony evidence window is a block count
    # (28800, commented '1 days(block number)' at the old 3s block
    # time) compared against block.number, with no wall-clock
    # scaling; at 0.45s it is ~3.6h.
    # ------------------------------------------------------------------
    S("parlia_stale_block_time_scope", FAMILY, severity="medium",
      outcome="a", scope="contract",
      contract_need=(SLASH_IND,),
      need=(r"submitFinalityViolationEvidence",
            r"felonySlashScope", r"28800"),
      need_any=(r"tarNum\s*\+\s*felonySlashScope\s*>\s*block\.number",),
      detail="ANALYSIS (system contract): the felony evidence "
             "window felonySlashScope is a block count (28800 in "
             "the verified source, commented as '1 day' at the "
             "old 3s block time) compared against block.number "
             "with no wall-clock scaling; at 0.45s it is ~3.6h, "
             "so evidence older than that is silently out of "
             "scope. Live mainnet re-denominated to 192000 blocks "
             "(= 24h)."),
    # ------------------------------------------------------------------
    # P-04 — No vote-participation penalty. The slashing surface
    # punishes downtime and malicious votes, but no code anywhere
    # scores vote participation; withholding votes is free.
    # ------------------------------------------------------------------
    S("parlia_no_vote_participation_penalty", FAMILY,
      severity="high", outcome="a", scope="contract",
      contract_need=(SLASH_IND,),
      need=(r"downtimeSlash",),
      need_any=(r"function\s+slash\s*\(",
                r"submitFinalityViolationEvidence"),
      need_absent=(r"participation", r"missedVote", r"nonVoting",
                   r"voteCount"),
      detail="ANALYSIS (system contract): the system contracts "
             "slash downtime (downtimeSlash) and malicious votes "
             "(submitFinalityViolationEvidence) but contain no "
             "participation accounting for BLS votes at all - no "
             "participation score, no reward penalty, no jail "
             "trigger for sustained non-voting. A validator can "
             "withhold finality votes indefinitely at zero cost; "
             "8 of 21 withholders freeze finality on a strict "
             "count basis (14/21 is exactly 2/3, so 7 leave "
             "exactly quorum), and fewer suffice stake-weighted "
             "given the top-7 concentration."),
    # ------------------------------------------------------------------
    # P-05 — Deterministic mining shuffle. getMiningValidators
    # draws the epoch set with seed block.number / _shuffleInterval
    # (200) - a pure function of public chain state, so the next
    # in-turn proposers are precomputable by anyone.
    # ------------------------------------------------------------------
    S("parlia_deterministic_mining_shuffle", FAMILY,
      severity="high", outcome="a", fn_re=r"^getMiningValidators$",
      include_view=True,
      contract_need=(VALIDATOR_SET,),
      need=(r"block\.number\s*/\s*_shuffleInterval",
            r"shuffle\s*\("),
      detail="ANALYSIS (system contract): the mining set is drawn "
             "with seed block.number / _shuffleInterval - a pure "
             "function of public chain state. The next in-turn "
             "proposers are precomputable by anyone; with an "
             "11/21 liveness threshold and a 2s backoff ladder, "
             "hitting 3 consecutive in-turn proposers buys "
             "~6-20s of near-idle chain."),
    # ------------------------------------------------------------------
    # P-08 — Slash asymmetry. StakeHub.initialize hard-codes
    # downtime 10 BNB / 2 days against felony 200 BNB / 30 days -
    # a 20x fine and 15x jail ratio.
    # ------------------------------------------------------------------
    S("parlia_slash_asymmetry", FAMILY, severity="high",
      outcome="a", fn_re=r"^initialize$",
      contract_need=(STAKE_HUB,),
      need=(r"downtimeSlashAmount\s*=\s*10 ether",
            r"felonySlashAmount\s*=\s*200 ether",
            r"downtimeJailTime\s*=\s*2 days",
            r"felonyJailTime\s*=\s*30 days"),
      detail="ANALYSIS (system contract): StakeHub.initialize "
             "hard-codes downtimeSlashAmount 10 BNB / "
             "downtimeJailTime 2 days against felonySlashAmount "
             "200 BNB / felonyJailTime 30 days - a 20x fine and "
             "15x jail ratio. The felony path is reachable from "
             "third-party evidence submission "
             "(submitDoubleSignEvidence / "
             "submitFinalityViolationEvidence), so an "
             "honest-but-partitioned validator can eat the felony "
             "penalty for correct behaviour under a split view, "
             "while a validator that simply stops voting is "
             "punished by nothing."),
    # ------------------------------------------------------------------
    # P-08 (toggle) — the malicious-vote slash is gated on the
    # governable boolean enableMaliciousVoteSlash; live mainnet
    # reads FALSE (2026-11-17), so vote misbehaviour is currently
    # unpunished even when evidence is submitted.
    # ------------------------------------------------------------------
    S("parlia_malicious_vote_slash_toggle", FAMILY,
      severity="medium", outcome="a", scope="contract",
      contract_need=(SLASH_IND,),
      need=(r"submitFinalityViolationEvidence",
            r"enableMaliciousVoteSlash",
            r"updateParam"),
      detail="ANALYSIS (system contract): the malicious-vote "
             "slash is gated on the governable boolean "
             "enableMaliciousVoteSlash (updatable via updateParam "
             "with no timelock in the contract). Live mainnet "
             "reads FALSE (verified 2026-11-17), so double-sign / "
             "malicious-vote evidence is currently a no-op even "
             "when submitted. The felony deterrent for vote "
             "misbehaviour is off by default and by toggle."),
    # ------------------------------------------------------------------
    # P-02 (silent failure) — _downtimeSlash has no return value
    # and its try/catch swallows a failed StakeHub downtime slash,
    # emitting only a failedFelony event. A failed slash is
    # indistinguishable from a successful one.
    # ------------------------------------------------------------------
    S("parlia_silent_downtime_slash_failure", FAMILY,
      severity="medium", outcome="a", fn_re=r"^_downtimeSlash$",
      contract_need=(SLASH_IND,),
      need=(r"try\s+IStakeHub\(STAKE_HUB_ADDR\)\.downtimeSlash",
            r"catch", r"emit failedFelony"),
      detail="ANALYSIS (system contract): _downtimeSlash calls "
             "StakeHub.downtimeSlash inside try/catch and a "
             "failure only emits a failedFelony event - no "
             "revert, no retry, and the function returns nothing, "
             "so callers cannot tell a failed slash from a "
             "successful one. A validator can accumulate missed "
             "blocks with no penalty applied and no observable "
             "signal beyond the event."),
    # ------------------------------------------------------------------
    # P-07 — Candidate churn with no reliability gate.
    # getMiningValidators re-draws maxNumOfWorkingCandidates (3)
    # of the 21 mining slots from the Candidate pool every 200
    # blocks via the shuffle, with no uptime/reliability gate on
    # candidates - the lowest-stake, weakest-infrastructure
    # members, refreshed continuously.
    # ------------------------------------------------------------------
    S("parlia_candidate_churn_no_reliability_gate", FAMILY,
      severity="medium", outcome="a", scope="contract",
      contract_need=(VALIDATOR_SET,),
      need=(r"maxNumOfWorkingCandidates",
            r"getMiningValidators", r"shuffle"),
      need_absent=(r"uptime", r"reliability", r"missRate"),
      detail="ANALYSIS (system contract): getMiningValidators "
             "re-draws maxNumOfWorkingCandidates (3) of the 21 "
             "mining slots from the Candidate pool every shuffle "
             "interval (200 blocks) with no reliability or uptime "
             "gate on candidates - they are by definition the "
             "lowest-stake, weakest-infrastructure members, and "
             "they get 14% of the set refreshed every ~90 seconds."),
    # ------------------------------------------------------------------
    # P-07 (governable) — Consensus params are governable.
    # updateParam lets governance change thresholds, jail times
    # and slash amounts; the design's invariants rest on
    # governance, not code (no timelock in the contract itself).
    # ------------------------------------------------------------------
    S("parlia_governable_consensus_params", FAMILY,
      severity="medium", outcome="a", scope="contract",
      contract_need=(SYS,),
      need=(r"updateParam",),
      need_any=(r"misdemeanorThreshold", r"felonyThreshold",
                r"downtimeSlashAmount", r"felonySlashAmount"),
      detail="ANALYSIS (system contract): consensus-critical "
             "parameters (misdemeanor/felony thresholds, jail "
             "times, slash amounts, malicious-vote toggle, "
             "cabinets) are all mutable via updateParam with no "
             "timelock in the contract itself. The chain's "
             "slashing invariants rest on governance discipline, "
             "not on fixed code; a single governance action can "
             "disable the vote slash (live: it is currently off) "
             "or re-denominate jail."),
]

register_family(globals(), SPECS)
