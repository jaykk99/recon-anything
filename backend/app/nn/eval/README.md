# Eval sets for the NN point system

## own-holdout-145.jsonl

The frozen 145-row own holdout (seed 42): 124 positive / 21 negative.
Reconstructed byte-identically from
`candidates.jsonl.bak-20261114` (the continuous scanner's frozen
candidate file) by the Nov 14 NN continuation work. Labels are the
adjudicated verdicts: label 1 = UNVERIFIED candidate, label 0 =
FALSE_POSITIVE (18 rows) or TRIGGER_ONLY (3 rows). Chains: bsc 128,
ethereum 9, base 6, arbitrum 2.

Provenance: copied from
`~/workspace/wt/nn-scorer/nn-logs/own-holdout-145-bak.jsonl`
(continuation coordinator, Nov 14 2026). Real adjudicated findings
only. Never edit this file in place; a new adjudicated set gets a new
file, and the ledger keeps every round so drift is visible.
