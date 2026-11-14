# NN v3 multichain sweep record (fixed own-test holdout, 145 rows, seed 42)

Own test = the original 145-row holdout (seed 42) from Jay's
candidates, as it stands after the Nov 14 dedupe of the candidates
file (727 -> 723 lines): 144 rows (123 worth-validating / 21
likely-false-positive). See the results note for why it is 144,
not 145. External rows NEVER enter the test set: Jay's own rows
are split first (579 train / 144 test), then all external rows
join training only. v1 baseline (81-32-16-1, own-only, 60 ep):
acc 0.8897, base 0.8552, AUC 0.9781, cm tp=108 fp=0 fn=16 tn=21,
FP recall 1.000, WV recall 0.871. v2 best (255-64-32-1, 120 ep,
own-train + 1,922 external): acc 0.9103, base 0.8552, AUC 0.9697,
cm tp=114 fp=3 fn=10 tn=18, FP recall 0.857, WV recall 0.919.
v2 at 60 epochs (255-32-16-1): acc 0.9034, AUC 0.9712.

## v3 model

| | |
|---|---|
| Architecture | 398-64-32-1 (398 = 36 plugin blocks x 8 + 40 key + 1 bounty + 5 recipient + 26 chain + 11 family + 6 domain + 3 flags + 3 source + 2 bytecode + 4 role + 3 report + 2 proxy/impl + 2 function + 1 value + 1 evidence) |
| Top-K plugins/keys | 48 (35 distinct plugins and 39 distinct keys present in training rows, so 36 blocks incl. OTHER are live) |
| Epochs / hidden / lr / seed | 60 / 64,32 / 0.05 / 42 (history recorded every 10th epoch; weights identical for any history_every — see test) |
| Training rows | 2,711 = own-train 579 (494 pos / 85 neg) + external 2,132 (1,839 pos / 293 neg) |
| Label skew (train) | 86.1% worth-validating / 13.9% likely-FP (2,333 / 378) |
| Test rows | 144 fixed own-test (123 pos / 21 neg), majority baseline 0.8542 — v2's 145 minus one removed base positive row, see results note |

<!-- METRICS-PLACEHOLDER: fill from /tmp/nn-multichain-train.log after the run -->

## v3 results (official run, 2026-11-14 ~09:52 EST)

| Metric | v1 (81-32-16-1, own-only, 60 ep) | v2 best (255-64-32-1, 120 ep) | v3 (398-64-32-1, 60 ep) |
|---|---|---|---|
| Test acc | 0.8897 | 0.9103 | **0.9306** |
| Majority baseline | 0.8552 | 0.8552 | 0.8542 |
| ROC AUC | 0.9781 | 0.9697 | 0.9679 |
| WV precision / recall | — / 0.871 | — / 0.919 | 0.945 / **0.976** |
| FP precision / recall | — / 1.000 | — / 0.857 | 0.824 / **0.667** |
| Confusion (tp fp fn tn) | 108 0 16 21 | 114 3 10 18 | 120 7 3 14 |
| Test rows | 145 | 145 | 144 (see note) |
| Train acc / AUC | — | — | 0.989 / 0.999 |

Read, honestly: accuracy is up 2.0 pts vs v2, AUC is flat
(-0.002), and the accuracy gain is NOT a clean win — it comes
from calling more things worth-validating. Likely-FP recall
FELL 0.857 -> 0.667 (7 false positives where v2 had 3: 6 on BNB,
1 on Ethereum). The all-positive NVD CVE rows (210, no negative
set) plausibly push scores up; that skew is the prime suspect and
is stated in the viewer limits. No config hit 100% (overfit flag,
not a win). Train AUC 0.999 shows the net memorises training
rows; the test AUC 0.968 is the honest number.

Feature importance (grouped permutation, AUC drop on test):
bounty_value 0.148, plugin 0.130, proxy_impl 0.062,
contract_role 0.057, chain 0.003, value_len 0.001,
source_origin 0.000, chain_family 0.000, domain 0.000,
chain_flags 0.000. The new multichain features contribute
~nothing on the own-test — expected: the own-test is EVM
contract rows only, so chain/family/domain have nothing to
separate there. The expansion's value is coverage for non-EVM /
web / hardware rows, which have NO labeled holdout to measure
it on. That is a coverage claim, not a measured accuracy claim.

NOTE on the 144-row test: the candidates file changed DURING
this job. The findings-audit work deduped
~/workspace/recon-continuous/results/candidates.jsonl 727 -> 723
lines (2 VERIFIED_REAL rows removed — they were excluded from
training anyway — 3 UNVERIFIED removed, 1 row re-adjudicated
UNVERIFIED -> FALSE_POSITIVE). The split procedure is identical
(stratified, seed 42, 20%), so the holdout is v2's 145 minus the
one removed base positive row (chain composition: bnb 128, eth 9,
base 5, arb 2 — v2 had base 6). Metrics compare within one row's
worth of difference (0.7 pts). Re-running on the old 727-row file
would mean training on rows another job deliberately removed;
the current file is ground truth.

## Training rows per chain / domain (all training rows)

| Chain | Train n | pos | neg | Source of the rows |
|---|---|---|---|---|
| other | 2,021 | 1,730 | 291 | v2 external rows with no chain named in their source text + web/hardware CVE rows |
| bnb | 525 | 475 | 50 | own-train 513 (as bsc) + 12 re-attributed audit rows |
| ethereum | 35 | 14 | 21 | own-train 31 + 4 re-attributed audit rows |
| base | 19 | 10 | 9 | own-train 15 + 4 re-attributed audit rows |
| arbitrum | 16 | 13 | 3 | own-train 12 + 4 re-attributed audit rows |
| polygon | 8 | 5 | 3 | own-train 8 |
| bitcoin | 26 | 25 | 1 | 25 NVD CVE rows + 1 re-attributed row (Sherlock-invalid, label 0) |
| zcash | 15 | 15 | 0 | 15 NVD CVE rows (node/miner software) |
| usdt | 15 | 15 | 0 | 15 audit rows whose subject token is USDT |
| usdc | 9 | 9 | 0 | 9 audit rows whose subject token is USDC |
| solana | 6 | 6 | 0 | 6 NVD CVE rows (rBPF / validator) |
| monero | 5 | 5 | 0 | 5 NVD CVE rows (node / library) |
| cardano | 5 | 5 | 0 | 5 NVD CVE rows (Hydra / node) |
| dogecoin | 2 | 2 | 0 | 1 NVD CVE row (Dogecoin Core) + 1 re-attributed audit row |
| tron | 2 | 2 | 0 | 2 NVD CVE rows (TronLink Wallet only) |
| dai | 1 | 1 | 0 | 1 audit row whose subject token is DAI |
| polkadot | 1 | 1 | 0 | 1 NVD CVE row (Frontier / Substrate) |

Per-domain train rows: contract 2,501 / web_api 90 / hardware_firmware 60 /
node_infra 60. Stablecoin-flagged rows: 92 (25 token-chain + 67 host-chain/other).

## Per-chain test slices (fixed own 144)

Own-test chains are only the chains Jay's scanner actually scanned:
bnb, ethereum, base, arbitrum. All other chains have 0 test rows —
their slices report counts only, never metrics.

| Chain | n | pos/neg | Acc | AUC | Baseline | WV rec | FP rec | Confusion |
|---|---|---|---|---|---|---|---|---|
| bnb | 128 | 115/13 | 0.945 | 0.979 | 0.898 | 0.991 | 0.538 | tp114 fp6 fn1 tn7 |
| ethereum | 9 | 4/5 | 0.667 | 0.700 | 0.556 | 0.500 | 0.800 | tp2 fp1 fn2 tn4 |
| base | 5 | 2/3 | 1.000 | 1.000 | 0.600 | 1.000 | 1.000 | tp2 fp0 fn0 tn3 — n=5, do not over-read |
| arbitrum | 2 | 2/0 | counts only | — | — | — | — | too few to measure |

Ethereum is the worst slice (2 of 4 positives missed, AUC 0.700
on 9 rows) — small-n noise, but the only slice where the model
is near chance. BNB carries the test (128/144 rows) and the
regression: 6 of the 7 test false positives are BNB rows.

## Excluded chains — no real data, not faked

| Chain | Why excluded |
|---|---|
| Litecoin (LTC) | NVD returns 0 CVEs for "litecoin"; no audit row in ScaBench (351 H/M) or defihack (389) names Litecoin. No ReconAnything plugin output for LTC exists either (0 own rows). |
| Bitcoin Cash (BCH) | NVD returns 0 CVEs for "bitcoin cash"; no audit row names it. |
| Dash (DASH) | NVD "dash" hits are a WordPress plugin ("Sell BTC" calculator, stored XSS) — not the Dash chain. No audit row names Dash. |
| Toncoin (TON) | NVD returns 0 CVEs for "toncoin"; no audit row names it. |
| Sui (SUI) | No audit row in the fetched corpora names Sui; NVD not queried for "sui" (keyword collides with common words, no clean signal). Move-audit corpora exist on Cantina/Code4rena but were not in the fetched sets. |
| Aptos (APT) | NVD "aptos" hits are Aptos Wisal payroll software — not the Aptos chain. No audit row names Aptos. |
| XRP Ledger (XRP) | xrpl.js supply-chain CVE has no CVSS severity (dropped: no severity claimed); go-xrpl CVE is Low (dropped per the Low rule). No audit row names XRP. |
| Avalanche (AVAX) | No audit row in ScaBench/defihack names Avalanche; NVD not queried (no clean keyword set). Own scanner has 0 AVAX rows. |

Also excluded as a source (not a chain): ArmurAI/Solana_vulnerability_audit_dataset
(HF, 244 rows) — LLM-generated instruction text, findings are model-written
guesses, several entries say the flagged behaviour "might be a misunderstanding".
Not judge/audit-confirmed, so unusable as label-1 rows. Solana coverage is the
6 real NVD CVEs instead.

Privacy chains, stated honestly: Monero/Zcash have no on-chain
visibility in this data — their rows are node/library CVEs (what
really exists for them), not on-chain findings. The model learns
"privacy-chain node CVE" signal, nothing about private transactions.

## Datasets

- v2 external standard, unchanged: 1,922 rows = ScaBench 351 +
  xanoutas 450 + defihack 378 + Sherlock-invalid 293 +
  audit-findings 450. Re-attribution only: 51 rows stamped with a
  chain from their own source text (exactly one chain named, else
  "other"), 92 flagged is_stablecoin. No v2 row duplicated, no v2
  label changed.
- NVD CVE rows added: 210 = xss 60 + sqli 30 + firmware 60 +
  bitcoin 25 + zcash 15 + monero 5 + solana 6 + cardano 5 +
  polkadot 1 + dogecoin 1 + tron 2. All label 1 (published CVE,
  CVSS High/Medium/Critical). 141 CVE candidates dropped for Low /
  missing severity; 10 "tron" keyword hits dropped as junk matches
  (A-V Tronics, Tronclass LMS). Plugin mapping strict: xss/sqli
  only on exact class match, firmware-hardcoded-credential text
  only, CWE-502 -> deserialization_detect, else plugin None
  (OTHER bucket). Raw fetched sources kept at
  ~/workspace/nn-multichain-sources/ (scabench.json, defihack.json,
  nvd/*.json) so a rebuild does not need re-fetching.
- Own rows: 723 candidates (727 lines before the Nov 14 dedupe,
  2 VERIFIED_REAL removed — they were excluded from training
  anyway), chains bsc 641 / ethereum 40 / base 20 / arbitrum 14 /
  polygon 8. No SOL/BTC/web/hardware rows exist in Jay's own data.

## Notes

- 60 epochs, not 120: on 2026-11-14 the box ran 4 sibling training
  jobs at once (load ~18, this job's CPU share ~12-15%); 120 epochs
  measured ~2.5 min/epoch wall (~5 h). v2's own 60 -> 120 delta was
  one test row (0.9034 -> 0.9103), so 60 epochs is the honest
  time-boxed choice; the comparison below names both v2 numbers.
- mlp.py micro-optimisation: _forward now uses map(math.tanh, ...)
  and _deltas inlines 1.0 - a*a. Verified bit-identical weights vs
  the pre-change code (max diff 0.0 on a 398-64-32-1, 2-epoch run).
  A map()-based gradient accumulation was tried and REVERTED: it
  was 18% slower in CPU time (list-allocation churn), also
  bit-identical, but slower is slower.
- No config hit 100% (overfit flag, not a win) — see metrics above.
- No simulated data anywhere. Anvil fixtures are for tool
  self-tests only and are not in this training set.
