# Program Synthesis & Self-Modifying Tooling (Meta-Learning)

Sandboxed Synthesizer for ReconAnything: when an existing module fails
on an unknown protocol / obfuscated API / custom contract format, this
tool reverse-engineers the schema from observed examples, synthesizes a
new decoder as Python source, verifies it, executes it only inside an
isolated subprocess against held-out fixtures, and stages it for human
review.

**Safety is the point.** Synthesized tools NEVER auto-merge, NEVER
auto-deploy, NEVER touch the live scanner, and NEVER run outside the
sandbox. They are detection-only decoders / parsers: never exploit
code, never transaction builders. They never predict `VERIFIED_REAL`.
Triage only. crypto.com is never a target.

Pure Python stdlib. Zero new dependencies. Runs on CPU.

## Files

| Path | What it is |
| --- | --- |
| `backend/app/nn/synthesis.py` | The whole synthesizer: `ASTVerifier`, `SchemaInferer`, `Synthesizer`, `SandboxRunner`, `SynthesisPipeline`, `stage_for_review` |
| `backend/app/nn/__init__.py` | Package exports |
| `backend/app/nn/evaluate_synthesis.py` | Honest evaluation runner (`python -m app.nn.evaluate_synthesis`) |
| `backend/app/nn/synthesized/` | Staging area for synthesized tools (NOT a plugin package) |
| `backend/app/nn/synthesized/README.md` | The review gate, in the staging dir itself |
| `backend/tests/test_nn_synthesis.py` | 45 tests (verifier, inference, held-out synthesis, sandbox, pipeline) |
| `backend/docs/nn-synthesis.md` | This file |

## Pipeline

1. **Infer** (`SchemaInferer.infer`): reverse-engineers the schema
   from observed examples — field types, lengths, selectors.
   - Hex: 32-byte ABI words (address / uint256 / bool / dynamic bytes
     via offset + length), 4-byte selector prefix (real calldata),
     EIP-1167 minimal proxy, EIP-1967 slots, Uniswap V3 swap path
     (token + fee uint24 + token, packed).
   - JSON: event logs (`topics` + `data`, the `eth_getLogs` result
     object), envelope responses (a `result` / `data` / `payload` key
     whose subtree holds recognizable values, or 2+ canonical fields),
     positional rows.
   - Values are classified by shape: `0x` + 40 hex = address, `0x` +
     64 hex starting with 12 zero bytes = address-in-a-word, other
     64-hex = hash, other `0x`-hex = integer, bool, int.
   - Anything it cannot pin down returns kind `unknown` with low
     confidence. The synthesizer refuses to guess: confidence below
     0.5 raises `SynthesisError` ("cannot crack format") and the
     pipeline reports `failed`. Loud failure, never silent.
2. **Synthesize** (`Synthesizer.synthesize`): template-based,
   deterministic code generation. The generator only fills in field
   layouts the inferrer actually observed. No LLM, no guessing.
   Output is a single `decode(payload)` function plus a `SCHEMA`
   literal.
3. **Verify** (`ASTVerifier.verify`): strict AST allowlist (below).
   The generated source must pass with `require_decode=True`. A
   template failing its own gate is a bug, reported loudly.
4. **Sandbox** (`SandboxRunner.run`): the source is re-verified, then
   executed ONLY in an isolated child process against held-out
   fixtures (unseen values, same real format). Fixtures must all pass.
5. **Stage** (`stage_for_review`): only on a full sandbox pass, the
   tool is written into `backend/app/nn/synthesized/` — the branch's
   staging tree — for HUMAN review. Never into `backend/app/plugins/`.

## The AST allowlist

Allowed imports (only): `re`, `json`, `math`, `struct`, `binascii`,
`hashlib`, `base64`, `collections`, `itertools`, `string`.

Banned, always: `os`, `sys`, `subprocess`, `socket`, `pathlib`,
`shutil`, `requests`, `urllib`, `http`, `pty`, `signal`, `threading`,
`multiprocessing`, `ctypes`, `inspect`, `importlib`, `pkgutil`,
`code`, `codeop`, `runpy`, `builtins`, `socketserver`, `ftplib`,
`smtplib`, `webbrowser`, `atexit` — as names, attributes, or imports.
Also banned: `eval`, `exec`, `open`, `__import__`, `compile` (as a
bare builtin call), `input`, `breakpoint`, `getattr`, `setattr`,
`delattr`, `hasattr`, `vars`, `dir`, `globals`, `locals`,
`memoryview`, `exit`, `quit`, `help`. Any dunder attribute access.
Any private (`_`-prefixed) attribute access. Classes, async,
decorators, `global`/`nonlocal`, `del`, `yield`, star imports.
Source over 64 KB or 5,000 AST nodes is rejected. The one deliberate
exception: the attribute `compile` is allowed so generated code may
call `re.compile`; the bare `compile()` builtin stays banned via the
Name check.

## The sandbox

- Child runs `python -I -S` (isolated, no site-packages), stripped
  environment (`PATH` only), temp working directory, hard wall-clock
  timeout (default 10 s), 256 MB address-space cap and a CPU cap.
- The child installs an import blocker for the dangerous modules and
  runs the generated code with restricted builtins: no `open`, `eval`,
  `exec`, `input`, or `__import__` — except a safe `__import__`
  wrapper that only allows the allowlisted modules. `import re` works;
  `import os` raises `ImportError`.
- No network is reachable from generated code: `socket` and friends
  cannot be imported, and there is no file access. This relies on the
  AST allowlist plus the child-side import block; in deployment, run
  the sandbox under a network namespace as well for a third layer.
- The parent re-verifies the AST before spawning the child (defense in
  depth). A timeout kills the child and reports `timed_out`.

## The review gate

- Staged files live in `backend/app/nn/synthesized/`. The plugin
  registry only scans `backend/app/plugins/`, so staged tools never
  run in the live scanner.
- Every staged file carries a `PENDING HUMAN REVIEW` header and
  `HUMAN_REVIEWED = False`. Its `run()` refuses to run until a human
  moves the file into `app/plugins/` AND flips the flag.
- Review checklist (also in `synthesized/README.md`): read the decoder
  and the synthesis report; confirm detection-only (parse only, no
  transactions, no drains, no exploits, no auth bypass, no
  private-data access); move it; flip the flag; run the plugin health
  gate before any merge.
- Synthesized tools are never auto-merged, never auto-deployed, never
  wired into the live scanner by automation.

## Honest evaluation (real formats only)

NO-SIMULATION RULE (restated Nov 14): no simulated data anywhere in
ReconAnything. The evaluation counts ONLY real formats taken from real
observed traffic / contracts. Nothing is invented. Reproduce with:

```bash
cd backend
PYTHONDONTWRITEBYTECODE=1 python -m app.nn.evaluate_synthesis
```

Results from the Nov 14 run on this box (real numbers, not targets):

| Real format | Outcome | Kind | Confidence | Synth | Sandbox |
| --- | --- | --- | --- | --- | --- |
| ERC-20 `transfer(address,uint256)` calldata (0xa9059cbb) | cracked + verified | abi_words | 0.90 | 0.001 s | 0.130 s |
| Uniswap V2 `getReserves()` return (3 ABI words) | cracked + verified | abi_words | 0.90 | 0.001 s | 0.186 s |
| ERC-20 Transfer event log (`eth_getLogs` object) | cracked + verified | event_log | 0.90 | 0.001 s | 0.120 s |
| EIP-1167 minimal proxy (real WETH implementation) | cracked + verified | proxy | 0.95 | 0.001 s | 0.193 s |
| Uniswap V3 swap path (token + fee + token) | cracked + verified | abi_packed | 0.80 | 0.003 s | 0.300 s |
| Etherscan API envelope (address result) | cracked + verified | json_envelope | 0.85 | 0.004 s | 0.522 s |
| JSON-RPC `eth_getBalance` response | cracked + verified | json_envelope | 0.85 | 0.007 s | 0.302 s |
| RLP legacy transaction (Yellow Paper) | failed loudly (no RLP generator) | unknown | 0.15 | — | — |

Totals: **7 of 7 crackable real formats cracked and verified, 0
failed, 1 expected loud failure.** Mean synthesis 0.003 s, mean
sandbox 0.251 s per format. AST verifier caught **18 of 18**
adversarial payloads (100%: `os.system`, `socket`, `eval`, `exec`,
`open`, `__import__`, dunder access, `subprocess`, `getattr`,
`requests`, `compile`, `sys.exit`, `pathlib` write, `input`, and
more) and accepted the clean decoder.

These are fixture wins on real formats, NOT live-contract wins. No
live contract was scanned to produce them, and no synthesized tool has
run outside the sandbox.

Addresses in the fixtures are real mainnet addresses: USDC
`0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`, WETH
`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`, the zero address (mint
sender in the Transfer log). Lowercase hex throughout; EIP-55
checksummed forms are `0xA0b86991…` and `0xC02aaA39…`.

## Limits (honest)

- Template-based, not general: it only cracks formats whose layout
  the inferrer pins down (the 7 above). Anything else — RLP, dynamic
  arrays, nested structs, compressed/encrypted blobs — fails loudly.
  That is by design; guessing would be worse.
- Address vs uint ambiguity: a 32-byte word with 12 leading zero
  bytes is read as an address only when its value does not fit in a
  uint64; small values are read as ints. A real address whose first
  bytes are zero (vanishingly rare on mainnet) would misclassify.
- A 32-byte word that is both a small int and an address-shaped value
  (e.g. `eth_getBalance` returning 42 vs an address `0x…002a`) cannot
  be told apart by shape alone; the JSON walker reports it as a value
  when it arrives as a short hex int, as an address when it arrives
  as a full word. Documented, not hidden.
- The JSON walker maps by value shape, so envelope noise (e.g. a
  numeric request `id`) can land in the output as `value` when it
  shares the shape. The held-out fixtures assert the exact output,
  noise included.
- The sandbox's network isolation rests on the AST allowlist plus the
  child-side import block. For production use, add a network
  namespace around the child.
- Synthesized decoders are triage aids. They never verify a live
  finding, never stamp `VERIFIED_REAL`, and never replace a human
  reading the contract.
