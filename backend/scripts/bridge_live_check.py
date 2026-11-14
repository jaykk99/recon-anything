"""CLI: python -m scripts.bridge_live_check --spec \\
    bridge-lock:ethereum:<vault>:<token>:arbitrum:<mintToken> \\
    [--spec bridge-quorum:ethereum:<bridge>] \\
    [--spec bridge-nonce:ethereum:<bridgeA>:bsc:<bridgeB>] [--out out.json]

Live bridge invariant checks (Wave 1.3). Read-only eth_call /
eth_getCode / eth_getStorageAt over the public keyless RPCs in
contract_chain.CHAINS; never sends a transaction. One --spec per
check; each result carries its verdict (candidate / clean /
degraded) and, on a break, both sides' live numbers.

Exit code 0 always (a candidate is a finding to triage, not a
script error); the JSON carries the verdicts.
"""
import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app import proxy_bridge_live as pbl  # noqa: E402


async def _run(specs):
    reader = pbl.SyncRpcReader()
    results = []
    for spec in specs:
        cfg = pbl.parse_bridge_target(spec)
        if cfg is None:
            results.append({"spec": spec, "verdict": "degraded",
                            "detail": "unparseable bridge spec"})
            continue
        if isinstance(cfg, pbl.BridgeLockMintConfig):
            res = await pbl.check_locked_vs_minted(reader, cfg)
        elif isinstance(cfg, pbl.BridgeQuorumConfig):
            res = await pbl.check_validator_quorum(reader, cfg)
        elif isinstance(cfg, pbl.BridgeNonceConfig):
            res = await pbl.check_nonce_continuity(reader, cfg)
        else:  # pragma: no cover - parse only returns the three
            res = {"verdict": "degraded", "detail": "unknown config"}
        res["spec"] = spec
        results.append(res)
    return results


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Read-only live bridge invariant checks.")
    p.add_argument("--spec", action="append", required=True,
                   help="bridge-lock: / bridge-quorum: / bridge-nonce: "
                        "spec (repeatable)")
    p.add_argument("--out", help="write results JSON here")
    args = p.parse_args(argv)
    results = asyncio.run(_run(args.spec))
    print(json.dumps({"results": results}, indent=2, sort_keys=True))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump({"results": results}, fh, indent=2,
                      sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
