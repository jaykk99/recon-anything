"""CLI: python -m scripts.fork_attack --chain bsc --address 0x... \
--hypothesis '{"function": "mint(address,uint256)", "args": ["STRANGER", "MAX"]}'

Local Anvil fork only. Refuses any broadcast hypothesis. Verdict
is always UNVERIFIED.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.fork_attack import run_fork_attack  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Run an attack hypothesis on a local Anvil fork.")
    p.add_argument("--chain", required=True)
    p.add_argument("--address", required=True)
    p.add_argument("--hypothesis", required=True,
                   help="JSON object, or @path to a JSON file")
    p.add_argument("--timeout", type=float, default=300)
    p.add_argument("--out", help="write the result JSON to this path")
    args = p.parse_args(argv)
    raw = args.hypothesis
    if raw.startswith("@"):
        with open(raw[1:]) as fh:
            hypothesis = json.load(fh)
    else:
        hypothesis = json.loads(raw)
    result = run_fork_attack(args.chain, args.address, hypothesis,
                             timeout_s=args.timeout)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"Result written to {args.out}")
    print(text)
    return 0 if result.get("status") in ("completed", "refused") else 1


if __name__ == "__main__":
    raise SystemExit(main())
