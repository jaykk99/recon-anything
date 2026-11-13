"""CLI: python -m scripts.defense_watch snapshot --chain bsc \
--address 0x... [--spenders 0x..,0x..] [--state out.json]
     python -m scripts.defense_watch diff --prev a.json --cur b.json
     python -m scripts.defense_watch watch --chain bsc --address 0x... \
--interval 300 --rounds 3 [--state state.json]
     python -m scripts.defense_watch upgrade --chain bsc \
--address 0x... --prev-state state.json [--state state.json]

Read-only live snapshots. Never sends a transaction. The upgrade
subcommand (Wave 1.3) diffs the implementation between the previous
snapshot and a fresh one: bytecode selector diff + dangerous-opcode
diff for the new implementation. Source re-analysis is wired in the
proxy_live plugin (verified source via the engine); the CLI reports
bytecode-diff only and marks unverified changes degraded, never
clean.
"""

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.defense_watch import (analyze_upgrade, diff_snapshots,  # noqa: E402
                               snapshot)


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def _save(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Read-only defense watch snapshots.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--chain", required=True)
    s.add_argument("--address", required=True)
    s.add_argument("--spenders", default="",
                   help="comma-separated spender addresses")
    s.add_argument("--token", default=None)
    s.add_argument("--state", help="write snapshot JSON here")
    d = sub.add_parser("diff")
    d.add_argument("--prev", required=True)
    d.add_argument("--cur", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--chain", required=True)
    w.add_argument("--address", required=True)
    w.add_argument("--spenders", default="")
    w.add_argument("--token", default=None)
    w.add_argument("--interval", type=float, default=300)
    w.add_argument("--rounds", type=int, default=2)
    w.add_argument("--state", help="persist latest snapshot here")
    u = sub.add_parser("upgrade")
    u.add_argument("--chain", required=True)
    u.add_argument("--address", required=True)
    u.add_argument("--prev-state", required=True,
                   help="previous snapshot JSON (from snapshot/watch)")
    u.add_argument("--state", help="persist the new snapshot here")
    args = p.parse_args(argv)

    if args.cmd == "upgrade":
        prev = _load(args.prev_state)
        cur = snapshot(args.chain, args.address)
        report = asyncio.run(analyze_upgrade(prev, cur))
        print(json.dumps(
            {"changes": diff_snapshots(prev, cur),
             "upgrade": report, "snapshot": cur},
            indent=2, sort_keys=True))
        if args.state:
            _save(args.state, cur)
        return 0

    if args.cmd == "diff":
        changes = diff_snapshots(_load(args.prev), _load(args.cur))
        print(json.dumps({"changes": changes}, indent=2))
        return 0
    spenders = [x for x in args.spenders.split(",") if x]
    prev = None
    if args.cmd == "watch" and args.state:
        try:
            prev = _load(args.state)
        except Exception:  # noqa: BLE001
            prev = None
    cur = None
    for i in range(args.cmd == "watch" and args.rounds or 1):
        if i:
            time.sleep(args.interval)
        cur = snapshot(args.chain, args.address,
                       spenders=spenders, token=args.token)
        if prev is not None:
            changes = diff_snapshots(prev, cur)
            print(json.dumps(
                {"round": i + 1, "changes": changes,
                 "snapshot": cur}, indent=2, sort_keys=True))
        else:
            print(json.dumps(cur, indent=2, sort_keys=True))
        prev = cur
        if args.state:
            _save(args.state, cur)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
