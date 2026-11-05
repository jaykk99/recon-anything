#!/usr/bin/env python3
"""Local-only fingerprint matcher for ReconAnything secret findings.

Usage:
    python3 match_secret_fingerprint.py --findings findings.json \
        --secrets-file /tmp/my-labels.txt

    python3 match_secret_fingerprint.py --fingerprint sha256:<hex> \
        --secrets-file /tmp/my-labels.txt

The secrets file has one ``label=value`` per line. This tool hashes
each value in memory, compares the hashes to the fingerprints from a
finding, and prints ONLY labels and fingerprints, plus MATCH / no-match
per label. It never prints, stores, or transmits a secret value, and
it makes no network requests.

Safety: keep the secrets file outside any repo, do not commit it, and
delete it when you are done. Values passed on the command line would
show up in process listings, so this tool deliberately does not
accept a secret as an argument.

The findings file is a JSON list (or dict with a ``findings`` list)
of finding objects; fingerprints are read from each finding's
``evidence.fingerprint`` field, and also from a top-level
``fingerprint`` field if present.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys


def fingerprint(secret: str) -> str:
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def load_fingerprints(path: str) -> set:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("findings", data) if isinstance(data, dict) else data
    out = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        fp = (item.get("evidence") or {}).get("fingerprint")
        if fp:
            out.add(fp)
        if item.get("fingerprint"):
            out.add(item["fingerprint"])
    return out


def load_labels(path: str):
    """Yield (label, value) pairs. Values stay in memory only."""
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                print(f"skip line {lineno}: no '=' separator",
                      file=sys.stderr)
                continue
            label, value = line.split("=", 1)
            yield label.strip(), value.strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Match local secret labels to finding fingerprints.")
    ap.add_argument("--findings", help="JSON findings file")
    ap.add_argument("--fingerprint",
                    help="Single fingerprint to match (sha256:<hex>)")
    ap.add_argument("--secrets-file", required=True,
                    help="label=value file, kept outside any repo")
    args = ap.parse_args(argv)

    targets = set()
    if args.findings:
        targets |= load_fingerprints(args.findings)
    if args.fingerprint:
        targets.add(args.fingerprint)
    if not targets:
        print("error: supply --findings or --fingerprint", file=sys.stderr)
        return 2

    matched_any = False
    for label, value in load_labels(args.secrets_file):
        fp = fingerprint(value)
        if fp in targets:
            print(f"MATCH label={label} fingerprint={fp}")
            matched_any = True
        else:
            print(f"no-match label={label} fingerprint={fp}")
    # Values are never printed, even on a match. The label is the
    # identification; the owner already knows what that label holds.
    return 0 if matched_any else 1


if __name__ == "__main__":
    raise SystemExit(main())
