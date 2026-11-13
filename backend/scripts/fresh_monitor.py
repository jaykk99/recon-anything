#!/usr/bin/env python3
"""Fresh-code monitor: watch GitHub repos and deployment
announcements for upgrades, newly added features, and
new-chain deployments, and feed newly upgraded contracts into
the scanner's fresh queue with priority.

Usage:
  fresh_monitor.py [--config config.json] [--state-dir state/]
                   [--repo owner/name] [--dry-run]

Sources are keyless / public only, no API keys:
- GitHub Atom feeds (releases.atom, tags.atom, commits.atom)
  need no auth and put no rate-limit pressure on the API.
- The public GitHub API (with ETag caching) and
  raw.githubusercontent.com are used only to fetch a repo's
  deployment files for an entry that is new.

What it emits:
- Fresh-code events JSONL (state/fresh_monitor_events.jsonl):
  every new release / tag / commit, with the addresses found.
- Fresh queue rows (state/queues/fresh_monitor.jsonl):
  {chain, address, queue: "fresh", label, source} - ONLY when
  a deployed address can actually be extracted, from the
  release notes or from the repo's deployment files
  (deployments.json, deployments/<chain>/*.json). An entry
  with no extractable address is recorded watch-only and
  NEVER faked into a queue row.

Dedup: a seen-state file (state/fresh_monitor_seen.json)
records (repo, entry id, updated) so a re-run only reports
what is new. ETags are cached in the same file so a
re-fetch that returns 304 costs nothing.

The on-chain upgrade side is covered by the transition
watcher; this is the GitHub / release side.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app import net  # noqa: E402

from app.plugins import contract_chain as cc  # noqa: E402

ATOM_NS = "{http://www.w3.org/2005/Atom}"
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")

# A modest default watchlist: major protocols whose upgrades
# and new-chain deployments are worth scanning first. Override
# with --config or --repo.
DEFAULT_REPOS = [
    {"repo": "Uniswap/v3-core", "chains": ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc"]},
    {"repo": "Uniswap/v3-periphery", "chains": ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc"]},
    {"repo": "aave/aave-v3-core", "chains": ["ethereum", "arbitrum", "optimism", "base", "polygon"]},
    {"repo": "compound-finance/compound-protocol", "chains": ["ethereum"]},
    {"repo": "curvefi/curve-contracts", "chains": ["ethereum", "arbitrum", "optimism", "base", "polygon"]},
    {"repo": "makerdao/dss", "chains": ["ethereum"]},
    {"repo": "pancakeswap/pancake-v3-core", "chains": ["bsc", "ethereum", "arbitrum", "base"]},
    {"repo": "OpenZeppelin/openzeppelin-contracts", "chains": ["ethereum", "bsc", "arbitrum", "base", "polygon"]},
]

# Deployment-file paths tried (raw GitHub) for a new release /
# tag, {chain} and {ref} substituted. First hit wins.
DEPLOYMENT_PATHS = (
    "deployments.json",
    "deployments/{chain}.json",
    "deployments/{chain}/addresses.json",
    "deployments/{chain}/latest.json",
    "addresses.json",
    "config/deployments.json",
)

USER_AGENT = "recon-anything-fresh-monitor/1.0"


def fetch(url: str, etag: str = "", timeout: int = 30,
          retries: int = 3):
    """GET a URL, keyless. Returns (status, body, etag).

    status 304 means "not modified" (body is b""). httpx is
    used, not urllib: urllib reads come back truncated through
    this VM's egress proxy (RemoteDisconnected / IncompleteRead)
    while httpx works. The client comes from app.net, which
    configures the egress proxy explicitly (trust_env=False,
    NO_PROXY mounts, system CA bundle) - a raw httpx.Client
    mis-parses the proxy env vars.

    Transient disconnects (the egress proxy drops connections
    in waves) are retried with a short backoff; a persistent
    failure raises RuntimeError so the caller records an
    honest error instead of a faked result.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/atom+xml, application/json, "
                  "text/plain, */*",
    }
    if etag:
        headers["If-None-Match"] = etag
    last_exc = None
    for attempt in range(retries):
        try:
            with net.sync_client(timeout=timeout,
                                 follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
        except httpx.RequestError as exc:
            last_exc = exc
            if attempt + 1 < retries:
                time.sleep(2 * (attempt + 1))
                continue
            raise RuntimeError(
                f"fetch failed for {url}: {exc}") from exc
        if resp.status_code == 304:
            return 304, b"", etag
        return resp.status_code, resp.content, \
            resp.headers.get("ETag", "")
    raise RuntimeError(f"fetch failed for {url}: {last_exc}")


# Deployment-file fetches are bounded per run: most repos do
# not publish a deployments.json, so an unbounded scan would
# spend the whole run on 404s. The release-notes extraction is
# the primary address source; deployment files are a bonus for
# repos that publish them.
DEPLOY_FETCH_BUDGET = 40


def parse_atom(body: bytes):
    """Atom feed -> list of entries {id, title, updated, link,
    text}."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    entries = []
    for el in root.findall(f"{ATOM_NS}entry"):
        def _text(tag):
            node = el.find(f"{ATOM_NS}{tag}")
            return (node.text or "").strip() if node is not None \
                else ""
        link = ""
        for ln in el.findall(f"{ATOM_NS}link"):
            if ln.get("rel") in (None, "alternate"):
                link = ln.get("href", "")
                break
        entries.append({
            "id": _text("id"),
            "title": _text("title"),
            "updated": _text("updated"),
            "link": link,
            "text": (_text("content") or _text("summary")),
        })
    return entries


def extract_addresses(text: str):
    """All plausible contract addresses in a blob of text,
    deduped, order kept."""
    seen = set()
    out = []
    for m in ADDRESS_RE.finditer(text or ""):
        addr = m.group(0)
        if addr.lower() == cc.ZERO_ADDRESS:
            continue
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(addr)
    return out


def extract_addresses_from_json(obj, depth: int = 0):
    """Every address string anywhere in a deployment JSON."""
    out = []
    if depth > 6:
        return out
    if isinstance(obj, str):
        out.extend(extract_addresses(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(extract_addresses_from_json(v, depth + 1))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(extract_addresses_from_json(v, depth + 1))
    return out


def fetch_deployment_addresses(repo: str, ref: str, chain: str,
                               etags: dict, budget: dict) -> list:
    """Try the deployment-file paths for one repo/ref/chain.
    Returns the addresses found in the first file that exists
    and parses, else []. `budget` is a shared {"left": n}
    counter: each fetch attempt costs 1, and when it hits 0
    no more deployment files are fetched this run."""
    owner_name = repo
    for path in DEPLOYMENT_PATHS:
        if budget["left"] <= 0:
            return []
        budget["left"] -= 1
        p = path.format(chain=chain, ref=ref)
        url = (f"https://raw.githubusercontent.com/{owner_name}/"
               f"{ref}/{p}")
        key = f"raw:{url}"
        try:
            status, body, etag = fetch(url, etags.get(key, ""),
                                       timeout=10)
        except RuntimeError:
            continue
        if etag:
            etags[key] = etag
        if status == 304:
            continue
        if status != 200 or not body:
            continue
        try:
            obj = json.loads(body)
        except ValueError:
            continue
        addrs = extract_addresses_from_json(obj)
        if addrs:
            return addrs
    return []


def load_state(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"seen": {}, "etags": {}}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def append_jsonl(path: str, rows) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def monitor_repo(repo_cfg: dict, state: dict, dry_run: bool,
                 budget: dict = None):
    """One repo -> (events, queue_rows)."""
    repo = repo_cfg["repo"]
    chains = repo_cfg.get("chains") or ["ethereum"]
    kinds = repo_cfg.get("watch") or ["releases", "tags"]
    if budget is None:
        budget = {"left": DEPLOY_FETCH_BUDGET}
    events, queue_rows = [], []
    seen = state.setdefault("seen", {})
    etags = state.setdefault("etags", {})
    for kind in kinds:
        feed_url = f"https://github.com/{repo}/{kind}.atom"
        key = f"feed:{feed_url}"
        try:
            status, body, etag = fetch(feed_url,
                                       etags.get(key, ""))
        except RuntimeError as exc:
            events.append({"repo": repo, "kind": kind,
                           "error": str(exc)})
            continue
        if etag:
            etags[key] = etag
        if status == 304 or not body:
            continue
        if status != 200:
            events.append({"repo": repo, "kind": kind,
                           "error": f"feed returned {status}"})
            continue
        for entry in parse_atom(body):
            eid = entry["id"] or entry["link"] or entry["title"]
            seen_key = f"{repo}|{kind}|{eid}"
            if seen_key in seen:
                continue
            seen[seen_key] = entry["updated"]
            # A tag / release ref for the deployment files.
            ref = ""
            m = re.search(r"/(?:releases/tag|tag)/([^/]+)",
                          entry["link"] or "")
            if m:
                ref = m.group(1)
            addresses = []
            source = ""
            # Deployment files are only worth fetching for
            # releases (the deployment announcements), and
            # only while the per-run budget lasts. Tags and
            # commits fall through to the release-notes check.
            if ref and kind == "releases":
                for chain in chains:
                    found = fetch_deployment_addresses(
                        repo, ref, chain, etags, budget)
                    if found:
                        addresses = found
                        source = f"deployment-file:{chain}"
                        break
                    if budget["left"] <= 0:
                        break
            if not addresses:
                addresses = extract_addresses(
                    entry["text"] + "\n" + entry["title"])
                if addresses:
                    source = "release-notes"
            event = {"repo": repo, "kind": kind,
                     "id": eid, "title": entry["title"],
                     "updated": entry["updated"],
                     "url": entry["link"],
                     "addresses": addresses,
                     "queue_emitted": bool(addresses)}
            events.append(event)
            if addresses and not dry_run:
                chain = (source.split(":", 1)[1]
                         if source.startswith("deployment-file:")
                         else chains[0])
                for addr in addresses:
                    queue_rows.append({
                        "chain": chain, "address": addr,
                        "queue": "fresh",
                        "label": f"{repo} {entry['title'][:80]}",
                        "source": f"fresh_monitor:{source}",
                    })
    return events, queue_rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Watch GitHub repos for upgrades / new "
                    "deployments and feed new contracts into the "
                    "scanner's fresh queue.")
    ap.add_argument("--config",
                    help="JSON config {repos: [{repo, chains, "
                         "watch}]} (default: built-in watchlist)")
    ap.add_argument("--state-dir",
                    help="state dir (default: backend/state)")
    ap.add_argument("--repo",
                    help="watch one repo only, owner/name")
    ap.add_argument("--dry-run", action="store_true",
                    help="report new entries, write no queue rows")
    args = ap.parse_args(argv)

    repos = None
    if args.config:
        with open(args.config) as fh:
            repos = json.load(fh).get("repos")
    if args.repo:
        repos = [{"repo": args.repo,
                  "chains": ["ethereum", "bsc", "arbitrum",
                             "optimism", "base", "polygon"]}]
    if not repos:
        repos = DEFAULT_REPOS

    base = args.state_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "state")
    seen_path = os.path.join(base, "fresh_monitor_seen.json")
    events_path = os.path.join(base, "fresh_monitor_events.jsonl")
    queue_path = os.path.join(base, "queues",
                              "fresh_monitor.jsonl")
    state = load_state(seen_path)

    all_events, all_rows = [], []
    budget = {"left": DEPLOY_FETCH_BUDGET}
    for repo_cfg in repos:
        events, rows = monitor_repo(repo_cfg, state, args.dry_run,
                                    budget)
        all_events.extend(events)
        all_rows.extend(rows)

    save_state(seen_path, state)
    if all_events:
        append_jsonl(events_path, all_events)
    if all_rows:
        append_jsonl(queue_path, all_rows)

    new_events = [e for e in all_events if "error" not in e]
    print(f"fresh_monitor: {len(repos)} repo(s), "
          f"{len(new_events)} new entr(ies), "
          f"{len(all_rows)} fresh queue row(s)"
          + (" (dry-run, no rows written)" if args.dry_run else ""))
    for e in new_events:
        print(f"  {e['repo']} [{e['kind']}] {e['title'][:100]} "
              f"-> {len(e['addresses'])} address(es)"
              + ("" if e["queue_emitted"] else " (watch-only)"))
    for e in all_events:
        if "error" in e:
            print(f"  {e['repo']} [{e['kind']}] ERROR: "
                  f"{e['error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
