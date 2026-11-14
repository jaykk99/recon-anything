"""Fetch xanoutas + audit-findings rows from the HuggingFace
datasets-server rows API (public, no key) into JSONL files the
build_external_dataset.py builder reads.

Datasets:
- xanoutas/solidity-security-findings (18.9k rows)
- mmlliu/audit-findings-dataset (23.6k rows)

Writes nn-logs/job2/xanoutas-rows.jsonl and
nn-logs/job2/auditfindings-rows.jsonl, one row dict per line, in
dataset order (the builder's dedup keeps the first occurrence, so
order matters). Paginates length=100. Prints progress every 50
pages. Stdlib only.

Run detached:
  nohup python3 nn-logs/fetch_external_rows.py > nn-logs/job2-fetch.log 2>&1 &
"""
import json
import os
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
JOB2_DIR = os.path.join(_HERE, "job2")
os.makedirs(JOB2_DIR, exist_ok=True)

DATASETS = [
    ("xanoutas/solidity-security-findings",
     os.path.join(JOB2_DIR, "xanoutas-rows.jsonl")),
    ("mmlliu/audit-findings-dataset",
     os.path.join(JOB2_DIR, "auditfindings-rows.jsonl")),
]
PAGE = 100


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "recon-nn/1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def fetch(dataset, out_path):
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        print(f"{dataset}: {out_path} already exists, skipping",
              flush=True)
        return
    info = _get_json(
        "https://datasets-server.huggingface.co/splits?dataset="
        + dataset)
    splits = info.get("splits", [])
    print(f"{dataset}: splits={[(s.get('config'), s.get('split')) for s in splits]}",
          flush=True)
    config = splits[0]["config"]
    split = splits[0]["split"]
    n_total = None
    offset = 0
    written = 0
    pages = 0
    t0 = time.time()
    with open(out_path, "w", encoding="utf-8") as fh:
        while True:
            url = ("https://datasets-server.huggingface.co/rows?dataset="
                   + dataset + "&config=" + config + "&split=" + split
                   + f"&offset={offset}&length={PAGE}")
            try:
                data = _get_json(url)
            except Exception as e:  # noqa: BLE001 - retry once
                print(f"  retry after {type(e).__name__}: {e}", flush=True)
                time.sleep(5)
                data = _get_json(url)
            rows = data.get("rows", [])
            if n_total is None:
                n_total = data.get("num_rows_total")
                print(f"{dataset}: total={n_total}", flush=True)
            if not rows:
                break
            for entry in rows:
                fh.write(json.dumps(entry.get("row", {}),
                                    ensure_ascii=False) + "\n")
                written += 1
            offset += len(rows)
            pages += 1
            if pages % 50 == 0:
                print(f"  {dataset}: {written}/{n_total} rows "
                      f"({time.time() - t0:.0f}s)", flush=True)
            if n_total is not None and offset >= n_total:
                break
    print(f"{dataset}: wrote {written} rows to {out_path} "
          f"({time.time() - t0:.0f}s)", flush=True)


def main():
    for dataset, out_path in DATASETS:
        fetch(dataset, out_path)
    print("FETCH-DONE", flush=True)


if __name__ == "__main__":
    main()
