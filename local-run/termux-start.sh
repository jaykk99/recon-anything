#!/usr/bin/env bash
# Start ReconAnything locally in Termux. Run termux-setup.sh once first.
# Tip: run `termux-wake-lock` in another Termux session so Android does
# not freeze the app mid-scan.
exec "$(cd "$(dirname "$0")" && pwd)/start-common.sh"
