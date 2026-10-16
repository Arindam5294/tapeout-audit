#!/bin/sh
# TapeOut Audit, one full cycle: audit -> sign + timestamp -> alert line. Author: Swanix.
# Set TAPEAUDIT_DIR (default: this folder) and, for signing, TAPEOUT_SIGNING_KEY (or a local .keys/ed25519.key).
set -e
cd "$(dirname "$0")"
start=$(date +%s)
python3 run_audit.py
python3 sign_report.py
python3 alert_check.py
echo "pipeline runtime: $(( $(date +%s) - start )) s"
