#!/usr/bin/env python3
"""Prints one line: OK | ALERT <reasons> | RECOVERED | STILLFAIL <reasons>.
ALERT only for checks with status FAIL (WARN never alerts). Remembers state in alert_state.txt so each incident
alerts once; a stale report (older than 2 hours) also counts as a failure so a dead pipeline is noticed."""
import json, pathlib, time, calendar, os
H = pathlib.Path(os.environ.get("TAPEAUDIT_DIR", pathlib.Path(__file__).resolve().parent))
fails = []
try:
    a = json.load(open(H / "audit_latest.json"))
    fails = [f"{c['id']} {c['title']}: {c['detail'][:200]}" for c in a.get("checks", []) if c.get("status") == "FAIL"]
    gen = calendar.timegm(time.strptime(a["generatedAt"], "%Y-%m-%dT%H:%M:%SZ"))
    if time.time() - gen > 7200: fails.append(f"report is stale (generated {a['generatedAt']})")
    blk = a["pinnedBlock"]["number"]
except Exception as e:
    fails.append(f"audit_latest.json unreadable: {e}"); blk = "?"
sp = H / "alert_state.txt"; prev = sp.read_text().strip() if sp.exists() else "OK"
if fails:
    sp.write_text("FAIL")
    print(("STILLFAIL " if prev == "FAIL" else "ALERT ") + f"block {blk}: " + " | ".join(fails))
else:
    sp.write_text("OK")
    print("RECOVERED" if prev == "FAIL" else "OK")
