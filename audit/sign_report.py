#!/usr/bin/env python3
"""TapeOut Audit, step 2: sign the report (Ed25519) and timestamp it on Bitcoin (OpenTimestamps).

Run after run_audit.py. Reads audit_latest.json, adds a "proof" object, writes it back.
- The signed "core" is audit_latest.json without the keys runtimeSeconds, reportSha256, history, passStreak, proof.
  Canonical bytes = json.dumps(core, sort_keys=True, separators=(",", ":")) (ASCII-escaped, UTF-8).
- reportSha256 = SHA-256 of those bytes (hex). The Ed25519 signature is over the 64-char hex string (UTF-8).
- reports/report_<block>.json holds the exact canonical bytes; reports/report_<block>.json.ots is its
  OpenTimestamps proof (pending until a Bitcoin block confirms it; the newest 72 pending proofs are upgraded each run).
Signing key: env TAPEOUT_SIGNING_KEY (32-byte seed, hex) if set, else .keys/ed25519.key (created on first run, chmod 600).
The private key is never printed, logged or written anywhere else.
"""
import json, os, sys, glob, base64, hashlib, subprocess, pathlib
HERE = pathlib.Path(os.environ.get("TAPEAUDIT_DIR", pathlib.Path(__file__).resolve().parent))
CODE = pathlib.Path(__file__).resolve().parent
PYLIB = next((p for p in (CODE / ".pylib", CODE.parent / "shield" / ".pylib") if p.exists()), None)
if PYLIB: sys.path.insert(0, str(PYLIB))
import nacl.signing

NONCORE = ["runtimeSeconds", "reportSha256", "history", "passStreak", "proof"]
KEY = CODE / ".keys" / "ed25519.key"
REP = HERE / "reports"; REP.mkdir(exist_ok=True)
LATEST = HERE / "audit_latest.json"
OTS_BIN = (PYLIB / "bin" / "ots") if PYLIB and (PYLIB / "bin" / "ots").exists() else None
OTS = [sys.executable, str(OTS_BIN)] if OTS_BIN else ["ots"]
ENV = dict(os.environ, PYTHONPATH=str(PYLIB) if PYLIB else os.environ.get("PYTHONPATH", ""))

seed_hex = os.environ.get("TAPEOUT_SIGNING_KEY", "").strip()
if seed_hex:
    sk = nacl.signing.SigningKey(bytes.fromhex(seed_hex))
elif os.environ.get("CI"):
    raise SystemExit("TAPEOUT_SIGNING_KEY secret is not set; refusing to sign with a throwaway key in CI")
else:
    if not KEY.exists():
        KEY.parent.mkdir(exist_ok=True); os.chmod(KEY.parent, 0o700)
        KEY.write_bytes(nacl.signing.SigningKey.generate().encode()); os.chmod(KEY, 0o600)
    sk = nacl.signing.SigningKey(KEY.read_bytes())
pub = sk.verify_key.encode().hex()

d = json.load(open(LATEST))
core = {k: v for k, v in d.items() if k not in NONCORE}
raw = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
digest = hashlib.sha256(raw).hexdigest()
assert digest == d["reportSha256"], "digest mismatch: audit_latest.json was edited after run_audit.py"
sig = sk.sign(digest.encode()).signature.hex()
nacl.signing.VerifyKey(bytes.fromhex(pub)).verify(digest.encode(), bytes.fromhex(sig))  # self-check

h = core["pinnedBlock"]["number"]
f = REP / f"report_{h}.json"
if not f.exists(): f.write_bytes(raw)
ots_err = None
if not (REP / f"report_{h}.json.ots").exists():
    try:
        r = subprocess.run(OTS + ["stamp", str(f)], env=ENV, capture_output=True, text=True, timeout=60)
        if r.returncode: ots_err = (r.stderr or r.stdout)[-300:]
    except Exception as e: ots_err = str(e)

def rep_height(p): return int(p.split("_")[-1].split(".")[0])
confirmed = None
proofs = sorted(glob.glob(str(REP / "report_*.json.ots")), key=rep_height, reverse=True)
for p in proofs[:72]:  # Bitcoin confirmation takes a few hours; keep upgrading the newest 72 proofs
    try:
        info = subprocess.run(OTS + ["info", p], env=ENV, capture_output=True, text=True, timeout=30).stdout
        if "BitcoinBlockHeaderAttestation" not in info:
            subprocess.run(OTS + ["upgrade", p], env=ENV, capture_output=True, timeout=60)
            info = subprocess.run(OTS + ["info", p], env=ENV, capture_output=True, text=True, timeout=30).stdout
    except Exception: continue
    if confirmed is None and "BitcoinBlockHeaderAttestation" in info:
        btc = int(info.split("BitcoinBlockHeaderAttestation(")[1].split(")")[0])
        rawp = pathlib.Path(p[:-4]).read_bytes()
        confirmed = {"reportBlock": rep_height(p), "bitcoinBlock": btc, "reportSha256": hashlib.sha256(rawp).hexdigest(),
                     "reportJson": rawp.decode(), "otsBase64": base64.b64encode(pathlib.Path(p).read_bytes()).decode()}
CONF = REP / "confirmed.json"
if confirmed is not None: CONF.write_text(json.dumps(confirmed))
elif CONF.exists(): confirmed = json.loads(CONF.read_text())
for p in proofs[300:]:  # keep the newest 300 reports
    for q in (p, p[:-4]):
        try: os.remove(q)
        except FileNotFoundError: pass

latest_ots = REP / f"report_{h}.json.ots"
d["proof"] = {
    "algorithm": "Ed25519", "publicKey": pub, "signedMessage": "reportSha256 (UTF-8 hex string)",
    "signature": sig, "sha256": digest, "reportBlock": h,
    "canonicalization": "json.dumps(report minus [runtimeSeconds, reportSha256, history, passStreak, proof], sort_keys=True, separators=(',', ':'))",
    "otsBase64": base64.b64encode(latest_ots.read_bytes()).decode() if latest_ots.exists() else None,
    "otsPending": latest_ots.exists() and (confirmed is None or confirmed["reportBlock"] != h),
    "otsError": ots_err,
    "confirmed": confirmed,
}
tmp = LATEST.with_suffix(".tmp"); tmp.write_text(json.dumps(d, indent=1)); tmp.replace(LATEST)
print("signed block", h, "sha256", digest[:16], "confirmed", confirmed and confirmed["bitcoinBlock"], "ots", "error: " + ots_err if ots_err else "ok")
print("publicKey", pub)
