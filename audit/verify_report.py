#!/usr/bin/env python3
"""Verify a TapeOut Audit report without trusting anyone.

Usage: python3 verify_report.py audit_latest.json [expected_public_key_hex]

1. Rebuilds the canonical core (report minus runtimeSeconds, reportSha256, history, passStreak, proof),
   serialised with json.dumps(core, sort_keys=True, separators=(",", ":")), and checks its SHA-256.
2. Verifies the Ed25519 signature over that hex digest (UTF-8) with the public key
   (pure-Python RFC 8032 verifier below; no dependencies).
3. Tells you how to check the Bitcoin timestamp: save proof.otsBase64 as report.json.ots next to the canonical bytes
   (reports/report_<block>.json) and run `ots verify report.json.ots`.
"""
import json, sys, hashlib, base64

# ---- RFC 8032 Ed25519 verification (reference arithmetic, verification only) ----
p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)
def inv(x): return pow(x, p - 2, p)
def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1); x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p: x = x * I % p
    if x % 2: x = p - x
    return x
By = 4 * inv(5) % p; B = (xrecover(By), By)
def add(P, Q):
    x1, y1 = P; x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2); y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)
    return (x3 % p, y3 % p)
def mul(P, e):
    R = (0, 1)
    while e:
        if e & 1: R = add(R, P)
        P = add(P, P); e >>= 1
    return R
def decode(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1); x = xrecover(y)
    if (x & 1) != (s[31] >> 7): x = p - x
    P = (x, y)
    if (-x * x + y * y - 1 - d * x * x * y * y) % p: raise ValueError("point not on curve")
    return P
def verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32: return False
    R = decode(sig[:32]); A = decode(pub); S = int.from_bytes(sig[32:], "little")
    if S >= L: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little")
    return mul(B, S) == add(R, mul(A, h))

NONCORE = ["runtimeSeconds", "reportSha256", "history", "passStreak", "proof"]
if __name__ == "__main__":
    rep = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "audit_latest.json"))
    expected_pub = sys.argv[2].lower() if len(sys.argv) > 2 else None
    core = {k: v for k, v in rep.items() if k not in NONCORE}
    raw = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw).hexdigest()
    pr = rep["proof"]
    ok_hash = digest == rep["reportSha256"] == pr["sha256"]
    ok_key = expected_pub is None or expected_pub == pr["publicKey"]
    ok_sig = verify(bytes.fromhex(pr["publicKey"]), digest.encode(), bytes.fromhex(pr["signature"]))
    print("block          ", rep["pinnedBlock"]["number"], rep["pinnedBlock"]["hash"])
    print("report sha256  ", digest, "OK" if ok_hash else "MISMATCH")
    print("public key     ", pr["publicKey"], "(matches expected)" if expected_pub and ok_key else ("DIFFERENT FROM EXPECTED" if not ok_key else "(compare with docs/KEYS.md)"))
    print("signature      ", "VALID" if ok_sig else "INVALID")
    print("bitcoin stamp  ", "pending (calendar commitment, confirms in a few hours)" if pr.get("otsPending") else "confirmed", "- verify with `ots verify`")
    sys.exit(0 if ok_hash and ok_sig and ok_key else 1)
