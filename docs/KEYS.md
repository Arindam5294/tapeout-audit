# TapeOut Audit signing key

Every TapeOut Audit report is signed with this Ed25519 key. If a report's signature does not verify against
this exact key, it was not produced by TapeOut Audit.

| | |
|---|---|
| Algorithm | Ed25519 (RFC 8032) |
| Public key (hex, 32 bytes) | `75b7f5f61779bad120496e4ecfaaae20784e3d4119bd39247db069bed7205f1a` |
| Signed message | the report's `reportSha256`, as a 64-character lowercase hex string, UTF-8 encoded |
| In use since | X Layer block 73,369,151 (2026-10-16) |

This key is separate from the Shield Audit key. It signs TapeOut Audit reports only.

## Verifying

```sh
python3 audit/verify_report.py data/audit_latest.json 75b7f5f61779bad120496e4ecfaaae20784e3d4119bd39247db069bed7205f1a
```

`verify_report.py` uses only the Python standard library (it has its own RFC 8032 verifier), so you can audit the
verifier in a few minutes.

## Where the private key lives

- It is never committed. `.gitignore` excludes `.keys/`.
- In GitHub Actions, it is the repository secret `TAPEOUT_SIGNING_KEY`. The value is the 32-byte Ed25519 seed as
  64 hex characters. On the machine that holds the key file, you can make that value with `python3 -c "print(open('.keys/ed25519.key','rb').read().hex())"`.
  Paste it directly into the secret and never into an issue, a log or a chat.
- `sign_report.py` refuses to run in CI without the secret. That way a throwaway key can never sign a public report.

## Rotation

If the key is ever replaced, this file will list the old key, the new key, the block where the change happened,
and a statement signed by the old key that endorses the new one.
