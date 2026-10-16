# TapeOut Audit

**An independent, read-only integrity monitor for the TapeOut protocol and DeWEB on X Layer (chainId 196).**
Each report is signed with Ed25519 and timestamped on Bitcoin.

By Swanix ([@swanixcrypto](https://x.com/swanixcrypto)) · MIT licensed · no keys, no paid services, no writes to the chain

**Live dashboard:** https://hark.site/s/11df3a32-f917-4ec1-9324-cb38757602a5?hark_region=us

---

## What it is

TapeOut puts things on chain: processors (ERC-721 contracts made by one factory), circuits (the NFTs they mint),
containers (each circuit's ERC-6551 wallet) and whole websites stored byte by byte in `SiteRegistry`, under names like
`1.2.231.tape`. TapeKit, the reference client, refuses to show anything that does not match the chain.
That protects one reader at a time. Nobody watches the whole protocol.

TapeOut Audit does. Every run it re-derives the protocol's state from scratch at one pinned block, from two
independent node operators, checks it against what the protocol promises, signs the result and timestamps it on Bitcoin.

## The problem it solves

- **Upgradeable core contracts.** The factory, SiteRegistry and DomainBinding are UUPS proxies. Processor code sits
  behind a beacon the factory owner controls. A silent upgrade would change what every circuit and every site does.
  Someone has to watch the implementation slots and the event history, continuously and in public.
- **Single-node trust.** A wallet or explorer that reads one RPC sees whatever that RPC says. X Layer has two
  independent public operators (OKX, which runs the sequencer, and dRPC). This audit requires them to agree.
- **"Is this site really what was published?"** Files can be large, multi-chunk and changed at any time. Someone has to
  re-hash the bytes against the published fingerprints and say which files fail.
- **No proof of history.** A green dashboard proves nothing after the fact. Signed, Bitcoin-timestamped reports
  prove what was checked and when.

## How it works

```
run_audit.py   pin block P = min(OKX head, dRPC head) − 2
               ├─ snapshot from OKX and from dRPC via Multicall3 (~10,000 reads each) → compare section by section
               ├─ implementation pins, owners, admin slots, wiring, seal status
               ├─ all processors (cpuAt 0..N-1), all circuit ids, all opened containers, all sites
               ├─ DeWEB files: fileInfo on both operators, re-hash bytes (rotating 16 MB/run)
               ├─ event history in 100-block windows (incremental, newest first, coverage reported)
               └─ audit_latest.json + circuit_index.json + audit_history.json
sign_report.py Ed25519 signature over reportSha256 + OpenTimestamps proof (upgrades the newest 72 pending proofs)
alert_check.py OK | ALERT <reason> | RECOVERED | STILLFAIL   (ALERT only on FAIL checks)
verify_report.py  anyone: recompute the hash and check the signature, no dependencies
```

## The 16 checks, in plain English

| ID | Check | What it means |
|---|---|---|
| C01 | Two independent node operators agree | Two separate companies running X Layer nodes report exactly the same block and the same contract data. |
| C02 | Data is fresh | The audit read the chain as it was moments ago (block under 300 s old), not an old copy. |
| C03 | Processor factory code is the audited version | The contract that creates processors still runs the exact code that was reviewed. |
| C04 | Circuit code is the audited version | Every processor NFT contract borrows its code from one place, and that place still points at the reviewed code. |
| C05 | Website store code is the audited version | The contract that stores every on-chain website file still runs the reviewed code. |
| C06 | Payment contract code is the audited version | The contract that records paid names and domains still runs the reviewed code. |
| C07 | Owners and admin keys unchanged | Nobody has quietly handed control of the core contracts to a new address. |
| C08 | Transistor code unchanged | The code behind transistors (the building blocks of circuits) is the same as when monitoring started. |
| C09 | Processor factory is sealed | Once sealed, nobody can change how processors work. Until then, the owner still can. |
| C10 | Every processor is genuine | Each numbered processor is a real, unique contract created by the official factory and running the official circuit code. |
| C11 | Numbering is append-only | Processor numbers and circuit numbers only ever grow. Nothing was renumbered or erased. |
| C12 | Every opened container belongs to the right circuit | Each website container really is the wallet of the circuit whose name points to it, so names can't be hijacked. |
| C13 | Website files match their on-chain fingerprints | Every byte we re-read hashes to exactly the fingerprint its owner published. |
| C14 | Paid-name records are consistent | Each container's "paid until" date and its live/not-live status tell the same story. |
| C15 | No surprise upgrades or ownership changes | Nobody has swapped the code or the owner of a core contract, even briefly. |
| C16 | Event history matches current state | Every "container opened" and "file written" event points at a real, correctly derived container. |

PASS means fine. WARN means a real fact you should know about that is not an integrity break. FAIL means a real
integrity problem, and it raises an alert. Exact rules are in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## First results (X Layer block 73,370,207, 2026-10-16)

**14 PASS · 2 WARN · 0 FAIL**

- 339 processors and 8,524 circuits minted. All processors are genuine, use one bytecode and point at the audited circuit beacon.
- 68 opened containers, all derived correctly. 31 DeWEB sites with 417 files (42.4 MB). Every file has been re-hashed:
  416 match their declared SHA-256. The other one is the WARN below.
- OKX and dRPC agreed on the block hash and on about 10,000 reads.
- All four pinned implementations match TapeKit's audited list. Owners, admin slots and contract wiring match the baseline.
- **WARN C09: the factory is not sealed.** `isSealed() = false`. The factory owner `0xb3d8…3138` can still upgrade
  the factory and both beacons, and through them the code of every processor. TapeKit's own docs recommend sealing.
  This is a trust assumption, not an exploit.
- **WARN C13: one unfinished upload.** On `1.2.231.tape`, `programs/program-eb68f0502c83434d/vendor/three/build/three.core.js`
  declares the SHA-256 of the full three.js core file (`9edde002…`). Only its first 24,000-byte chunk was ever stored
  (FileSet on 2026-10-09, tx `0x0113b889…`). The stored bytes hash to `99f24acc…`, so TapeKit correctly refuses this file.
  The site owner needs to finish or re-upload it.
- History: the factory owner changed once after deployment, from the deployer `0x571d…af15` to `0xb3d8…3138`
  at block 71,746,726 (2026-09-27 13:29 UTC). Every `Upgraded` event found so far is from the deployment
  transactions and points at audited code. `monthlyFee` on X Layer is currently 0, so activation is free there.
  24 of 68 containers are live.

## Verify a report yourself

```sh
python3 audit/verify_report.py data/audit_latest.json 75b7f5f61779bad120496e4ecfaaae20784e3d4119bd39247db069bed7205f1a
# block 73370207 0xa101…4c8a
# report sha256 … OK
# signature VALID
```

1. Remove `runtimeSeconds`, `reportSha256`, `history`, `passStreak` and `proof` from the report.
   Serialise the rest with `json.dumps(core, sort_keys=True, separators=(",", ":"))` and take its SHA-256.
2. Check the Ed25519 signature over that 64-character hex string with the public key in [docs/KEYS.md](docs/KEYS.md).
3. Bitcoin timestamp: `data/reports/report_<block>.json` is exactly those bytes, and `report_<block>.json.ots` is its proof.
   Run `ots verify data/reports/report_<block>.json.ots` (`pip install opentimestamps-client`).
4. Don't trust the auditor either. Every value in the report has an address and a block number. Re-read it from any X Layer node.

## Check my circuit

`data/circuit_index.json` (about 46 KB) maps every processor number to `{address, name, circuits}` and every opened
container to `{name, processor, circuitId, live, paidUntil, files, verifiedFiles, verifiedOk}`.
The signature covers it through `lookupSha256`. A dashboard can answer "is `1.2.245.tape` verified?" with one lookup.

## Run it

```sh
pip install pynacl opentimestamps-client pycryptodomex   # signing/timestamping only; the audit itself is pure Python
export TAPEAUDIT_DIR=data
python3 audit/run_audit.py      # ~1.5–2 min with the default budgets
python3 audit/sign_report.py    # needs TAPEOUT_SIGNING_KEY, or creates a local .keys/ed25519.key outside CI
python3 audit/alert_check.py
python3 audit/backfill_logs.py 100   # optional: spend 100 s extending event-history coverage
```

Tuning: `TAPEAUDIT_LOG_BUDGET` (seconds of log scanning per run, default 60) and `TAPEAUDIT_BYTE_BUDGET`
(bytes re-hashed per run, default 16,000,000).

GitHub Actions: `.github/workflows/audit.yml` runs the pipeline, verifies the signature and commits `data/`. It runs
by hand, and you can uncomment the hourly schedule. Add the repository secret `TAPEOUT_SIGNING_KEY` first (see docs/KEYS.md).

## Revenue model

- **Free public monitor.** The dashboard, the signed reports and the circuit lookup stay free for everyone, forever.
  Trust in the monitor is the product.
- **"Verified by TapeOut Audit" badge (paid, per site or project).** A TapeOut project gets an embeddable badge
  that links to its live, signed status: files verified, container derivation, activation. It also gets a monthly
  signed attestation it can show to its users.
- **Alerts tier.** Instant alerts (Telegram, Discord, email or webhook) when a project's files change or fail
  verification, when its container's activation is close to expiry, or when any core contract is upgraded or changes owner.
- **API tier.** JSON API access with higher rate limits for wallets, marketplaces and explorers that want
  "verified" flags inline, plus historical signed reports for disputes.
- **Custom audits.** One-off deep reviews of a project's DeWEB site and its use of TapeOut contracts.

## Roadmap

1. Finish the full event-history backfill. Coverage grows every run and is reported in C15.
2. Public dashboard with charts from `history`, the pass streak, per-site status and the "Check my circuit" box,
   **hosted on X Layer DeWEB itself**, so the monitor is served by the protocol it monitors.
3. The same auditor for BNB Smart Chain and Base (same contracts and the same TapeKit pins, with more independent operators).
4. Per-name activation (`isLive(name, container)`) and DomainBinding event analytics (`Bound`, `ContainerPaid`, `FeeChanged`).
5. Telegram/Discord alert bot and the badge/API service.
6. TapeSend hub monitoring once it is deployed on X Layer.

## Layout

```
audit/        run_audit.py · sign_report.py · alert_check.py · verify_report.py · lib.py · logscan.py · backfill_logs.py · run_pipeline.sh
data/         audit_latest.json · circuit_index.json · audit_history.json · baseline.json · prev_state.json · logscan_state.json · reports/
docs/         METHODOLOGY.md · KEYS.md
```

---

TapeOut Audit is independent. It is not affiliated with TapeOut, HashPort or OKX. A PASS means the checks above held
at the stated block. It is not an endorsement of any project or site.
