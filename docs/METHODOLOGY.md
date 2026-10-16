# TapeOut Audit methodology

TapeOut Audit is an independent, read-only auditor. It never signs a transaction, never holds funds and needs no
API keys. Everything below can be reproduced with public X Layer nodes and the scripts in `audit/`.

## 1. Scope

| Contract | Address (X Layer, chainId 196) | Kind |
|---|---|---|
| Processor factory | `0x1f09daefa827f02cbb40967cc91b259763760761` | ERC-1967 / UUPS proxy |
| Circuit beacon | `0xf70d1ed4f62cf3780157b0b421b7e2f45bd0991c` | UpgradeableBeacon, the code of every processor NFT |
| Transistor beacon | `0x1059ad62cabb6a6925bb65aa617300556c60a51b` | UpgradeableBeacon |
| Container opener | `0x536add8f30f03b69f6fbf29d425a816a0dc50106` | plain contract, no proxy (implementation slot is empty) |
| SiteRegistry (DeWEB file store) | `0xd6efb7adcc9c83dc4924ad56f6a8e4e969b9adb6` | ERC-1967 / UUPS proxy |
| DomainBinding (activation / payments) | `0x68809fd2fb343aa57d0aeb7f33defe477c9666f9` | ERC-1967 / UUPS proxy |
| Processors 0..N-1 | `factory.cpuAt(i)` | BeaconProxy (ERC-721), one per processor |
| Containers | `opener.accountOf(processor, #ID)` | ERC-6551 accounts |

The pinned (audited) implementations come from TapeKit `kernel/src/config.js` and SPEC Appendix B:
factory `0x7495…d17b`, circuit `0x977f…29b2`, SiteRegistry `0xa85c…a45f`, DomainBinding `0x5ebf…47df`.
TapeKit publishes no expected value for the transistor beacon, so its implementation is baseline-pinned:
the value seen on the first run (`0x265bf10fab9ddec0ee0a649c6b9db845f1b9a06b`) must never change.

## 2. One pinned block, two independent operators

1. Ask OKX (`rpc.xlayer.tech`) and dRPC (`xlayer.drpc.org`) for their head. Set the pinned block P = min(heads) − 2.
   OKX runs the X Layer sequencer. dRPC is the only other independent public operator. thirdweb forwards to OKX,
   so it does not count as a second opinion (TapeKit config notes).
2. Every read uses block P, never `latest`, so the whole report describes one consistent chain state.
3. The full snapshot (implementation and admin slots, 18 governance getters, every `cpuAt`, `nextId`, `isCPU`,
   `name`, every `isOpened` over all circuit ids, every `accountOf` and `pathCount`) is read from **both**
   operators. The two copies are compared section by section with SHA-256. About 10,000 reads are compared per run.
4. Reads go through Multicall3 (`0xcA11bde05977b3631167028862bE2a173976CA11`, deployed on X Layer). That is the only
   way to stay under the public nodes' rate limits.

## 3. Selectors

Every selector and event topic is recomputed with keccak-256 at startup and checked against the published value.
The script refuses to run on a mismatch. Selectors not in the brief were found by disassembling the deployed
implementations (PUSH4 scan), resolved with the public signature database, and recomputed locally:

| Function | Selector | Where found |
|---|---|---|
| `nextId()` | `0x61b8ce8c` | circuit implementation. It returns the **last minted #ID (= count)**, because ids start at 1. `ownerOf(nextId)` exists and `ownerOf(nextId+1)` reverts. `totalSupply()` is **not** implemented. |
| `isSealed()` | `0x631f9852` | factory implementation |
| `circuitBeacon()` / `transistorBeacon()` | `0xddcb22fa` / `0xb3746a25` | factory implementation |
| `isOpenedContainer(address)` | `0x8951bab2` | SiteRegistry implementation |
| `opener()` / `registry()` | `0x9c9b4cdb` / `0x7b103999` | SiteRegistry / DomainBinding |
| `pendingOwner()` | `0xe30c3978` | SiteRegistry, DomainBinding (Ownable2Step). The factory reverts (plain Ownable). |

Events: `Upgraded(address)` `0xbc7cd75a…`, `OwnershipTransferred` `0x8be0079c…`, `FileSet` `0x13b9b0f0…`,
`Opened(address,uint256,address,address)` `0x1d2e18a3…`, `CPUCreated(…)` `0x2e8868f1…`,
`OperatorSet` `0xa0bb1a67…`, `FallbackSet` `0x47296cb5…`, `Bound` `0x25694298…`, `ContainerPaid` `0x2201bd4c…`.

## 4. The checks

Each check returns PASS, WARN or FAIL.

- **FAIL** means a real integrity problem. It triggers an alert.
- **WARN** means a real fact a user should know about that is not an integrity break, or a cross-check that could not run.
- A WARN or FAIL is never used for "the auditor had a bug". When a node is unreachable, the check says so and does not guess.

| ID | Check | PASS when | WARN | FAIL |
|---|---|---|---|---|
| C01 | Two operators agree | OKX and dRPC give the same hash for P and identical snapshots | only one operator answered | any difference |
| C02 | Data is fresh | block P is less than 300 s old (TapeKit `maxBlockAgeSeconds`) | – | older |
| C03 | Factory implementation pinned | ERC-1967 slot ∈ audited list | – | otherwise |
| C04 | Circuit code pinned | `factory.circuitBeacon()` is the expected beacon and its `implementation()` ∈ list | – | otherwise |
| C05 | SiteRegistry implementation pinned | slot ∈ list | – | otherwise |
| C06 | DomainBinding implementation pinned | slot ∈ list | – | otherwise |
| C07 | Owners / admin unchanged | 17 control values (owners, pending owners, admin slots, cross-contract wiring) equal `baseline.json` | – | any change, or wiring broken |
| C08 | Transistor code unchanged | the transistor beacon implementation equals the baseline | – | changed |
| C09 | Factory sealed | `isSealed()` is true | not sealed: the owner can still upgrade every processor's code | – |
| C10 | Every processor genuine | for i in 0..N-1: unique address, `isCPU`, code present, ERC-1967 beacon slot = circuit beacon | – | any failure |
| C11 | Numbering append-only | count never shrinks, earlier addresses never move, no processor's `nextId` decreases | – | any violation |
| C12 | Container derivation | every opened container: `token()` = (196, processor, #ID), `accountOf` round-trips, registry `isOpenedContainer` is true. A non-container control returns false. | – | any mismatch |
| C13 | Website file integrity | re-read bytes match the declared size and SHA-256. `fileInfo` is identical on both operators. | unfinished upload (see below), or the dRPC fileInfo differs | stored bytes contradict the declared size/hash in a file that is not an unfinished upload |
| C14 | Paid-name records consistent | `isContainerLive` ⇔ `containerPaidUntil > block time` | inconsistency | – |
| C15 | No surprise upgrades / ownership changes | in all scanned history, every `Upgraded` points at audited code, nothing changed after the baseline, and the newest 3,600 blocks or more are scanned without gaps | ownership/admin event after the baseline, or the recent window is not covered | `Upgraded` to unaudited code, even if it was later reverted |
| C16 | Event history matches state | every `Opened` event maps to a live, correctly derived container. Every `FileSet` container is an opened container. | – | mismatch |

### Unfinished uploads (C13)

`putFile` stores the first chunk (24,000 bytes or less) together with the SHA-256 the owner declares for the
**whole** file. Further chunks arrive with `appendChunk`. When the stored size is an exact multiple of 24,000,
equal to `chunkCount × 24,000`, and the stored bytes do not hash to the declared value, the owner stopped
uploading part-way. TapeKit readers will refuse that file, which is correct fail-closed behaviour. TapeOut Audit
reports it as a WARN with the site name and path. Any other hash or size mismatch is a FAIL.

## 5. Website files: rotating byte budget

- All sites are found by enumeration (`isOpened` on every circuit id, then `pathCount`), not only from events.
  New sites are therefore never missed.
- Every run re-reads `fileInfo` for every file on both operators.
- Bytes are fetched with `read()` up to 96 KB, or with `readRange` in 96 KB segments above that (the same rule as TapeKit).
  Every byte is pinned to block P.
- Each run re-hashes up to `TAPEAUDIT_BYTE_BUDGET` bytes (default 16 MB). The order is: earlier failures first,
  then new or changed files (where size, hash or `updatedAt` differ from the last verified version), then the files verified longest ago.
  The report gives coverage as the number of files and bytes verified against their **current** version.

## 6. Event history: 100-block windows

Both OKX and the free dRPC tier reject `eth_getLogs` over more than about 100 blocks, and they rate-limit hard,
at roughly 9 windows per second combined. Full history since deployment (block 70,995,047, 2026-09-18 20:41 UTC)
is about 2.4 million blocks. The scanner works as follows:

- Each window counts as scanned only when a node returned a result for it. Failed windows go back to the front of the queue.
- It covers new blocks first, then the first 5,000 blocks after deployment, then backfills from newest to oldest
  within `TAPEAUDIT_LOG_BUDGET` seconds per run. It keeps its progress in `logscan_state.json`.
- When a contract's current owner differs from the last owner seen in scanned events, it binary-searches
  `owner()` over archive state to find the exact block of the change, then fetches that block's logs.
- The report always states the coverage (%) and how many recent blocks were scanned without gaps.

## 7. Signing and timestamping

- `reportCore` is `audit_latest.json` without `runtimeSeconds`, `reportSha256`, `history`, `passStreak` and `proof`.
- Canonical bytes are `json.dumps(core, sort_keys=True, separators=(",", ":"))`, with Python's default ASCII escaping.
- `reportSha256` = SHA-256(canonical bytes). The Ed25519 signature covers the hex string of that hash.
- `reports/report_<block>.json` holds the exact canonical bytes. `report_<block>.json.ots` is its OpenTimestamps
  proof. Each run upgrades the newest 72 pending proofs. The newest proof confirmed on Bitcoin is cached in `reports/confirmed.json`.
- `circuit_index.json` (the "Check my circuit" lookup) is covered by the signature through `lookupSha256`.

## 8. Known limits

- Two operators is the most X Layer offers today. If OKX and dRPC were both wrong in the same way, this audit would be too.
- Until the log backfill reaches 100%, C15 can only speak for the blocks it has scanned. The coverage is printed in the check.
- A file's "declared hash" is whatever its owner declared. "Verified" means the bytes match the chain, not that the site is safe.
- `isContainerLive` is read as published. Activation via `isLive(name, container)` (per-name payments) is not
  enumerated, because names are not discoverable without events.
- Processor names come from `name()`. They are not unique and are for display only (SPEC §B.3).
