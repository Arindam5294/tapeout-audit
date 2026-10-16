"""Incremental event-log scanner for TapeOut core contracts on X Layer.

Public X Layer nodes only answer eth_getLogs for <=100-block windows (OKX: "block range greater than 100 max";
dRPC free: 101) and rate-limit hard, so history is scanned in 100-block windows, spread over all nodes, and the
scanned ranges are remembered in logscan_state.json. Each run first covers new blocks up to the pinned block,
then spends the rest of its time budget backfilling toward the deployment block. A window only counts as scanned
when a node returned a result for it (errors are re-queued), so coverage is never overstated.
"""
import json, time, threading, collections, pathlib, fcntl
from lib import NODES, Node, RpcError

WIN = 100
_TW = Node("https://196.rpc.thirdweb.com", "okx-forward", 1, 100)
# (node, windows per request, pause after success). Two threads on each OKX host.
PLAN = [(NODES["okx_a"], 1, 0.1), (NODES["okx_a"], 1, 0.1), (NODES["okx_b"], 1, 0.1), (NODES["okx_b"], 1, 0.1),
        (NODES["drpc"], 3, 0.2), (_TW, 1, 0.2)]

def merge(rs):
    rs = sorted([list(r) for r in rs]); out = []
    for a, b in rs:
        if out and a <= out[-1][1] + 1: out[-1][1] = max(out[-1][1], b)
        else: out.append([a, b])
    return out

def gaps(rs, lo, hi):
    """Unscanned sub-ranges of [lo,hi] given merged scanned ranges."""
    out, cur = [], lo
    for a, b in rs:
        if b < cur: continue
        if a > hi: break
        if a > cur: out.append([cur, min(a - 1, hi)])
        cur = max(cur, b + 1)
    if cur <= hi: out.append([cur, hi])
    return out

def scan(state_path, addresses, deploy_block, pinned, budget_s, new_first=True, log=print):
    p = pathlib.Path(state_path)
    lockf = open(str(p) + ".lock", "w")
    fcntl.flock(lockf, fcntl.LOCK_EX)  # one scanner at a time; a concurrent writer would lose the other's progress
    st = json.loads(p.read_text()) if p.exists() else {"deployBlock": deploy_block, "scanned": [], "logs": []}
    addrs_key = sorted(a.lower() for a in addresses)
    if st.get("addresses") not in (None, addrs_key) or st.get("deployBlock") not in (None, deploy_block):
        log("logscan: watched address set changed, restarting coverage")
        st = {"deployBlock": deploy_block, "scanned": [], "logs": []}
    st["addresses"] = addrs_key
    st["deployBlock"] = deploy_block
    scanned = merge(st["scanned"])
    todo_ranges = gaps(scanned, deploy_block, pinned)
    # newest first: new blocks matter most, then backfill downward
    windows = []
    for a, b in sorted(todo_ranges, key=lambda r: -r[1]):
        hi = b
        while hi >= a:
            lo = max(a, hi - WIN + 1); windows.append((lo, hi)); hi = lo - 1
    # priority: (1) blocks newer than anything scanned, (2) the first 5,000 blocks after deployment
    # (initial Upgraded/OwnershipTransferred events establish the baseline), (3) backfill newest -> oldest
    top = max((b for a, b in scanned), default=deploy_block - 1)
    early = [w for w in windows if w[0] > top] + [w for w in windows if w[1] < deploy_block + 5000 and w[0] <= top]
    es = set(early)
    windows = early + [w for w in windows if w not in es]
    q = collections.deque(windows)  # failed windows go back to the FRONT so coverage stays contiguous
    done, found, lock = [], [], threading.Lock()
    t_end = time.time() + budget_s
    addrs = [a.lower() for a in addresses]
    # per-node pacing (measured 2026-10-16): OKX ~4-5 getLogs/s per host, dRPC ~7/s with batch 3
    plan = PLAN
    stats = {}
    def worker(node, bsz, pause):
        backoff = 0.5
        while time.time() < t_end:
            ws = []
            with lock:
                for _ in range(bsz):
                    if q: ws.append(q.popleft())
            if not ws: return
            payload = [{"jsonrpc": "2.0", "id": k, "method": "eth_getLogs",
                        "params": [{"fromBlock": hex(lo), "toBlock": hex(hi), "address": addrs}]} for k, (lo, hi) in enumerate(ws)]
            try:
                r = node._post(payload if len(payload) > 1 else payload[0], timeout=min(15, max(3, t_end - time.time() + 3)))
                r = r if isinstance(r, list) else [r]
                byid = {x.get("id"): x for x in r}
            except Exception:
                byid = {}
            bad = 0
            for k, w in enumerate(ws):
                x = byid.get(k)
                if x and "result" in x and isinstance(x["result"], list):
                    with lock: done.append(w); found.extend(x["result"]); stats[node.url] = stats.get(node.url, 0) + 1
                else:
                    with lock: q.appendleft(w)
                    bad += 1
            if bad: time.sleep(min(backoff, max(0, t_end - time.time()))); backoff = min(backoff * 2, 8)
            else: backoff = 0.5; time.sleep(pause)
    ths = [threading.Thread(target=worker, args=a, daemon=True) for a in plan]
    for t in ths: t.start()
    for t in ths: t.join(timeout=max(1, t_end - time.time() + 20))
    with lock:
        scanned = merge(scanned + [list(w) for w in done])
        seen = {(l["blockNumber"], l["logIndex"]) for l in st["logs"]}
        for l in found:
            k = (int(l["blockNumber"], 16), int(l["logIndex"], 16))
            if k in seen: continue
            seen.add(k)
            st["logs"].append({"blockNumber": k[0], "logIndex": k[1], "address": l["address"].lower(),
                               "topics": l["topics"], "data": l["data"], "tx": l["transactionHash"]})
    st["logs"].sort(key=lambda l: (l["blockNumber"], l["logIndex"]))
    st["scanned"] = scanned
    tmp = pathlib.Path(str(p) + ".tmp"); tmp.write_text(json.dumps(st, separators=(",", ":"))); tmp.replace(p)
    lockf.close()
    total = pinned - deploy_block + 1
    cov = sum(min(b, pinned) - max(a, deploy_block) + 1 for a, b in scanned if b >= deploy_block and a <= pinned)
    log(f"logscan per node: {stats}")
    log(f"logscan: +{len(done)} windows this run, coverage {cov}/{total} blocks ({100*cov/total:.1f}%), {len(st['logs'])} logs stored")
    return st, cov, total
