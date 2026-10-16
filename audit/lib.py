"""TapeOut Audit - small, dependency-free JSON-RPC + ABI helpers for X Layer (chainId 196).
Pure Python (urllib); keccak from pycryptodomex in .pylib (falls back to pure-python keccak)."""
import json, time, threading, urllib.request, urllib.error, os, sys, pathlib
from concurrent.futures import ThreadPoolExecutor

HERE = pathlib.Path(__file__).resolve().parent
for p in (HERE / ".pylib", HERE.parent / "shield" / ".pylib"):
    if p.exists():
        sys.path.insert(0, str(p))
try:
    from Cryptodome.Hash import keccak as _kc
    def keccak(b: bytes) -> bytes:
        k = _kc.new(digest_bits=256); k.update(b); return k.digest()
except Exception:  # pure-python fallback (Keccak-f[1600], original padding 0x01)
    _RC = [0x1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081,
           0x8000000000008009, 0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B,
           0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800A,
           0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008]
    _R = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    M = (1 << 64) - 1
    def _rol(x, n): return ((x << n) | (x >> (64 - n))) & M if n else x
    def _f(A):
        for rc in _RC:
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
            A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = _rol(A[x][y], _R[x][y])
            A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            A[0][0] ^= rc
        return A
    def keccak(b: bytes) -> bytes:
        rate = 136; b = bytearray(b) + b"\x01"
        while len(b) % rate: b.append(0)
        b[-1] |= 0x80
        A = [[0] * 5 for _ in range(5)]
        for off in range(0, len(b), rate):
            for i in range(rate // 8):
                A[i % 5][i // 5] ^= int.from_bytes(b[off + 8 * i: off + 8 * i + 8], "little")
            A = _f(A)
        return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))

def sel(sig: str) -> str: return keccak(sig.encode())[:4].hex()
def topic(sig: str) -> str: return "0x" + keccak(sig.encode()).hex()

# ---------- ABI ----------
def enc_uint(n): return "%064x" % int(n)
def enc_addr(a): return "0" * 24 + a.lower().replace("0x", "")
def enc_call(sig, *args):
    """Encode a call. Supports address, uint*, string args (head/tail)."""
    types = sig[sig.index("(") + 1:-1].split(",") if sig.split("(")[1] != ")" else []
    head, tail = [], b""
    nhead = 32 * len(types)
    for t, v in zip(types, args):
        if t == "string":
            head.append(enc_uint(nhead + len(tail)))
            bs = v.encode() if isinstance(v, str) else v
            tail += int(len(bs)).to_bytes(32, "big") + bs + b"\x00" * ((32 - len(bs) % 32) % 32)
        elif t == "address": head.append(enc_addr(v))
        else: head.append(enc_uint(v))
    return "0x" + sel(sig) + "".join(head) + tail.hex()

def words(h):
    b = bytes.fromhex(h[2:] if h.startswith("0x") else h)
    return b
def dec_uint(h, i=0): b = words(h); return int.from_bytes(b[32 * i:32 * i + 32], "big")
def dec_addr(h, i=0): b = words(h); return "0x" + b[32 * i + 12:32 * i + 32].hex()
def dec_bool(h): return dec_uint(h) != 0
def dec_bytes_at(b, off):
    n = int.from_bytes(b[off:off + 32], "big"); return b[off + 32: off + 32 + n]
def dec_string(h, i=0):
    b = words(h); off = int.from_bytes(b[32 * i:32 * i + 32], "big")
    return dec_bytes_at(b, off).decode("utf-8", "replace")
def dec_bytes(h):
    b = words(h); off = int.from_bytes(b[0:32], "big"); return dec_bytes_at(b, off)
def dec_string_array(h):
    b = words(h); off = int.from_bytes(b[0:32], "big"); n = int.from_bytes(b[off:off + 32], "big")
    base = off + 32; out = []
    for k in range(n):
        o = int.from_bytes(b[base + 32 * k: base + 32 * k + 32], "big")
        out.append(dec_bytes_at(b, base + o).decode("utf-8", "replace"))
    return out

# ---------- RPC ----------
class RpcError(Exception): pass

class Node:
    def __init__(self, url, operator, max_batch, max_log_range):
        self.url, self.operator, self.max_batch, self.max_log_range = url, operator, max_batch, max_log_range
        self.calls = 0; self.errors = 0; self.lock = threading.Lock()
    def _post(self, payload, timeout=40):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=data, headers={"content-type": "application/json", "user-agent": "tapeout-audit/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read()[:2000]
            try: return json.loads(body)
            except Exception: raise RpcError(f"HTTP {e.code}: {body[:200]!r}")
    def batch(self, reqs, retries=4):
        """reqs: list of (method, params). Returns list of {'result'|'error'} in order. Splits by max_batch."""
        out = []
        for i in range(0, len(reqs), self.max_batch):
            chunk = reqs[i:i + self.max_batch]
            payload = [{"jsonrpc": "2.0", "id": k, "method": m, "params": p} for k, (m, p) in enumerate(chunk)]
            for attempt in range(retries):
                try:
                    with self.lock: self.calls += 1
                    resp = self._post(payload if len(payload) > 1 else payload[0])
                    if isinstance(resp, dict) and "id" not in resp: raise RpcError(str(resp)[:200])
                    if isinstance(resp, dict): resp = [resp]
                    byid = {r.get("id"): r for r in resp}
                    res = [byid.get(k, {"error": {"message": "missing"}}) for k in range(len(chunk))]
                    # retry on rate-limit style errors
                    if any("error" in r and _transient(r["error"]) for r in res): raise RpcError("transient: " + str([r["error"] for r in res if "error" in r][0])[:160])
                    out.extend(res); break
                except (urllib.error.URLError, TimeoutError, RpcError, ConnectionError, json.JSONDecodeError, OSError) as e:
                    with self.lock: self.errors += 1
                    if attempt == retries - 1: raise RpcError(f"{self.url}: {e}")
                    time.sleep(0.8 * (attempt + 1) ** 2)
        return out
    def one(self, method, params):
        r = self.batch([(method, params)])[0]
        if "error" in r: raise RpcError(f"{self.url} {method}: {r['error']}")
        return r["result"]

def _transient(err):
    m = json.dumps(err).lower()
    return any(s in m for s in ("rate", "limit exceeded", "too many", "timeout", "temporar", "busy", "capacity", "429", "missing"))

NODES = {
    "okx_a": Node("https://rpc.xlayer.tech", "okx", 10, 100),
    "okx_b": Node("https://xlayerrpc.okx.com", "okx", 10, 100),
    "drpc": Node("https://xlayer.drpc.org", "drpc", 3, None),
}

def pmap(fn, items, workers=8):
    with ThreadPoolExecutor(workers) as ex: return list(ex.map(fn, items))

# ---------- Multicall3 (0xcA11...CA11, verified deployed on X Layer) ----------
MULTICALL3 = "0xca11bde05977b3631167028862be2a173976ca11"
def enc_aggregate3(calls):
    """calls: list of (target, calldata_hex). allowFailure=true for all."""
    n = len(calls)
    head = "0" * 62 + "20" + enc_uint(n)
    elems = []
    for tgt, data in calls:
        d = bytes.fromhex(data[2:])
        e = enc_addr(tgt) + enc_uint(1) + enc_uint(96) + enc_uint(len(d)) + (d + b"\x00" * ((32 - len(d) % 32) % 32)).hex()
        elems.append(e)
    offs, pos = [], 32 * n
    for e in elems:
        offs.append(enc_uint(pos)); pos += len(e) // 2
    return "0x" + sel("aggregate3((address,bool,bytes)[])") + head + "".join(offs) + "".join(elems)
def dec_aggregate3(h):
    b = words(h); off = int.from_bytes(b[0:32], "big"); n = int.from_bytes(b[off:off + 32], "big")
    base = off + 32; out = []
    for k in range(n):
        o = base + int.from_bytes(b[base + 32 * k: base + 32 * k + 32], "big")
        ok = int.from_bytes(b[o:o + 32], "big") != 0
        bo = o + int.from_bytes(b[o + 32:o + 64], "big")
        rd = dec_bytes_at(b, bo)
        out.append((ok, "0x" + rd.hex()))
    return out
def multicall(node, calls, block, chunk=250):
    """Returns list of (ok, returnhex). Chunks into several aggregate3 eth_calls, batched per node limit."""
    reqs, spans = [], []
    for i in range(0, len(calls), chunk):
        reqs.append(("eth_call", [{"to": MULTICALL3, "data": enc_aggregate3(calls[i:i + chunk])}, block]))
    res = node.batch(reqs)
    out = []
    for k, r in enumerate(res):
        part = calls[k * chunk:(k + 1) * chunk]
        if "error" in r:
            if "too large" in json.dumps(r["error"]) and len(part) > 1:  # node response cap: split and retry
                out.extend(multicall(node, part, block, chunk=max(1, len(part) // 2))); continue
            raise RpcError(f"{node.url} multicall: {r['error']}")
        out.extend(dec_aggregate3(r["result"]))
    return out
