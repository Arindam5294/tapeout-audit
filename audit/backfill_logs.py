"""One-off history backfill: scan event logs for N seconds (default 100). Usage: python3 audit/backfill_logs.py 100"""
import sys,time,os
from lib import *
from logscan import scan
ADDR=["0x1f09daefa827f02cbb40967cc91b259763760761","0x536add8f30f03b69f6fbf29d425a816a0dc50106","0xd6efb7adcc9c83dc4924ad56f6a8e4e969b9adb6","0x68809fd2fb343aa57d0aeb7f33defe477c9666f9","0xf70d1ed4f62cf3780157b0b421b7e2f45bd0991c","0x1059ad62cabb6a6925bb65aa617300556c60a51b"]
pinned=int(sys.argv[2]) if len(sys.argv)>2 else int(NODES["drpc"].one("eth_blockNumber",[]),16)-2
t=time.time()
st,c,tot=scan(os.path.join(os.environ.get("TAPEAUDIT_DIR", os.path.dirname(os.path.abspath(__file__))), "logscan_state.json"),ADDR,70995047,pinned,float(sys.argv[1]) if len(sys.argv)>1 else 100)
print(time.time()-t, {k:sum(1 for l in st['logs'] if l['topics'][0]==k) for k in set(l['topics'][0] for l in st['logs'])})
print("nodes", {k:(n.calls,n.errors) for k,n in NODES.items()})
