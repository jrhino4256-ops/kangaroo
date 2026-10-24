"""A full node: validates, mines, stores and gossips blocks and transactions over HTTP.

    python node.py --port 8001 --mine --wallet miner.json
    python node.py --port 8002 --peer http://127.0.0.1:8001
"""
import argparse
import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import chain as C
from chain import Block, Blockchain, OrphanBlock, Transaction, ValidationError, mine, COIN
from wallet import load_or_create_wallet

EXPLORER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "explorer.html")
PAGE_HEAD = (b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
             b'<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>')
CHAIN_PARAMS = {"coin": COIN, "maxTarget": hex(C.MAX_TARGET), "reward": C.INITIAL_REWARD,
                "halving": C.HALVING_INTERVAL, "adjustInterval": C.ADJUST_INTERVAL,
                "targetBlockTime": C.TARGET_BLOCK_TIME}

# Talk to peers directly, never through an HTTP proxy from the environment.
_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_json(url: str, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with _http.open(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:  # the node explains why it rejected us
        return json.loads(e.read())


class Node:
    def __init__(self, url: str, datadir: str | None):
        self.url = url
        self.chain = Blockchain()
        self.lock = threading.RLock()
        self.peers = set()
        self.tip_changed = threading.Event()
        self.blockfile = os.path.join(datadir, "blocks.jsonl") if datadir else None
        if self.blockfile and os.path.exists(self.blockfile):
            with open(self.blockfile) as f:
                for line in f:
                    try:
                        self.chain.add_block(Block.from_dict(json.loads(line)))
                    except (ValidationError, OrphanBlock):
                        pass
            print(f"loaded {self.chain.height} blocks from {self.blockfile}")

    def log(self, msg):
        print(f"[{self.url}] {msg}", flush=True)

    # --- gossip

    def broadcast(self, path: str, payload: dict, skip: str | None = None):
        def send(peer):
            try:
                http_json(peer + path, payload)
            except Exception:
                pass
        for peer in list(self.peers):
            if peer != skip:
                threading.Thread(target=send, args=(peer,), daemon=True).start()

    def connect(self, peer: str):
        peer = peer.rstrip("/")
        if peer == self.url or peer in self.peers:
            return
        try:
            their_peers = http_json(peer + "/peers", {"url": self.url})["peers"]
        except Exception as e:
            self.log(f"could not reach {peer}: {e.__class__.__name__}")
            return
        self.peers.add(peer)
        self.log(f"connected to {peer}")
        self.sync(peer)
        for p in their_peers:
            self.connect(p)

    def sync(self, peer: str):
        """Download a peer's best chain and adopt it if it has more work."""
        try:
            blocks = http_json(peer + "/chain", timeout=60)["blocks"]
        except Exception as e:
            self.log(f"sync with {peer} failed: {e}")
            return
        for d in blocks:
            try:
                self.receive_block(Block.from_dict(d), source=peer, relay=False)
            except ValidationError as e:
                self.log(f"rejected block from {peer}: {e}")
                return

    # --- incoming data

    def receive_block(self, block: Block, source: str | None = None, relay=True) -> bool:
        with self.lock:
            known = block.hash in self.chain.blocks
            try:
                became_tip = self.chain.add_block(block)
            except OrphanBlock:
                if source:
                    threading.Thread(target=self.sync, args=(source,), daemon=True).start()
                return False
            if not known and self.blockfile:
                with open(self.blockfile, "a") as f:
                    f.write(json.dumps(block.to_dict()) + "\n")
            if became_tip:
                self.tip_changed.set()
                self.log(f"new tip #{self.chain.height} {block.hash[:16]}… ({len(block.txs) - 1} txs)")
        if became_tip and relay:
            self.broadcast("/block", {"block": block.to_dict(), "from": self.url}, skip=source)
        return became_tip

    def receive_tx(self, tx: Transaction, source: str | None = None) -> bool:
        with self.lock:
            new = self.chain.add_transaction(tx)
        if new:
            self.tip_changed.set()  # restart mining so the new transaction gets included
            self.log(f"mempool += {tx.txid[:16]}…")
            self.broadcast("/tx", {"tx": tx.to_dict(), "from": self.url}, skip=source)
        return new

    # --- mining

    def mine_forever(self, address: str):
        self.log(f"mining to {address}")
        while True:
            with self.lock:
                template = self.chain.block_template(address)
                self.tip_changed.clear()
            block = mine(template, should_stop=self.tip_changed.is_set)
            if block is None:
                continue  # someone else found a block (or the mempool changed); start over
            try:
                self.receive_block(block)
            except ValidationError as e:
                self.log(f"mined an invalid block?! {e}")


def make_handler(node: Node):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, obj, status=200):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/explorer"):  # the block explorer web page
                with open(EXPLORER, "rb") as f:
                    body = PAGE_HEAD + f.read() + b"</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            c = node.chain
            parts = self.path.strip("/").split("/")
            with node.lock:
                if parts == ["info"]:
                    tip = c.blocks[c.tip]
                    return self.reply({"height": c.height, "tip": c.tip,
                                       "difficulty": (2 ** 240) / tip.target,
                                       "mempool": len(c.mempool), "peers": sorted(node.peers)})
                if parts == ["chain"]:
                    return self.reply({"blocks": [{**b.to_dict(), "hash": b.hash} for b in c.best_chain()],
                                       "params": CHAIN_PARAMS})
                if parts[0] == "block" and len(parts) == 2 and parts[1] in c.blocks:
                    return self.reply(c.blocks[parts[1]].to_dict())
                if parts[0] == "balance" and len(parts) == 2:
                    sats = c.balance(parts[1])
                    return self.reply({"address": parts[1], "balance": sats, "coins": sats / COIN})
                if parts[0] == "utxos" and len(parts) == 2:
                    return self.reply({"utxos": [{"txid": t, "index": i, "amount": o.amount}
                                                 for (t, i), o in c.spendable_utxos(parts[1])]})
                if parts == ["mempool"]:
                    return self.reply({"txs": [t.to_dict() for t in c.mempool.values()]})
            self.reply({"error": "not found"}, 404)

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                path = self.path.strip("/")
                if path == "block":
                    accepted = node.receive_block(Block.from_dict(body["block"]), body.get("from"))
                    return self.reply({"accepted": accepted})
                if path == "tx":
                    tx = Transaction.from_dict(body["tx"])
                    node.receive_tx(tx, body.get("from"))
                    return self.reply({"txid": tx.txid})
                if path == "peers":
                    if body.get("url"):
                        threading.Thread(target=node.connect, args=(body["url"],), daemon=True).start()
                    return self.reply({"peers": sorted(node.peers)})
            except ValidationError as e:
                return self.reply({"error": str(e)}, 400)
            except (KeyError, TypeError, ValueError, AttributeError) as e:
                return self.reply({"error": f"malformed request: {e}"}, 400)
            self.reply({"error": "not found"}, 404)

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--peer", action="append", default=[], help="URL of a node to connect to")
    ap.add_argument("--mine", action="store_true", help="mine blocks")
    ap.add_argument("--wallet", default="wallet.json", help="wallet whose address receives mining rewards")
    ap.add_argument("--datadir", help="directory to store blocks in (default: memory only)")
    args = ap.parse_args()

    if args.datadir:
        os.makedirs(args.datadir, exist_ok=True)
    node = Node(f"http://{args.host}:{args.port}", args.datadir)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(node))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    node.log(f"listening, genesis {node.chain.genesis_hash[:16]}…")
    node.log(f"block explorer: http://{args.host}:{args.port}/")
    def keep_connected():  # retry seed peers that were down when we started
        while True:
            for p in args.peer:
                node.connect(p)
            threading.Event().wait(5)
    threading.Thread(target=keep_connected, daemon=True).start()
    if args.mine:
        _, address = load_or_create_wallet(args.wallet)
        node.mine_forever(address)
    else:
        threading.Event().wait()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
