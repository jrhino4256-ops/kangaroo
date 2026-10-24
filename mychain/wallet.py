"""Command-line wallet. Keys stay in a local JSON file; nodes only ever see signatures.

    python wallet.py new      [--wallet alice.json]
    python wallet.py address  [--wallet alice.json]
    python wallet.py balance  [--wallet alice.json] [--node URL]
    python wallet.py send ADDRESS AMOUNT [--fee 0.0001] [--wallet alice.json] [--node URL]
"""
import argparse
import json
import os
import sys

from crypto import new_private_key, public_key, address_from_pubkey, is_valid_address


def load_or_create_wallet(path: str):
    if os.path.exists(path):
        with open(path) as f:
            priv = int(json.load(f)["private_key"], 16)
    else:
        priv = new_private_key()
        with open(path, "w") as f:
            json.dump({"private_key": f"{priv:064x}"}, f)
        os.chmod(path, 0o600)
        print(f"created new wallet {path}", file=sys.stderr)
    return priv, address_from_pubkey(public_key(priv))


def main():
    from chain import COIN, Transaction, TxIn, TxOut
    from node import http_json

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["new", "address", "balance", "send"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--wallet", default="wallet.json")
    ap.add_argument("--node", default="http://127.0.0.1:8001")
    ap.add_argument("--fee", type=float, default=0.0001)
    a = ap.parse_args()

    if a.command == "new" and os.path.exists(a.wallet):
        sys.exit(f"{a.wallet} already exists")
    priv, me = load_or_create_wallet(a.wallet)

    if a.command in ("new", "address"):
        print(me)
    elif a.command == "balance":
        r = http_json(f"{a.node}/balance/{me}")
        print(f"{me}: {r['coins']:.8f} coins")
    elif a.command == "send":
        if len(a.args) != 2:
            sys.exit("usage: wallet.py send ADDRESS AMOUNT")
        to, amount = a.args[0], round(float(a.args[1]) * COIN)
        fee = round(a.fee * COIN)
        if not is_valid_address(to):
            sys.exit(f"invalid address: {to}")
        picked, total = [], 0
        for u in http_json(f"{a.node}/utxos/{me}")["utxos"]:
            picked.append(TxIn(u["txid"], u["index"]))
            total += u["amount"]
            if total >= amount + fee:
                break
        if total < amount + fee:
            sys.exit(f"insufficient funds: have {total / COIN:.8f}")
        outputs = [TxOut(amount, to)]
        if total - amount - fee:
            outputs.append(TxOut(total - amount - fee, me))
        tx = Transaction(picked, outputs)
        tx.sign_inputs(priv)
        r = http_json(f"{a.node}/tx", {"tx": tx.to_dict()})
        print(r.get("txid") or r)


if __name__ == "__main__":
    main()
