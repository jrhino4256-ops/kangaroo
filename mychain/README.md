# MyChain: a small Bitcoin-style blockchain

A complete working cryptocurrency in about 1,000 lines of plain Python 3.10+. It needs no dependencies.
It uses the same building blocks as Bitcoin, scaled down so you can run a network on a laptop
and read every line.

| File | What it does |
|---|---|
| `crypto.py` | SHA-256d, secp256k1 ECDSA signatures, Base58Check `1…` addresses (identical to Bitcoin's) |
| `chain.py` | Transactions, UTXO set, merkle trees, blocks, proof-of-work, difficulty retargeting, halving, most-work chain selection and reorgs, mempool |
| `node.py` | Full node over HTTP: validates, mines, stores blocks, gossips blocks/transactions to peers, syncs |
| `wallet.py` | CLI wallet: create keys, check balance, sign and send payments |
| `test_chain.py` | Tests for the consensus rules (double spends, forged signatures, greedy miners, reorgs…) |

## Try it

```bash
cd mychain
python3 -m unittest test_chain          # all rules tested, ~15s

# terminal 1: a mining node
python3 node.py --port 8001 --mine --wallet alice.json --datadir data1

# terminal 2: a second miner that joins the network
python3 node.py --port 8002 --mine --wallet miner2.json --peer http://127.0.0.1:8001

# terminal 3: use the wallet
python3 wallet.py balance --wallet alice.json
python3 wallet.py new --wallet bob.json            # prints bob's address
python3 wallet.py send <BOB_ADDRESS> 12.5 --wallet alice.json
python3 wallet.py balance --wallet bob.json --node http://127.0.0.1:8002
```

Node HTTP API: `GET /info`, `/chain`, `/block/<hash>`, `/balance/<addr>`, `/utxos/<addr>`, `/mempool`;
`POST /tx`, `/block`, `/peers`.

## Rules (and how they compare to Bitcoin)

| | MyChain | Bitcoin |
|---|---|---|
| Block time target | 10 s | 10 min |
| Retarget every | 20 blocks (max 4× change) | 2016 blocks (max 4×) |
| Reward | 50 coins, halving every 210 blocks | 50 BTC, halving every 210,000 |
| Max supply | ~21,000 coins | ~21,000,000 BTC |
| Units | 1 coin = 100,000,000 base units | 1 BTC = 100,000,000 sats |
| Chain choice | most cumulative work | most cumulative work |
| Timestamps | > median of last 11, < now + 2h | same |

To change the economics, edit the constants at the top of `chain.py`. A different
`GENESIS_MESSAGE` gives a different, incompatible chain.

## Simplifications (do not put real value on this)

- **Pure-Python crypto is slow and not constant-time.** A real coin uses libsecp256k1.
- **No scripting language.** Every output pays to an address (like Bitcoin's P2PKH). Each input
  signs the whole transaction (like `SIGHASH_ALL`).
- **JSON wire format and HTTP gossip** instead of Bitcoin's binary P2P protocol. Sync downloads
  the peer's full chain, and reorgs replay from genesis. Both are fine for thousands of blocks,
  not millions.
- **No DoS protection, peer banning, or transaction fee market.** Any node you connect to can
  waste your CPU.
- Wallet files hold an **unencrypted private key**.

## Ideas for next steps

Merkle proofs for light clients · headers-first sync · a small script language (multisig, timelocks) ·
a block explorer web page · replacing the crypto with `coincurve` for 100× faster verification.
