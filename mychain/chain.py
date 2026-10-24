"""Core consensus: transactions, blocks, proof-of-work and the UTXO set.

The rules mirror Bitcoin's, scaled down so a laptop can mine:
  * coins live in unspent transaction outputs (UTXOs) locked to an address
  * spending an output needs the matching public key and an ECDSA signature
  * blocks link by hash and must have a header hash below the target
  * the target retargets every ADJUST_INTERVAL blocks toward TARGET_BLOCK_TIME
  * the block reward halves every HALVING_INTERVAL blocks
  * nodes follow the chain with the most cumulative work
"""
import json
import time
from dataclasses import dataclass, field, asdict

from crypto import sha256d, sign, verify, public_key, address_from_pubkey, is_valid_address

COIN = 100_000_000              # smallest units per coin (like satoshis)
INITIAL_REWARD = 50 * COIN
HALVING_INTERVAL = 210          # Bitcoin: 210,000
TARGET_BLOCK_TIME = 10          # seconds; Bitcoin: 600
ADJUST_INTERVAL = 20            # blocks; Bitcoin: 2016
MAX_TARGET = 2 ** 240           # easiest allowed difficulty
MAX_FUTURE_DRIFT = 2 * 60 * 60  # same 2-hour rule as Bitcoin
MAX_BLOCK_TXS = 1000
GENESIS_MESSAGE = "MyChain genesis 24/Oct/2026 - chancellor on brink of second bailout for banks"
GENESIS_TIME = 1792540800  # 2026-10-21 00:00 UTC


class ValidationError(Exception):
    pass


class OrphanBlock(Exception):
    """We do not have this block's parent yet; the caller should sync."""


# ---------------------------------------------------------------- transactions

@dataclass
class TxIn:
    txid: str          # transaction that created the output being spent
    index: int         # which output of that transaction
    pubkey: str = ""   # hex compressed public key of the owner
    sig: str = ""      # hex signature over the transaction's sighash


@dataclass
class TxOut:
    amount: int
    address: str


@dataclass
class Transaction:
    inputs: list
    outputs: list
    coinbase: str = ""  # only set on a block's first transaction (holds the height)

    @property
    def is_coinbase(self) -> bool:
        return not self.inputs

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        return cls([TxIn(**i) for i in d["inputs"]],
                   [TxOut(**o) for o in d["outputs"]],
                   d.get("coinbase", ""))

    def serialize(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    @property
    def txid(self) -> str:
        return sha256d(self.serialize())[::-1].hex()

    def sighash(self) -> bytes:
        """What each input signs: the whole transaction with signatures blanked out."""
        blank = Transaction([TxIn(i.txid, i.index) for i in self.inputs], self.outputs, self.coinbase)
        return sha256d(blank.serialize())

    def sign_inputs(self, priv: int) -> None:
        pub = public_key(priv).hex()
        h = self.sighash()
        sig = sign(priv, h).hex()
        for i in self.inputs:
            i.pubkey, i.sig = pub, sig


def make_coinbase(height: int, address: str, amount: int, extra: str = "") -> Transaction:
    outputs = [TxOut(amount, address)] if address else []
    return Transaction([], outputs, f"height:{height}" + (f" {extra}" if extra else ""))


def block_subsidy(height: int) -> int:
    halvings = height // HALVING_INTERVAL
    return INITIAL_REWARD >> halvings if halvings < 64 else 0


# ---------------------------------------------------------------- blocks

def merkle_root(txids: list) -> str:
    """Bitcoin-style merkle tree: pair up hashes, duplicating the last one if odd."""
    level = [bytes.fromhex(t) for t in txids]
    if not level:
        return "00" * 32
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


@dataclass
class Block:
    prev_hash: str
    merkle_root: str
    timestamp: int
    target: int
    nonce: int
    txs: list = field(default_factory=list)

    def header_prefix(self) -> bytes:
        return f"{self.prev_hash}{self.merkle_root}{self.timestamp:016x}{self.target:064x}".encode()

    @property
    def hash(self) -> str:
        return sha256d(self.header_prefix() + f"{self.nonce:016x}".encode())[::-1].hex()

    @property
    def work(self) -> int:
        return 2 ** 256 // (self.target + 1)

    def to_dict(self) -> dict:
        return {"prev_hash": self.prev_hash, "merkle_root": self.merkle_root,
                "timestamp": self.timestamp, "target": hex(self.target), "nonce": self.nonce,
                "txs": [t.to_dict() for t in self.txs]}

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(d["prev_hash"], d["merkle_root"], int(d["timestamp"]), int(d["target"], 16),
                   int(d["nonce"]), [Transaction.from_dict(t) for t in d["txs"]])


def mine(block: Block, should_stop=None) -> Block | None:
    """Proof-of-work: try nonces until the header hash is below the target."""
    prefix = block.header_prefix()
    nonce = 0
    while True:
        h = int.from_bytes(sha256d(prefix + f"{nonce:016x}".encode())[::-1], "big")
        if h <= block.target:
            block.nonce = nonce
            return block
        nonce += 1
        if should_stop and nonce % 20000 == 0 and should_stop():
            return None


def make_genesis() -> Block:
    cb = make_coinbase(0, "", 0, GENESIS_MESSAGE)  # no outputs: the genesis coins are unspendable
    b = Block("00" * 32, merkle_root([cb.txid]), GENESIS_TIME, MAX_TARGET, 0, [cb])
    return mine(b)


# ---------------------------------------------------------------- the chain

class Blockchain:
    def __init__(self):
        genesis = make_genesis()
        self.genesis_hash = genesis.hash
        self.blocks = {genesis.hash: genesis}       # every valid-header block we know, any branch
        self.heights = {genesis.hash: 0}
        self.chainwork = {genesis.hash: genesis.work}
        self.tip = genesis.hash
        self.utxos = {}                              # (txid, index) -> TxOut on the best chain
        self.mempool = {}                            # txid -> Transaction waiting to be mined
        self.invalid = set()                         # blocks whose transactions failed validation
        self._connect(genesis, 0, self.utxos)

    # --- queries

    @property
    def height(self) -> int:
        return self.heights[self.tip]

    def best_chain(self, tip: str | None = None) -> list:
        chain, h = [], tip or self.tip
        while h != "00" * 32:
            chain.append(self.blocks[h])
            h = self.blocks[h].prev_hash
        return chain[::-1]

    def ancestor(self, block_hash: str, height: int) -> Block:
        while self.heights[block_hash] > height:
            block_hash = self.blocks[block_hash].prev_hash
        return self.blocks[block_hash]

    def balance(self, address: str) -> int:
        return sum(o.amount for o in self.utxos.values() if o.address == address)

    def spendable_utxos(self, address: str) -> list:
        """UTXOs for an address that no mempool transaction is already spending."""
        pending = {(i.txid, i.index) for tx in self.mempool.values() for i in tx.inputs}
        return [(k, o) for k, o in self.utxos.items() if o.address == address and k not in pending]

    def next_target(self, parent_hash: str) -> int:
        parent = self.blocks[parent_hash]
        height = self.heights[parent_hash] + 1
        if height % ADJUST_INTERVAL:
            return parent.target
        first = self.ancestor(parent_hash, height - ADJUST_INTERVAL)
        expected = ADJUST_INTERVAL * TARGET_BLOCK_TIME
        actual = min(max(parent.timestamp - first.timestamp, expected // 4), expected * 4)
        return min(parent.target * actual // expected, MAX_TARGET)

    def median_time_past(self, block_hash: str) -> int:
        times = []
        for _ in range(11):
            b = self.blocks[block_hash]
            times.append(b.timestamp)
            if block_hash == self.genesis_hash:
                break
            block_hash = b.prev_hash
        return sorted(times)[len(times) // 2]

    # --- transaction validation

    def _check_tx(self, tx: Transaction, utxos: dict) -> int:
        """Validate a non-coinbase transaction against a UTXO view; returns its fee."""
        if not tx.inputs or not tx.outputs:
            raise ValidationError("transaction needs inputs and outputs")
        if tx.coinbase:
            raise ValidationError("only coinbase transactions may carry coinbase data")
        seen, total_in = set(), 0
        sighash = tx.sighash()
        for i in tx.inputs:
            key = (i.txid, i.index)
            if key in seen:
                raise ValidationError("input spent twice in one transaction")
            seen.add(key)
            prev = utxos.get(key)
            if prev is None:
                raise ValidationError(f"input {i.txid}:{i.index} missing or already spent")
            try:
                pub = bytes.fromhex(i.pubkey)
                sig = bytes.fromhex(i.sig)
            except ValueError:
                raise ValidationError("malformed pubkey or signature")
            if address_from_pubkey(pub) != prev.address:
                raise ValidationError("public key does not own this output")
            if not verify(pub, sighash, sig):
                raise ValidationError("bad signature")
            total_in += prev.amount
        total_out = 0
        for o in tx.outputs:
            if not isinstance(o.amount, int) or o.amount <= 0:
                raise ValidationError("output amounts must be positive integers")
            if not is_valid_address(o.address):
                raise ValidationError(f"invalid address {o.address}")
            total_out += o.amount
        if total_out > total_in:
            raise ValidationError("outputs exceed inputs")
        return total_in - total_out

    @staticmethod
    def _apply_tx(tx: Transaction, utxos: dict) -> None:
        for i in tx.inputs:
            del utxos[(i.txid, i.index)]
        txid = tx.txid
        for n, o in enumerate(tx.outputs):
            utxos[(txid, n)] = o

    def _connect(self, block: Block, height: int, utxos: dict) -> None:
        """Check every transaction in a block and apply it to `utxos` (mutated in place)."""
        if not block.txs or not block.txs[0].is_coinbase:
            raise ValidationError("first transaction must be the coinbase")
        if len(block.txs) > MAX_BLOCK_TXS:
            raise ValidationError("too many transactions")
        if merkle_root([t.txid for t in block.txs]) != block.merkle_root:
            raise ValidationError("merkle root mismatch")
        cb = block.txs[0]
        if cb.coinbase.split(" ")[0] != f"height:{height}":
            raise ValidationError("coinbase must commit to the block height")
        fees = 0
        for tx in block.txs[1:]:
            if tx.is_coinbase:
                raise ValidationError("only one coinbase per block")
            fees += self._check_tx(tx, utxos)
            self._apply_tx(tx, utxos)
        for o in cb.outputs:
            if o.amount <= 0 or not is_valid_address(o.address):
                raise ValidationError("bad coinbase output")
        if sum(o.amount for o in cb.outputs) > block_subsidy(height) + fees:
            raise ValidationError("coinbase pays more than subsidy + fees")
        self._apply_tx(cb, utxos)

    # --- accepting new data

    def add_block(self, block: Block) -> bool:
        """Add a block from anywhere. Returns True if it became the new tip."""
        h = block.hash
        if h in self.blocks:
            return False
        if h in self.invalid or block.prev_hash in self.invalid:
            raise ValidationError("block is (or builds on) an invalid block")
        if block.prev_hash not in self.blocks:
            raise OrphanBlock(block.prev_hash)

        # Header checks: cheap, done for every branch.
        if int(h, 16) > block.target:
            raise ValidationError("insufficient proof of work")
        if block.target != self.next_target(block.prev_hash):
            raise ValidationError("wrong difficulty target")
        if block.timestamp <= self.median_time_past(block.prev_hash):
            raise ValidationError("timestamp too old")
        if block.timestamp > time.time() + MAX_FUTURE_DRIFT:
            raise ValidationError("timestamp too far in the future")

        height = self.heights[block.prev_hash] + 1
        work = self.chainwork[block.prev_hash] + block.work
        self.blocks[h], self.heights[h], self.chainwork[h] = block, height, work
        if work <= self.chainwork[self.tip]:
            return False  # stored as a side branch; its transactions are checked if it ever wins

        # Most work wins. Build the UTXO set for the new chain before switching to it.
        try:
            if block.prev_hash == self.tip:
                utxos = dict(self.utxos)
                self._connect(block, height, utxos)
            else:  # reorganisation: replay the winning branch from genesis
                utxos = {}
                for n, b in enumerate(self.best_chain(h)):
                    self._connect(b, n, utxos)
        except ValidationError:
            for d in (self.blocks, self.heights, self.chainwork):
                del d[h]
            self.invalid.add(h)
            raise
        old_chain = self.best_chain() if block.prev_hash != self.tip else []
        self.tip, self.utxos = h, utxos
        self._refresh_mempool(old_chain)
        return True

    def _refresh_mempool(self, old_chain: list) -> None:
        """Drop mined/conflicting transactions; put back ones from blocks a reorg orphaned."""
        on_chain = {t.txid for b in old_chain for t in b.txs}
        on_chain -= {t.txid for b in self.best_chain() for t in b.txs}
        candidates = [t for b in old_chain for t in b.txs[1:] if t.txid in on_chain]
        candidates += list(self.mempool.values())
        self.mempool = {}
        for tx in candidates:
            try:
                self.add_transaction(tx)
            except ValidationError:
                pass

    def add_transaction(self, tx: Transaction) -> bool:
        """Validate a transaction and put it in the mempool. Returns False if already known."""
        txid = tx.txid
        if txid in self.mempool:
            return False
        if tx.is_coinbase:
            raise ValidationError("coinbase transactions cannot be relayed")
        view = dict(self.utxos)
        for pending in self.mempool.values():  # allow spending unconfirmed outputs
            self._apply_tx(pending, view)
        self._check_tx(tx, view)
        self.mempool[txid] = tx
        return True

    # --- mining

    def block_template(self, miner_address: str) -> Block:
        utxos = dict(self.utxos)
        txs, fees = [], 0
        for tx in list(self.mempool.values())[:MAX_BLOCK_TXS - 1]:
            try:
                fees += self._check_tx(tx, utxos)
            except ValidationError:
                continue
            self._apply_tx(tx, utxos)
            txs.append(tx)
        height = self.height + 1
        cb = make_coinbase(height, miner_address, block_subsidy(height) + fees)
        txs.insert(0, cb)
        ts = max(int(time.time()), self.median_time_past(self.tip) + 1)
        return Block(self.tip, merkle_root([t.txid for t in txs]), ts, self.next_target(self.tip), 0, txs)


def build_payment(chain: Blockchain, priv: int, to_address: str, amount: int, fee: int) -> Transaction:
    """Wallet helper: pick coins, add change, sign."""
    me = address_from_pubkey(public_key(priv))
    picked, total = [], 0
    for key, out in chain.spendable_utxos(me):
        picked.append(key)
        total += out.amount
        if total >= amount + fee:
            break
    if total < amount + fee:
        raise ValidationError(f"insufficient funds: have {total}, need {amount + fee}")
    outputs = [TxOut(amount, to_address)]
    if total - amount - fee > 0:
        outputs.append(TxOut(total - amount - fee, me))
    tx = Transaction([TxIn(txid, idx) for txid, idx in picked], outputs)
    tx.sign_inputs(priv)
    return tx
