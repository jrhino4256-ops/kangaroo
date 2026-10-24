import copy
import unittest

import chain as C
from chain import Blockchain, ValidationError, OrphanBlock, build_payment, mine, TxOut
from crypto import new_private_key, public_key, address_from_pubkey


def wallet():
    k = new_private_key()
    return k, address_from_pubkey(public_key(k))


def mine_next(bc: Blockchain, address: str):
    b = mine(bc.block_template(address))
    bc.add_block(b)
    return b


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.bc = Blockchain()
        self.alice_key, self.alice = wallet()
        self.bob_key, self.bob = wallet()

    def test_genesis_is_deterministic(self):
        self.assertEqual(Blockchain().genesis_hash, self.bc.genesis_hash)

    def test_mining_pays_reward(self):
        mine_next(self.bc, self.alice)
        self.assertEqual(self.bc.height, 1)
        self.assertEqual(self.bc.balance(self.alice), C.INITIAL_REWARD)

    def test_payment_and_fee(self):
        mine_next(self.bc, self.alice)
        tx = build_payment(self.bc, self.alice_key, self.bob, 10 * C.COIN, 1000)
        self.bc.add_transaction(tx)
        mine_next(self.bc, self.bob)  # bob mines, collecting reward + fee
        self.assertEqual(self.bc.balance(self.bob), 10 * C.COIN + C.INITIAL_REWARD + 1000)
        self.assertEqual(self.bc.balance(self.alice), 40 * C.COIN - 1000)
        self.assertEqual(self.bc.mempool, {})

    def test_double_spend_rejected(self):
        mine_next(self.bc, self.alice)
        tx1 = build_payment(self.bc, self.alice_key, self.bob, 10 * C.COIN, 0)
        self.bc.add_transaction(tx1)
        tx2 = copy.deepcopy(tx1)
        tx2.outputs[0].amount = 20 * C.COIN
        tx2.outputs[1].amount = 30 * C.COIN
        tx2.sign_inputs(self.alice_key)
        with self.assertRaises(ValidationError):
            self.bc.add_transaction(tx2)

    def test_stealing_rejected(self):
        mine_next(self.bc, self.alice)
        tx = build_payment(self.bc, self.alice_key, self.bob, 10 * C.COIN, 0)
        tx.sign_inputs(self.bob_key)  # bob tries to sign for alice's coins
        with self.assertRaisesRegex(ValidationError, "does not own"):
            self.bc.add_transaction(tx)

    def test_tampered_tx_rejected(self):
        mine_next(self.bc, self.alice)
        tx = build_payment(self.bc, self.alice_key, self.bob, 10 * C.COIN, 0)
        tx.outputs[0].address = self.bob
        tx.outputs[0].amount = 49 * C.COIN  # change after signing
        tx.outputs[1].amount = 1 * C.COIN
        with self.assertRaisesRegex(ValidationError, "bad signature"):
            self.bc.add_transaction(tx)

    def test_overspend_rejected(self):
        mine_next(self.bc, self.alice)
        tx = build_payment(self.bc, self.alice_key, self.bob, 10 * C.COIN, 0)
        tx.outputs[0].amount = 60 * C.COIN
        tx.sign_inputs(self.alice_key)
        with self.assertRaisesRegex(ValidationError, "exceed"):
            self.bc.add_transaction(tx)

    def test_greedy_coinbase_rejected(self):
        b = self.bc.block_template(self.alice)
        b.txs[0].outputs[0] = TxOut(C.INITIAL_REWARD + 1, self.alice)
        b.merkle_root = C.merkle_root([t.txid for t in b.txs])
        with self.assertRaisesRegex(ValidationError, "subsidy"):
            self.bc.add_block(mine(b))
        self.assertEqual(self.bc.height, 0)

    def test_bad_pow_rejected(self):
        b = mine(self.bc.block_template(self.alice))
        while int(b.hash, 16) <= b.target:
            b.nonce += 1
        with self.assertRaisesRegex(ValidationError, "proof of work"):
            self.bc.add_block(b)

    def test_orphan_detected(self):
        other = Blockchain()
        mine_next(other, self.alice)
        b2 = mine_next(other, self.alice)
        with self.assertRaises(OrphanBlock):
            self.bc.add_block(b2)

    def test_reorg_to_heavier_chain(self):
        # Two nodes share block 1, then fork. The longer fork wins everywhere.
        b1 = mine_next(self.bc, self.alice)
        other = Blockchain()
        other.add_block(b1)

        pay = build_payment(self.bc, self.alice_key, self.bob, 5 * C.COIN, 0)
        self.bc.add_transaction(pay)
        mine_next(self.bc, self.alice)          # our branch: height 2, includes payment
        for _ in range(2):
            mine_next(other, self.bob)          # their branch: height 3, no payment
        for b in other.best_chain()[2:]:
            self.bc.add_block(b)

        self.assertEqual(self.bc.tip, other.tip)
        self.assertEqual(self.bc.balance(self.bob), 2 * C.INITIAL_REWARD)
        # The payment from the orphaned block goes back into the mempool.
        self.assertIn(pay.txid, self.bc.mempool)
        mine_next(self.bc, self.alice)
        self.assertEqual(self.bc.balance(self.bob), 2 * C.INITIAL_REWARD + 5 * C.COIN)

    def test_difficulty_rises_when_blocks_are_fast(self):
        # The first window spans the (old) genesis timestamp, so look at the second one.
        for _ in range(2 * C.ADJUST_INTERVAL):
            mine_next(self.bc, self.alice)
        self.assertLess(self.bc.blocks[self.bc.tip].target, C.MAX_TARGET)

    def test_halving(self):
        self.assertEqual(C.block_subsidy(C.HALVING_INTERVAL - 1), 50 * C.COIN)
        self.assertEqual(C.block_subsidy(C.HALVING_INTERVAL), 25 * C.COIN)
        self.assertEqual(C.block_subsidy(64 * C.HALVING_INTERVAL), 0)

    def test_serialization_roundtrip(self):
        b = mine_next(self.bc, self.alice)
        self.assertEqual(C.Block.from_dict(b.to_dict()).hash, b.hash)


if __name__ == "__main__":
    unittest.main()
