#!/usr/bin/env python3
# Copyright (c) the gsr-stark-verifier contributors
# Distributed under the MIT software license.
"""gsr-privacy-pool relay, replacement and pinning policy on a gsr node patched with bitcoin/bitcoin#36466.

Settlements are stand-ins: the rollup coin is a P2TR output with a NUMS internal key and one
`OP_1 OP_CHECKSEQUENCEVERIFY` tapscript leaf, spent with an input-0 annex sized so the whole
transaction has the weight of a real settlement. Mempool policy depends only on size, fees,
versions, annexes and topology, not on what the leaf script computes.
"""
import json
import os
from decimal import Decimal

from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_0, OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_RETURN, OP_TRUE, sha256, taproot_construct
from test_framework.script_util import PAY_TO_ANCHOR
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
LEAF = CScript([OP_1, OP_CHECKSEQUENCEVERIFY])
TAP = taproot_construct(NUMS, [("rollup", LEAF)])
CONTROL = bytes([TAP.leaves["rollup"].version | TAP.negflag]) + TAP.internal_pubkey + TAP.leaves["rollup"].merklebranch


def successor(state):
    """Rollup output for a new state; like the real leaf, its script commits to the state."""
    return taproot_construct(NUMS, [("rollup", CScript([state, OP_DROP, OP_1, OP_CHECKSEQUENCEVERIFY]))]).scriptPubKey
P2WSH_TRUE = CScript([OP_0, sha256(CScript([OP_TRUE]))])

# Fixed settlement weight (verifier + empty-batch annex) and bytes each transfer adds to the annex.
REGIMES = {"current": 331_700, "target": 16_000}
PER_TX_ANNEX = 1_482
WITHDRAWAL = 1_000_000


def annex(n):
    return b"\x50\x00" + bytes(max(n, 2) - 2)


class GsrPrivacyPoolRelayPinning(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        self.r = {}
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.recipient = MiniWallet(self.node, tag_name="recipient")
        self.third = MiniWallet(self.node, tag_name="third")
        self.generate(self.wallet, 30)
        self.generate(self.node, 101)
        self.wallet.rescan_utxos()
        for w in (self.recipient, self.third):
            for _ in range(4):
                self.wallet.send_to(from_node=self.node, scriptPubKey=w.get_output_script(), amount=COIN)
        self.generate(self.node, 1)
        for w in (self.recipient, self.third):
            w.rescan_utxos()
        self.test_annex_encoding()
        self.test_mixed_inputs()
        for regime in REGIMES:
            self.test_growing_batches(regime)
            self.test_pinning(regime)
        self.test_p2a()
        self.test_escrow_annex_inflation()
        path = os.environ.get("GSRPP_REPORT")
        if path:
            with open(path, "w") as f:
                json.dump(self.r, f, indent=1)
        self.log.info(json.dumps(self.r, indent=1))

    # helpers
    def rollup_coin(self, value=10 * COIN):
        sent = self.wallet.send_to(from_node=self.node, scriptPubKey=TAP.scriptPubKey, amount=value)
        self.generate(self.node, 1)
        self.wallet.rescan_utxos()
        return {"txid": sent["txid"], "vout": sent["sent_vout"], "value": value}

    def wallet_input(self, w):
        u = w.get_utxo(confirmed_only=True)
        leaf = list(w._taproot_info.leaves.values())[0]
        wit = [leaf.script, bytes([leaf.version | w._taproot_info.negflag]) + w._taproot_info.internal_pubkey]
        return {"txid": u["txid"], "vout": u["vout"], "value": int(u["value"] * COIN), "witness": wit}

    def settlement(self, coin, weight, fee, *, version=2, withdraw=True, p2a=None, extra=(), annex_bytes=None):
        def build(annex_len):
            tx = CTransaction()
            tx.version = version
            tx.vin = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]), nSequence=1)]
            tx.vin += [CTxIn(COutPoint(int(e["txid"], 16), e["vout"]), nSequence=0xfffffffd) for e in extra]
            outs = [CTxOut(WITHDRAWAL, self.recipient.get_output_script())] if withdraw else []
            if p2a is not None:
                outs.append(CTxOut(p2a, PAY_TO_ANCHOR))
            total = coin["value"] + sum(e["value"] for e in extra)
            a = annex_bytes or annex(annex_len)
            tx.vout = [CTxOut(total - fee - sum(o.nValue for o in outs), successor(sha256(a)))] + outs
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
            tx.wit.vtxinwit[0].scriptWitness.stack = [LEAF, CONTROL, a]
            for i, e in enumerate(extra, 1):
                tx.wit.vtxinwit[i].scriptWitness.stack = list(e["witness"])
            return tx
        if annex_bytes is not None:
            return build(0)
        n = 2
        for _ in range(3):
            n = max(2, n + weight - build(n).get_weight())
        return build(n)

    def accept(self, tx):
        res = self.node.testmempoolaccept([tx.serialize().hex()])[0]
        return res["allowed"], res.get("reject-reason", "") + (" " + res.get("reject-details", "") if res.get("reject-details") else "")

    def min_fee(self, make, lo, hi):
        assert self.accept(make(hi))[0], self.accept(make(hi))
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self.accept(make(mid))[0]:
                hi = mid
            else:
                lo = mid
        return hi

    def send(self, tx):
        return self.node.sendrawtransaction(tx.serialize().hex(), 0)

    def child(self, parent, vsize, feerate_sat_vb, version):
        u = self.recipient._create_utxo(txid=parent.txid_hex, vout=1, value=Decimal(WITHDRAWAL) / COIN,
                                        height=0, coinbase=False, confirmations=0)
        return self.recipient.create_self_transfer(utxo_to_spend=u, fee_rate=Decimal(feerate_sat_vb) / 100_000,
                                                   target_vsize=vsize, version=version)

    def clear(self):
        self.generate(self.node, 1)
        for w in (self.wallet, self.recipient, self.third):
            w.rescan_utxos()

    # tests
    def test_annex_encoding(self):
        coin = self.rollup_coin()
        cases = {
            "current GSRP annex (0x50 'G' ...)": b"\x50GSRP\x01" + bytes(200),
            "0x50 0x00 'GSRP' ... (proposed)": b"\x50\x00GSRP\x01" + bytes(200),
            "marker-only 0x50": b"\x50",
            "0x50 0x01 ... (reserved prefix)": b"\x50\x01" + bytes(200),
        }
        self.r["annex_encoding"] = {k: self.accept(self.settlement(coin, 0, 20_000, annex_bytes=v)) for k, v in cases.items()}

    def test_mixed_inputs(self):
        coin = self.rollup_coin()
        sent = self.wallet.send_to(from_node=self.node, scriptPubKey=P2WSH_TRUE, amount=COIN)
        self.clear()
        p2wsh = {"txid": sent["txid"], "vout": 1, "value": COIN, "witness": [CScript([OP_TRUE])]}
        tap = self.wallet_input(self.third)
        tap_marker = dict(tap, witness=tap["witness"] + [b"\x50"])
        tap_data = dict(tap, witness=tap["witness"] + [annex(20_000)])
        self.r["mixed_inputs"] = {
            "rollup(annex) + taproot input without annex": self.accept(self.settlement(coin, 20_000, 30_000, extra=[tap])),
            "rollup(annex) + taproot input with marker annex": self.accept(self.settlement(coin, 20_000, 30_000, extra=[tap_marker])),
            "rollup(annex) + P2WSH input": self.accept(self.settlement(coin, 20_000, 30_000, extra=[p2wsh])),
            "rollup(annex) + taproot input with 20 kB annex": self.accept(self.settlement(coin, 20_000, 30_000, extra=[tap_data])),
        }

    def test_growing_batches(self, regime):
        fixed = REGIMES[regime]
        coin = self.rollup_coin()
        feerate = 5
        s0 = self.settlement(coin, fixed + 4 * PER_TX_ANNEX, 0)
        f0 = feerate * s0.get_vsize()
        s0 = self.settlement(coin, fixed + 4 * PER_TX_ANNEX, f0)
        rows = []
        before = self.nodes[1].getpeerinfo()[0]["bytesrecv_per_msg"].get("tx", 0)
        self.send(s0)
        self.sync_mempools()
        relayed = [self.nodes[1].getpeerinfo()[0]["bytesrecv_per_msg"].get("tx", 0) - before]
        prev, prev_fee = s0, f0
        for added in (1, 4):
            w = fixed + (4 + added) * PER_TX_ANNEX
            size = self.settlement(coin, w, prev_fee).get_vsize()
            need = self.min_fee(lambda f: self.settlement(coin, w, f), prev_fee - 1, prev_fee + 20 * size)
            rows.append({"added_transfers": added, "old_vsize": prev.get_vsize(), "old_fee": prev_fee, "new_vsize": size,
                         "min_new_fee": need, "min_delta_fee": need - prev_fee,
                         "incremental_only_bound": -(-size // 10),
                         "same_feerate_bound": -(-(prev_fee * size) // prev.get_vsize()) - prev_fee,
                         "same_fee_higher_size": self.accept(self.settlement(coin, w, prev_fee)),
                         "old_fee_plus_incremental": self.accept(self.settlement(coin, w, prev_fee + -(-size // 10)))})
        # A chain of five one-transfer replacements, each paying the minimum, relayed to node1.
        chain = []
        for k in range(1, 6):
            w = fixed + (4 + k) * PER_TX_ANNEX
            need = self.min_fee(lambda f: self.settlement(coin, w, f), prev_fee - 1, prev_fee + 20 * prev.get_vsize())
            tx = self.settlement(coin, w, need)
            b = self.nodes[1].getpeerinfo()[0]["bytesrecv_per_msg"].get("tx", 0)
            self.send(tx)
            self.sync_mempools()
            assert_equal(self.nodes[1].getrawmempool(), [tx.txid_hex])
            chain.append({"vsize": tx.get_vsize(), "size": len(tx.serialize()), "fee": need, "delta_fee": need - prev_fee,
                          "bytes_relayed_to_peer": self.nodes[1].getpeerinfo()[0]["bytesrecv_per_msg"].get("tx", 0) - b})
            prev, prev_fee = tx, need
        self.r[f"growing_batches_{regime}"] = {"start_feerate_sat_vb": feerate, "s0_vsize": s0.get_vsize(), "s0_fee": f0,
                                               "s0_bytes_relayed": relayed[0], "single_step": rows, "chain": chain}
        self.clear()

    def test_pinning(self, regime):
        fixed = REGIMES[regime]
        out = {}
        for version in (2, 3):
            coin = self.rollup_coin()
            w = fixed + 4 * PER_TX_ANNEX
            s0 = self.settlement(coin, w, 0, version=version)
            f0 = 5 * s0.get_vsize()
            s0 = self.settlement(coin, w, f0, version=version)
            ok, why = self.accept(s0)
            res = {"parent_vsize": s0.get_vsize(), "parent_accepted": [ok, why]}
            if ok:
                w1 = w + PER_TX_ANNEX
                hi = f0 + 200 * s0.get_vsize()
                self.send(s0)
                base = self.min_fee(lambda f: self.settlement(coin, w1, f, version=version), f0 - 1, hi)
                limit = 1_000 if version == 3 else 101_000 - s0.get_vsize() - 50
                if version == 3:
                    res["v2_child_of_v3"] = self.accept_raw(self.child(s0, 200, 1, 2)["hex"])
                    res["child_1001_vb"] = self.accept_raw(self.child(s0, 1_001, 1, 3)["hex"])
                c = self.child(s0, limit, 1, version)
                res["child_vsize"], res["child_fee"] = c["tx"].get_vsize(), int(c["fee"] * COIN)
                res["child_accepted"] = self.accept_raw(c["hex"])
                over = self.child(s0, limit + 200, 1, version)
                res["child_over_cluster_limit"] = self.accept_raw(over["hex"])
                self.node.sendrawtransaction(c["hex"])
                pinned = self.min_fee(lambda f: self.settlement(coin, w1, f, version=version), f0 - 1, hi)
                res.update({"replacement_min_fee_unpinned": base, "replacement_min_fee_pinned": pinned,
                            "pin_overhead_sats": pinned - base})
            out[f"v{version}"] = res
            self.clear()
        self.r[f"pinning_{regime}"] = out

    def accept_raw(self, hexstr):
        res = self.node.testmempoolaccept([hexstr])[0]
        return [res["allowed"], res.get("reject-reason", "")]

    def p2a_child(self, parent, vout, version, vsize, feerate_sat_vb):
        fund = self.wallet_input(self.third)
        tx = CTransaction()
        tx.version = version
        tx.vin = [CTxIn(COutPoint(int(parent.txid_hex, 16), vout), nSequence=0xfffffffd),
                  CTxIn(COutPoint(int(fund["txid"], 16), fund["vout"]), nSequence=0xfffffffd)]
        tx.vout = [CTxOut(0, self.third.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        tx.wit.vtxinwit[1].scriptWitness.stack = fund["witness"]
        if vsize:
            tx.vout.append(CTxOut(0, CScript([OP_RETURN])))
            pad = 0
            while True:
                tx.vout[-1].scriptPubKey = CScript([OP_RETURN, bytes(pad)]) if pad else CScript([OP_RETURN])
                if tx.get_vsize() >= vsize:
                    break
                pad += max(1, vsize - tx.get_vsize())
        tx.vout[0].nValue = fund["value"] + parent.vout[vout].nValue - feerate_sat_vb * tx.get_vsize()
        return tx

    def test_p2a(self):
        out = {}
        coin = self.rollup_coin()
        w = REGIMES["target"] + 4 * PER_TX_ANNEX
        mk = lambda p2a, fee, v=3: self.settlement(coin, w, fee, version=v, p2a=p2a)
        fee = 5 * mk(240, 0).get_vsize()
        out["v3_fee_paying_p2a_0_sat"] = self.accept(mk(0, fee))
        out["v3_fee_paying_p2a_239_sat"] = self.accept(mk(239, fee))
        out["v3_fee_paying_p2a_240_sat"] = self.accept(mk(240, fee))
        out["v3_zero_fee_parent_p2a_0_sat_alone"] = self.accept(mk(0, 0))
        s0 = mk(240, fee)
        self.send(s0)
        p2a_vout = len(s0.vout) - 1
        cpfp = self.p2a_child(s0, p2a_vout, 3, 0, 20)
        out["third_party_p2a_cpfp"] = self.accept(cpfp)
        self.send(cpfp)
        rc = self.child(s0, 500, 40, 3)
        out["recipient_child_after_p2a_child_sibling_eviction"] = self.accept_raw(rc["hex"])
        out["p2a_child_vsize"] = cpfp.get_vsize()
        self.clear()
        coin = self.rollup_coin()
        w2 = REGIMES["target"] + 4 * PER_TX_ANNEX
        s2 = self.settlement(coin, w2, fee, version=2, p2a=240)
        self.send(s2)
        out["v2_replacement_min_fee_unpinned"] = self.min_fee(lambda f: self.settlement(coin, w2 + PER_TX_ANNEX, f, version=2, p2a=240), fee - 1, fee + 400_000)
        big = self.p2a_child(s2, len(s2.vout) - 1, 2, 90_000, 1)
        out["v2_parent_p2a_child_90kvb_1satvb"] = self.accept(big)
        self.send(big)
        w3 = w2 + PER_TX_ANNEX
        out["v2_replacement_min_fee_after_p2a_pin"] = self.min_fee(lambda f: self.settlement(coin, w3, f, version=2, p2a=240), fee - 1, fee + 400_000)
        out["v2_parent_fee"] = fee
        self.r["p2a"] = out
        self.clear()

    def test_escrow_annex_inflation(self):
        out = {}
        for order in ("honest_first", "inflated_first"):
            coin = self.rollup_coin()
            esc = self.wallet_input(self.third)
            w = REGIMES["target"] + 4 * PER_TX_ANNEX
            honest = self.settlement(coin, w, 50_000, extra=[dict(esc, witness=esc["witness"] + [b"\x50"])])
            inflated = self.settlement(coin, w, 50_000, extra=[dict(esc, witness=esc["witness"] + [annex(60_000)])],
                                       annex_bytes=honest.wit.vtxinwit[0].scriptWitness.stack[2])
            assert_equal(honest.txid_hex, inflated.txid_hex)
            first, second = (honest, inflated) if order == "honest_first" else (inflated, honest)
            self.send(first)
            self.sync_mempools()
            res = {"honest_vsize": honest.get_vsize(), "inflated_vsize": inflated.get_vsize(), "fee": 50_000,
                   "second_accepted": self.accept(second), "peer_has_wtxid": self.nodes[1].getmempoolentry(first.txid_hex)["wtxid"] == first.wtxid_hex}
            mk = lambda f: self.settlement(coin, w + PER_TX_ANNEX, f, extra=[dict(esc, witness=esc["witness"] + [b"\x50"])])
            res["reproved_replacement_min_fee"] = self.min_fee(mk, 49_999, 400_000)
            out[order] = res
            self.clear()
        self.r["escrow_annex_inflation"] = out


if __name__ == "__main__":
    GsrPrivacyPoolRelayPinning(__file__).main()
