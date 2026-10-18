#!/usr/bin/env python3
# Copyright (c) the gsr-stark-verifier contributors
# Distributed under the MIT software license.
"""A gsr-privacy-pool settlement has no unconfirmed parent and no spendable output while unconfirmed.

Run on a gsr node patched with bitcoin/bitcoin#36466 (copy into `test/functional/`). Settlements are stand-ins
with the real layout: inputs `[rollup (sequence 1), funding (sequence 1)]`, outputs `[successor, withdrawal]`
where the successor is `P2TR(NUMS, {.. OP_1 OP_CSV})` and the withdrawal is
`P2TR(NUMS, {OP_1 OP_CSV OP_DROP <key> OP_CHECKSIG})`. Checked:

* a settlement whose funding coin is unconfirmed is non-BIP68-final, so it never has an unconfirmed parent;
* no child of an unconfirmed settlement is accepted, through either output, with any sequence;
* so a settlement has no descendants, and a higher-fee settlement replaces it under ordinary RBF;
* once the settlement confirms, the withdrawal recipient spends with sequence 1.
"""
import json
import os

from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (CScript, OP_0, OP_1, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP, OP_TRUE,
                                   TaprootSignatureHash, sha256, taproot_construct)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
P2WSH_TRUE = CScript([OP_0, sha256(CScript([OP_TRUE]))])
FUNDING_INPUT_SEQUENCE = 1  # pr_protocol_types::FUNDING_INPUT_SEQUENCE
ROLLUP_INPUT_SEQUENCE = 1


def leaf_coin(script):
    tap = taproot_construct(NUMS, [("l", script)])
    control = bytes([tap.leaves["l"].version | tap.negflag]) + NUMS + tap.leaves["l"].merklebranch
    return tap, control


def rollup(state):
    return leaf_coin(CScript([state, OP_DROP, OP_1, OP_CHECKSEQUENCEVERIFY]))


def withdrawal_leaf(xonly):
    return CScript([OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP, xonly, OP_CHECKSIG])


FUNDING_LEAF = CScript([OP_1])


class GsrPrivacyPoolNoPinHandles(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def accept(self, tx):
        return self.node.testmempoolaccept([tx.serialize().hex()])[0]

    def fund(self, spk, value, confirm=True):
        sent = self.wallet.send_to(from_node=self.node, scriptPubKey=spk, amount=value)
        if confirm:
            self.generate(self.node, 1)
        return COutPoint(int(sent["txid"], 16), sent["sent_vout"]), value

    def settlement(self, state, prev, funding, fee, recipient):
        """Spend rollup coin `prev` (state `state`) and `funding`; pay the successor and one CSV withdrawal."""
        (r_out, r_value), (f_out, f_value) = prev, funding
        tap_r, ctl_r = rollup(state)
        tap_w, _ = leaf_coin(withdrawal_leaf(recipient))
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(r_out, nSequence=ROLLUP_INPUT_SEQUENCE), CTxIn(f_out, nSequence=FUNDING_INPUT_SEQUENCE)]
        w_value = 100_000
        tx.vout = [CTxOut(r_value + f_value - w_value - fee, rollup(state + b"'")[0].scriptPubKey),
                   CTxOut(w_value, tap_w.scriptPubKey)]
        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([state, OP_DROP, OP_1, OP_CHECKSEQUENCEVERIFY]), ctl_r,
                                                  b"\x50\x00" + state]
        _, ctl_f = leaf_coin(FUNDING_LEAF)
        tx.wit.vtxinwit[1].scriptWitness.stack = [FUNDING_LEAF, ctl_f, b"\x50"]
        return tx

    def children(self, parent, key, xonly):
        """Every child an attacker could try against `parent`'s outputs."""
        out = []
        w_tap, w_ctl = leaf_coin(withdrawal_leaf(xonly))
        state = None
        for seq in (0, 1, 0xfffffffd, 0xffffffff):
            for vout in (0, 1):
                c = CTransaction()
                c.version = 2
                c.vin = [CTxIn(COutPoint(int(parent.txid_hex, 16), vout), nSequence=seq)]
                c.vout = [CTxOut(parent.vout[vout].nValue - 50_000, P2WSH_TRUE)]
                c.wit.vtxinwit = [CTxInWitness()]
                if vout == 1:
                    spent = [parent.vout[1]]
                    h = TaprootSignatureHash(c, spent, 0, 0, scriptpath=True, leaf_script=withdrawal_leaf(xonly),
                                             leaf_ver=0xc0, annex=b"\x50", codeseparator_pos=0xffffffff)
                    c.wit.vtxinwit[0].scriptWitness.stack = [sign_schnorr(key, h), withdrawal_leaf(xonly), w_ctl,
                                                             b"\x50"]
                else:
                    state = self.state + b"'"
                    script = CScript([state, OP_DROP, OP_1, OP_CHECKSEQUENCEVERIFY])
                    c.wit.vtxinwit[0].scriptWitness.stack = [script, rollup(state)[1], b"\x50\x00"]
                out.append((f"vout{vout}_seq{seq:#x}", c))
        return out

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, 10)
        self.generate(self.node, 101)
        r = {}
        key = generate_privkey()
        xonly = compute_xonly_pubkey(key)[0]
        self.state = b"S0"
        prev = self.fund(rollup(self.state)[0].scriptPubKey, 10 * COIN)
        f_tap, _ = leaf_coin(FUNDING_LEAF)

        # 1. An unconfirmed funding coin can't fund a settlement.
        unconfirmed = self.fund(f_tap.scriptPubKey, COIN, confirm=False)
        res = self.accept(self.settlement(self.state, prev, unconfirmed, 20_000, xonly))
        r["unconfirmed_funding"] = res.get("reject-reason")
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "non-BIP68-final")
        self.generate(self.node, 1)

        # 2. Once the funding coin confirms the settlement relays; no child of it is accepted.
        s1 = self.settlement(self.state, prev, unconfirmed, 20_000, xonly)
        self.node.sendrawtransaction(s1.serialize().hex())
        r["settlement_vsize"] = s1.get_vsize()
        r["children"] = {}
        for name, c in self.children(s1, key, xonly):
            res = self.accept(c)
            r["children"][name] = res.get("reject-reason")
            assert not res["allowed"], name
        assert_equal(self.node.getmempoolentry(s1.txid_hex)["descendantcount"], 1)

        # 3. With no descendants, ordinary RBF (a different batch, higher fee) replaces it.
        s2 = self.settlement(self.state, prev, unconfirmed, 40_000, xonly)
        s2.vout[0] = CTxOut(s2.vout[0].nValue, rollup(self.state + b"2")[0].scriptPubKey)
        self.node.sendrawtransaction(s2.serialize().hex())
        assert s1.txid_hex not in self.node.getrawmempool()
        r["rbf_replaced"] = True
        r["rbf_extra_fee"] = 20_000

        # 4. One confirmation later the recipient spends the withdrawal with sequence 1.
        self.generate(self.node, 1)
        spend = dict(self.children(s2, key, xonly))["vout1_seq0x1"]
        res = self.accept(spend)
        r["withdrawal_spend_after_confirmation"] = res["allowed"]
        assert res["allowed"], res
        self.log.info(json.dumps(r, indent=2))
        if os.environ.get("GSRPP_REPORT"):
            with open(os.environ["GSRPP_REPORT"], "w") as f:
                json.dump(r, f, indent=2)


if __name__ == "__main__":
    GsrPrivacyPoolNoPinHandles(__file__).main()
