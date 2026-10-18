#!/usr/bin/env python3
"""Non-interactive deposit escrows: `P2TR(NUMS, {sweep (0xc2), refund (0xc0)})`.

The sweep leaf is `0x20 D OP_DROP || body`. The body uses OP_TX to require that input 0 of the sweeping
transaction is a taproot script-path spend of this rollup's covenant (this image and rollup id, any state
root), with exactly the covenant's witness item count and an annex, that the escrow input itself carries
`ESCROW_INPUT_SEQUENCE`, and that the escrow input's own annex is the one-byte marker `0x50` (bitcoin/bitcoin#36466
requires an annex on every non-P2A input once one has it; pinning it stops a relayer inflating it). The guest accepts that sequence only on escrow inputs, and only if the input's output
key opens to a sweep leaf committing to `D`; `D` commits to the rollup id, and P2a lineage means only the
genuine rollup coin has receipts, so the escrow mints exactly its note in exactly this rollup. `python3 deposit_escrow.py node-test` checks the body's
semantics on the gsr regtest node against a small stand-in covenant leaf.
"""
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time

import rollup_covenant as rc
from gsr import assemble
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from transaction import NUMS
from test_framework.address import script_to_p2wsh
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.script import (OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP, TaprootSignatureHash,
                                   taproot_construct)

SWEEP_LEAF, REFUND_LEAF = 0xc2, 0xc0
SEL_SPK = bytes([0, 0, 0, 0x30, 0x08, 0])
SEL_WITNESS_COUNT = bytes([0, 0, 0, 0x30, 0x40, 0])
SEL_WITNESS_ITEMS = bytes([0, 0, 0, 0x30, 0x80, 0])
SEL_CURRENT_SEQUENCE = bytes([0, 0, 0, 0x10, 0x20, 0])
SEL_CURRENT_ANNEX = bytes([0, 0, 0x02, 0, 0, 0])
ANNEX_MARKER = b"\x50"
ESCROW_INPUT_SEQUENCE = 2  # pr_protocol_types::ESCROW_INPUT_SEQUENCE
ROLLUP_ID_PUSH = b"\x24" + struct.pack("<I", 1)


class Template:
    """Where the root sits in a covenant leaf (which must hold the rollup id push once), and the hash of the rest."""

    def __init__(self, script: bytes, root_offset: int, rollup_id: bytes, witness_items: int) -> None:
        d = root_offset
        assert script[d] == 0x20
        hits = [i for i in range(len(script)) if script.startswith(ROLLUP_ID_PUSH + rollup_id, i)]
        assert len(hits) == 1, "rollup id push must be unique"
        r = hits[0] + len(ROLLUP_ID_PUSH)
        assert d + 33 <= r and r + 32 <= len(script)
        self.d, self.r, self.length, self.k = d, r, len(script), witness_items
        self.masked = hashlib.sha256(script[:d + 1] + script[d + 33:]).digest()

    @staticmethod
    def of(cov: rc.Covenant) -> "Template":
        return Template(cov.script, cov.decl_len, cov.gen.stmt.rollup_id, covenant_witness_items())


def covenant_witness_items() -> int:
    """Items of a covenant spend: the verifier stack plus new root, leaf, control block and annex."""
    g = rc.g
    return rc.ref.QUERIES * len(g.QUERY_ITEMS) + len(g.SETUP_ITEMS) + 4


def sweep_body(t: Template) -> bytes:
    d, n = t.d, t.length
    seq = ESCROW_INPUT_SEQUENCE.to_bytes(4, "little").rstrip(b"\0")  # OP_TX pushes a BIP 441 minimal unsigned number
    drops = ["2DROP"] * ((t.k - 3) // 2) + ["DROP"] * ((t.k - 3) % 2)
    return bytes(assemble([
        SEL_CURRENT_ANNEX, "TX", ANNEX_MARKER, "EQUALVERIFY",
        SEL_CURRENT_SEQUENCE, "TX", seq, "EQUALVERIFY",
        0, SEL_SPK, "TX", "SIZE", 34, "EQUALVERIFY", 0, 2, "SUBSTR", b"\x51\x20", "EQUALVERIFY",
        0, SEL_WITNESS_COUNT, "TX", t.k, "NUMEQUALVERIFY",
        0, SEL_WITNESS_ITEMS, "TX",
        0, 1, "SUBSTR", b"\x50", "EQUALVERIFY",
        "SIZE", 33, "EQUALVERIFY", "DUP", 1, 32, "SUBSTR", NUMS, "EQUALVERIFY",
        0, 1, "SUBSTR", "DUP", b"\xc2", "EQUAL", "SWAP", b"\xc3", "EQUAL", "ADD", "VERIFY",
        "SIZE", n, "EQUALVERIFY",
        "DUP", 0, d + 1, "SUBSTR", "SWAP",
        d + 33, n - d - 33, "SUBSTR", "CAT", "SHA256", t.masked, "EQUALVERIFY",
        *drops, 1,
    ]).code)


def sweep_leaf(digest: bytes, body: bytes) -> bytes:
    return b"\x20" + digest + b"\x75" + body


def refund_leaf(user_xonly: bytes, delay: int) -> bytes:
    return bytes(CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, user_xonly, OP_CHECKSIG]))


class Escrow:
    def __init__(self, digest: bytes, body: bytes, user_xonly: bytes, delay: int) -> None:
        self.sweep, self.refund = sweep_leaf(digest, body), refund_leaf(user_xonly, delay)
        self.taproot = taproot_construct(NUMS, [("sweep", CScript(self.sweep), SWEEP_LEAF),
                                                ("refund", CScript(self.refund), REFUND_LEAF)])
        self.script_pubkey = bytes(self.taproot.scriptPubKey)
        self.refund_hash = self.taproot.leaves["refund"].leaf_hash

    def control(self, name: str, version: int) -> bytes:
        return bytes([version | self.taproot.negflag]) + NUMS + self.taproot.leaves[name].merklebranch

    def sweep_witness(self) -> list[bytes]:
        return [self.sweep, self.control("sweep", SWEEP_LEAF), ANNEX_MARKER]


# ---- node test against a stand-in covenant leaf ----------------------------------------------------------

def standin(root: bytes, rollup_id: bytes, tail: bytes = b"\x51") -> bytes:
    return b"\x20" + root + b"\x75" + ROLLUP_ID_PUSH + rollup_id + b"\x75" + tail


def node_test() -> dict:
    work = rc.REPO / "build/escrow-node-test"
    datadir, port = work / "node", 19782
    shutil.rmtree(work, ignore_errors=True)
    datadir.mkdir(parents=True)
    bin_ = rc.REPO / "build/bitcoin/bin"
    subprocess.run([str(bin_ / "bitcoind"), "-regtest", f"-datadir={datadir}", "-daemonwait", "-server", "-listen=0",
                    f"-rpcport={port}", f"-port={port + 1}", "-vbparams=tapleaf_0xc2:0:3999999999"], check=True)

    def rpc(method, *args):
        p = subprocess.run([str(bin_ / "bitcoin-cli"), "-regtest", f"-datadir={datadir}", f"-rpcport={port}", "-stdin",
                            method], input="".join((a if isinstance(a, str) else json.dumps(a)) + "\n" for a in args),
                           text=True, capture_output=True)
        if p.returncode:
            raise RuntimeError(p.stderr.strip())
        try:
            return json.loads(p.stdout)
        except json.JSONDecodeError:
            return p.stdout.strip()

    report = {}
    try:
        op_true = b"\x51"
        miner = script_to_p2wsh(op_true)
        first = rpc("generatetoaddress", 1, miner)[0]
        rpc("generatetoaddress", 100, miner)
        while rpc("getdeploymentinfo")["deployments"]["tapleaf_0xc2"]["bip9"]["status"] != "active":
            rpc("generatetoaddress", 144, miner)
        cb = rpc("getblock", first, 2)["tx"][0]
        rid, other_rid = hashlib.sha256(b"rid").digest(), hashlib.sha256(b"other").digest()
        tmpl = Template(standin(b"\0" * 32, rid), 0, rid, 3)
        body = sweep_body(tmpl)
        user = generate_privkey()
        user_x = compute_xonly_pubkey(user)[0]
        delay = 5
        escrow = Escrow(hashlib.sha256(b"deposit").digest(), body, user_x, delay)

        def leaf_coin(script, key=NUMS):
            tr = taproot_construct(key, [("c", CScript(script), SWEEP_LEAF)])
            return bytes(tr.scriptPubKey), bytes([SWEEP_LEAF | tr.negflag]) + key
        good_spk, good_ctl = leaf_coin(standin(b"\x11" * 32, rid))
        rid2_spk, rid2_ctl = leaf_coin(standin(b"\x22" * 32, other_rid))
        bad_spk, bad_ctl = leaf_coin(standin(b"\x11" * 32, rid, b"\x51\x51\x75"))  # different template tail
        nk = compute_xonly_pubkey(generate_privkey())[0]
        key_spk, key_ctl = leaf_coin(standin(b"\x11" * 32, rid), nk)
        p2wsh = bytes(CScript(b"\x00\x20" + hashlib.sha256(op_true).digest()))
        mimic_ws = b"\x6d\x51"  # 2DROP TRUE: a valid P2WSH spend carrying the covenant leaf and control block
        mimic = bytes(CScript(b"\x00\x20" + hashlib.sha256(mimic_ws).digest()))
        outs = [good_spk, rid2_spk, bad_spk, key_spk, mimic] + [escrow.script_pubkey] * 6
        fund = CTransaction()
        fund.version = 2
        fund.vin = [CTxIn(COutPoint(int(cb["txid"], 16), 0))]
        fund.vout = [CTxOut(100_000, CScript(s)) for s in outs]
        fund.wit.vtxinwit = [CTxInWitness()]
        fund.wit.vtxinwit[0].scriptWitness.stack = [op_true]
        rpc("generateblock", miner, [fund.serialize().hex()])
        fid = fund.txid_hex
        coin = {s: i for i, s in reversed(list(enumerate(outs)))}
        escrow_vouts = list(range(5, 11))
        annex = b"\x50\x00" + b"\x00" * 10

        def attempt(name, first_vout, first_wit, escrow_vout, expect, seq=ESCROW_INPUT_SEQUENCE, escrow_wit=None,
                    sign=False):
            tx = CTransaction()
            tx.version = 2
            vins = ([CTxIn(COutPoint(int(fid, 16), first_vout), b"", 0xffffffff)] if first_vout is not None else [])
            tx.vin = vins + [CTxIn(COutPoint(int(fid, 16), escrow_vout), b"", seq)]
            tx.vout = [CTxOut(150_000 if first_vout is not None else 90_000, CScript(p2wsh))]
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
            if first_vout is not None:
                tx.wit.vtxinwit[0].scriptWitness.stack = first_wit
            w = escrow_wit or escrow.sweep_witness()
            if sign:
                spent = [CTxOut(100_000, CScript(outs[v])) for v in ([first_vout] if first_vout is not None else [])
                         + [escrow_vout]]
                h = TaprootSignatureHash(tx, spent, 0, len(tx.vin) - 1, scriptpath=True,
                                         leaf_script=CScript(escrow.refund), leaf_ver=REFUND_LEAF,
                                         codeseparator_pos=0xffffffff)
                w = [sign_schnorr(user, h), escrow.refund, escrow.control("refund", REFUND_LEAF)]
            tx.wit.vtxinwit[-1].scriptWitness.stack = w
            try:
                rpc("generateblock", miner, [tx.serialize().hex()])
                ok = True
                err = None
            except RuntimeError as e:
                ok, err = False, str(e).splitlines()[-1][:160]
            report[name] = {"accepted": ok, "expected": expect, **({"error": err} if err else {}),
                            "weight": tx.get_weight()}
            assert ok == expect, (name, err)
            assert ok or first_vout is None or "input 1 of" in err or "non-BIP68-final" in err, (name, err)
            return ok

        good_wit = [standin(b"\x11" * 32, rid), good_ctl, annex]
        # ESCROW_INPUT_SEQUENCE is also a BIP 68 lock of two blocks: a sweep never spends an unconfirmed escrow.
        attempt("reject_sweep_escrow_one_confirmation", coin[good_spk], good_wit, escrow_vouts[0], False)
        rpc("generatetoaddress", 1, miner)
        attempt("reject_template_mismatch", coin[bad_spk], [standin(b"\x11" * 32, rid, b"\x51\x51\x75"), bad_ctl, annex],
                escrow_vouts[0], False)
        attempt("reject_non_nums_internal_key", coin[key_spk], [standin(b"\x11" * 32, rid), key_ctl, annex],
                escrow_vouts[0], False)
        attempt("reject_p2wsh_mimic", coin[mimic], [standin(b"\x11" * 32, rid), good_ctl, mimic_ws], escrow_vouts[0],
                False)
        attempt("reject_no_annex", coin[good_spk], good_wit[:2], escrow_vouts[0], False)
        attempt("reject_escrow_alone", None, None, escrow_vouts[0], False)
        attempt("reject_refund_before_delay", None, None, escrow_vouts[0], False, seq=delay, sign=True)
        attempt("reject_sweep_without_escrow_sequence", coin[good_spk], good_wit, escrow_vouts[1], False,
                seq=0xffffffff)
        attempt("reject_escrow_without_annex", coin[good_spk], good_wit, escrow_vouts[0], False,
                escrow_wit=escrow.sweep_witness()[:2])
        attempt("reject_escrow_inflated_annex", coin[good_spk], good_wit, escrow_vouts[0], False,
                escrow_wit=escrow.sweep_witness()[:2] + [b"\x50\x00" + bytes(20_000)])
        attempt("accept_sweep_genuine_template", coin[good_spk], good_wit, escrow_vouts[0], True)
        attempt("reject_sweep_other_rollup_id_same_image", coin[rid2_spk],
                [standin(b"\x22" * 32, other_rid), rid2_ctl, annex], escrow_vouts[1], False)
        rpc("generatetoaddress", delay, miner)
        attempt("accept_refund_after_delay", None, None, escrow_vouts[2], True, seq=delay, sign=True)
        report["sweep_body_bytes"] = len(body)
        report["sweep_leaf_bytes"] = len(escrow.sweep)
    finally:
        rpc("stop")
        time.sleep(2)
    (work / "report.json").write_text(json.dumps(report, indent=2))
    return report


def vector() -> dict:
    """Known answer shared with crates/state-transition/src/escrow.rs."""
    sweep = sweep_leaf(b"\x11" * 32, b"\x51")
    refund = refund_leaf(b"\x22" * 32, 144)
    tr = taproot_construct(NUMS, [("sweep", CScript(sweep), SWEEP_LEAF), ("refund", CScript(refund), REFUND_LEAF)])
    return {"sweep_leaf": sweep.hex(), "sibling": tr.leaves["refund"].leaf_hash.hex(),
            "script_pubkey": bytes(tr.scriptPubKey).hex()}


if __name__ == "__main__":
    if sys.argv[1:] == ["vector"]:
        print(json.dumps(vector(), indent=2))
    elif sys.argv[1:] == ["node-test"]:
        print(json.dumps(node_test(), indent=2))
    else:
        sys.exit(__doc__)
