#!/usr/bin/env python3
"""The privacy-rollup settlement covenant: one Taproot leaf per state, `<old_root> 1 CSV DROP || suffix`.

The suffix is fixed for the rollup (it embeds the rollup id and the `apply_batch` image through the claim). It
  * requires that it runs as input 0 of a coin whose only leaf is itself under the NUMS internal key;
  * derives the successor leaf from its own tapscript (read with OP_TX) by replacing the 32-byte state root,
    tweaks NUMS with it (OP_TWEAKADD) and requires output 0 to pay exactly that P2TR key;
  * rebuilds the 196-byte batch journal from OP_TX: version, rollup id, old root (the script prefix), new root
    (one witness item), SHA256(version, locktime, every input), SHA256(every output), SHA256(annex);
  * verifies the RISC Zero succinct receipt of `apply_batch` against the claim of that journal.

Amounts, sequence, version, locktime, funding inputs and every output are bound through the input/output
digests, so the guest's interpretation of the transaction is the transaction.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "risc0-succinct/tools"))
sys.path.insert(0, str(REPO / "recursive-stwo/tools"))
import generate as g  # noqa: E402
import reference as ref  # noqa: E402
from gsr import Asm, Script, V, assemble, op_success_offsets  # noqa: E402
from transaction import NUMS  # noqa: E402
from paths import BITCOIN_SOURCE  # noqa: E402

sys.path.insert(0, str(BITCOIN_SOURCE / "test/functional"))
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut  # noqa: E402
from test_framework.script import CScript, taproot_construct  # noqa: E402

LEAF = 0xC2
METER = REPO / "recursive-stwo/build/harness/gsr-meter"
INPUTS_SELECTOR = bytes([0x00, 0x07, 0x00, 0x20, 0x3F, 0x00])
OUTPUTS_SELECTOR = bytes([0x00, 0x01, 0x00, 0x02, 0x00, 0x03])
ANNEX_SELECTOR = bytes([0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
INDEX_SELECTOR = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
SHAPE_SELECTOR = bytes([0x00, 0x00, 0x08 | 0x20 | 0x40, 0x00, 0x00, 0x00])  # leaf hash, internal key, root
TAPSCRIPT_SELECTOR = bytes([0x00, 0x01, 0x04, 0x00, 0x00, 0x00])
CS_PREFIX = 5  # 0xfe || u32: the script is 64 KiB..4 GiB (asserted)
ROOT_END = CS_PREFIX + 33


def tag2(name: str) -> bytes:
    return hashlib.sha256(name.encode()).digest() * 2


class RollupStatement(g.Statement):
    extra_items = ("new_root",)
    head_names = ("old_root",)

    def __init__(self, receipt: dict, rollup_id: bytes, old_root: bytes) -> None:
        super().__init__(receipt, covenant=True)
        assert len(rollup_id) == 32 and len(old_root) == 32
        self.rollup_id, self.old_root = rollup_id, old_root
        self.jd: V | None = None

    def head(self) -> Script:
        return assemble([self.old_root, 1, "CHECKSEQUENCEVERIFY", "DROP"])

    def prologue(self, m: Asm, items: dict[str, V], heads: list[V]) -> None:
        old, new = heads[0], items["new_root"]
        g.Gen.size_check(m, new, 32)
        m.push(INDEX_SELECTOR)
        m.raw(assemble(["TX", 0, "EQUALVERIFY"]), 1)
        m.push(SHAPE_SELECTOR)
        m.raw(assemble(["TX", "ROT", "EQUALVERIFY", NUMS, "EQUALVERIFY"]), 1)

        m.push(TAPSCRIPT_SELECTOR)
        ts = m.op("TX", 1, V("tapscript")).top()
        m.push(tag2("TapLeaf") + bytes([LEAF]))
        m.pick(ts)
        m.push(CS_PREFIX)
        m.raw(assemble(["LEFT", "CAT", b"\x20", "CAT"]), 3, V("leaf_head"))
        m.pick(new)
        m.op("CAT", 2, V("leaf_mid"))
        m.roll(ts)
        m.push(ROOT_END)
        m.push(0xFFFFFFFF)
        m.raw(assemble(["SUBSTR", "CAT", "SHA256"]), 4, V("leaf"))
        leaf = m.top()
        m.push(tag2("TapTweak") + NUMS)
        m.roll(leaf)
        m.raw(assemble(["CAT", "SHA256", NUMS, "TWEAKADD", b"\x22\x51\x20", "SWAP", "CAT"]), 2, V("spk0"))
        spk0 = m.top()
        m.push(OUTPUTS_SELECTOR)
        outs = m.op("TX", 1, V("outputs")).top()
        m.pick(outs)
        m.push(8)
        m.push(35)
        m.op("SUBSTR", 3, V("out0_spk"))
        m.roll(spk0)
        m.raw(assemble(["EQUALVERIFY"]), 2)

        m.push(struct.pack("<I", 1) + self.rollup_id)
        m.roll(old)
        m.op("CAT", 2, V("j"))
        m.roll(new)
        m.op("CAT", 2, V("j"))
        m.push(INPUTS_SELECTOR)
        m.raw(assemble(["TX", "SHA256", "CAT"]), 2, V("j"))
        j = m.top()
        m.roll(outs)
        m.roll(j)
        m.raw(assemble(["SWAP", "SHA256", "CAT"]), 2, V("j"))
        m.push(ANNEX_SELECTOR)
        m.raw(assemble(["TX", "SHA256", "CAT", "SHA256"]), 2, V("jd"))
        self.jd = m.top()

    def journal_digest(self, m: Asm) -> V:
        assert self.jd is not None
        return self.jd


class Covenant:
    """The covenant leaf for one state root. The suffix after the root is identical for every root."""

    def __init__(self, receipt: dict, rollup_id: bytes, root: bytes) -> None:
        self.gen = g.Gen(RollupStatement(receipt, rollup_id, root), ref.load_circuit())
        first = self.gen.generate()[1]
        script, info = self.gen.generate(first["accesses"], first["pool"])
        self.script = bytes(script.code)
        assert self.script[:33] == b"\x20" + root and 0x10000 <= len(self.script) < 1 << 32
        assert not op_success_offsets(self.script)
        self.functions = info["functions"]
        self.taproot = taproot_construct(NUMS, [("rollup", CScript(self.script), LEAF)])
        self.script_pubkey = bytes(self.taproot.scriptPubKey)
        self.control = bytes([LEAF | self.taproot.negflag]) + NUMS

    def for_root(self, root: bytes) -> "Covenant":
        """The leaf of another state of the same rollup: only the 32-byte prefix changes."""
        other = object.__new__(Covenant)
        other.gen, other.functions = self.gen, self.functions
        other.script = b"\x20" + root + self.script[33:]
        other.taproot = taproot_construct(NUMS, [("rollup", CScript(other.script), LEAF)])
        other.script_pubkey = bytes(other.taproot.scriptPubKey)
        other.control = bytes([LEAF | other.taproot.negflag]) + NUMS
        return other

    def witness(self, receipt: dict, seal: bytes, new_root: bytes, annex: bytes, hints=None) -> list[bytes]:
        items = g.build_witness(self.gen, receipt, seal, hints)
        return items + [new_root, self.script, self.control, annex]


def successor_script_pubkey(cov: Covenant, new_root: bytes) -> bytes:
    """What the Script derives: the same leaf with the root replaced, single leaf under NUMS."""
    return cov.for_root(new_root).script_pubkey


def settlement_tx(batch: dict) -> CTransaction:
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(COutPoint(int.from_bytes(bytes.fromhex(i["txid"]), "little"), i["vout"]), b"", i["sequence"])
              for i in batch["inputs"]]
    tx.vout = [CTxOut(o["value"], CScript(bytes.fromhex(o["script_pubkey"]))) for o in batch["outputs"]]
    tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
    return tx


def varops_budget(tx: CTransaction, spent_spks: list[bytes]) -> int:
    """GetTransactionVaropsBudget: weight minus every input that does not run tapscript v2."""
    weight = tx.get_weight()
    for txin, wit, spk in zip(tx.vin, tx.wit.vtxinwit, spent_spks):
        stack = list(wit.scriptWitness.stack)
        if len(stack) >= 2 and stack[-1][:1] == b"\x50":
            stack = stack[:-1]
        taproot = len(spk) == 34 and spk[:2] == b"\x51\x20"
        if not (taproot and len(stack) >= 2 and stack[-1] and stack[-1][0] & 0xFE == LEAF):
            weight -= 4 * len(txin.serialize())
            weight -= len(wit.scriptWitness.serialize())
    return weight * 10_000


def meter(cov: Covenant, tx: CTransaction, batch: dict, path: Path) -> dict:
    spent = [(i["amount"], bytes.fromhex(i["script_pubkey"])) for i in batch["inputs"]]
    request = {"script": cov.script.hex(), "witness": [w.hex() for w in tx.wit.vtxinwit[0].scriptWitness.stack[:-3]],
               "info": {"functions": cov.functions}, "budget": varops_budget(tx, [s for _, s in spent]),
               "transaction_hex": tx.serialize().hex(),
               "spent_outputs": [{"value": v, "script_pub_key": s.hex()} for v, s in spent],
               "stage_script_ends": []}
    path.write_text(json.dumps(request))
    proc = subprocess.run([str(METER), str(path)], capture_output=True, text=True)
    if not proc.stdout:
        raise RuntimeError(proc.stderr or f"meter exit {proc.returncode}")
    return json.loads(proc.stdout)


def limits(cov: Covenant, e: dict) -> dict:
    return {
        "standard_weight": e["transaction_weight"] <= 400000,
        "varops": e["varops"] <= e["budget"],
        "invoked_body_bytes": e["invoked_body_bytes"] <= 4000000,
        "function_ids": len(cov.functions) <= 256,
        "stack_entries": e["peak_entries"] <= 32768,
        "live_payload": e["peak_payload_bytes"] <= 8000000,
        "single_element": e["peak_element_bytes"] <= 4000000,
        "verifier": e["ok"] and e["final_stack_exact_true"] and not e["immediate_success"],
    }
