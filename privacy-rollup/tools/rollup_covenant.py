#!/usr/bin/env python3
"""The gsr-privacy-pool settlement covenant: one fixed Taproot leaf, `decls || 1 CSV DROP || suffix`.

Every state of a rollup lives at the same address; the state root is published in output 1 as
`OP_RETURN <new_root>` (non-witness data, checked by the guest through the output digest). The leaf
  * requires that it runs as input 0 of a coin whose only leaf is itself under the NUMS internal key;
  * requires output 0 to pay its own scriptPubKey (input 0's, read with OP_TX);
  * rebuilds the 196-byte batch journal from OP_TX: version, rollup id, old root and new root (two 32-byte
    witness items), SHA256(version, locktime, every input), SHA256(every output), SHA256(annex);
  * verifies the RISC Zero succinct receipt of `apply_batch` against the claim of that journal.

The old root is a witness item, not part of the script: the guest accepts it only if the predecessor
settlement (whose txid input 0 commits to) published it in its output 1 and has a receipt itself, or if it
is the descriptor's genesis root. Amounts, sequence, version, locktime, funding inputs and every output are
bound through the input/output digests, so the guest's interpretation of the transaction is the transaction.
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
import compress  # noqa: E402
import generate as g  # noqa: E402
import reference as ref  # noqa: E402
from gsr import Asm, Script, V, assemble, op_success_offsets  # noqa: E402
from transaction import NUMS  # noqa: E402
from paths import BITCOIN_SOURCE  # noqa: E402

sys.path.insert(0, str(BITCOIN_SOURCE / "test/functional"))
from test_framework.messages import (  # noqa: E402
    COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string_vector)
from test_framework.script import CScript, taproot_construct  # noqa: E402

LEAF = 0xC2
METER = REPO / "recursive-stwo/build/harness/gsr-meter"
INPUTS_SELECTOR = bytes([0x00, 0x07, 0x00, 0x20, 0x3F, 0x00])
OUTPUTS_SELECTOR = bytes([0x00, 0x01, 0x00, 0x02, 0x00, 0x03])
ANNEX_SELECTOR = bytes([0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
INDEX_SELECTOR = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
SHAPE_SELECTOR = bytes([0x00, 0x00, 0x08 | 0x20 | 0x40, 0x00, 0x00, 0x00])  # leaf hash, internal key, root
INPUT_SPK_SELECTOR = bytes([0x00, 0x00, 0x00, 0x30, 0x08, 0x00])  # scriptPubKey of the input given below it


def tag2(name: str) -> bytes:
    return hashlib.sha256(name.encode()).digest() * 2


class RollupStatement(g.Statement):
    extra_items = ("old_root", "new_root")

    def __init__(self, receipt: dict, rollup_id: bytes) -> None:
        super().__init__(receipt, covenant=True)
        assert len(rollup_id) == 32
        self.rollup_id = rollup_id
        self.jd: V | None = None

    def head(self) -> Script:
        return assemble([1, "CHECKSEQUENCEVERIFY", "DROP"])

    def prologue(self, m: Asm, items: dict[str, V], heads: list[V]) -> None:
        old, new = items["old_root"], items["new_root"]
        g.Gen.size_check(m, old, 32)
        g.Gen.size_check(m, new, 32)
        m.push(INDEX_SELECTOR)
        m.raw(assemble(["TX", 0, "EQUALVERIFY"]), 1)
        m.push(SHAPE_SELECTOR)
        m.raw(assemble(["TX", "ROT", "EQUALVERIFY", NUMS, "EQUALVERIFY"]), 1)

        m.push(OUTPUTS_SELECTOR)
        outs = m.op("TX", 1, V("outputs")).top()
        m.pick(outs)
        m.push(9)
        m.push(34)
        m.op("SUBSTR", 3, V("out0_spk"))
        m.push(0)
        m.push(INPUT_SPK_SELECTOR)
        m.op("TX", 2, V("own_spk"))
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
    """The rollup's covenant leaf and its fixed address; the same for every state of the rollup."""

    def __init__(self, receipt: dict, rollup_id: bytes, compressed: bool = True) -> None:
        stmt = RollupStatement(receipt, rollup_id)
        self.gen = g.Gen(stmt, ref.load_circuit())
        first = self.gen.generate()[1]
        script, info = self.gen.generate(first["accesses"], first["pool"])
        code = bytes(script.code)
        self.compression = None
        if compressed:
            code, self.compression = compress.compress(code)
        self.script = code
        assert 0x10000 <= len(self.script) < 1 << 32
        assert not op_success_offsets(self.script)
        self.functions = info["functions"]
        self.taproot = taproot_construct(NUMS, [("rollup", CScript(self.script), LEAF)])
        self.script_pubkey = bytes(self.taproot.scriptPubKey)
        self.control = bytes([LEAF | self.taproot.negflag]) + NUMS

    def witness(self, receipt: dict, seal: bytes, old_root: bytes, new_root: bytes, annex: bytes,
                hints=None) -> list[bytes]:
        items = g.build_witness(self.gen, receipt, seal, hints)
        return items + [old_root, new_root, self.script, self.control, annex]


def state_root_script(root: bytes) -> bytes:
    """Output 1 of every settlement (pr_protocol_types::state_root_script)."""
    assert len(root) == 32
    return b"\x6a\x20" + root


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
    """GetTransactionVaropsBudget: weight minus every input that does not run Tapleaf 0xC2, less one signature
    check (500,000) for each Tapleaf 0xC2 input's commitment check."""
    weight, commitments = tx.get_weight(), 0
    for txin, wit, spk in zip(tx.vin, tx.wit.vtxinwit, spent_spks):
        stack = list(wit.scriptWitness.stack)
        if len(stack) >= 2 and stack[-1][:1] == b"\x50":
            stack = stack[:-1]
        taproot = len(spk) == 34 and spk[:2] == b"\x51\x20"
        if not (taproot and len(stack) >= 2 and stack[-1] and stack[-1][0] & 0xFE == LEAF):
            weight -= 4 * len(txin.serialize())
            weight -= len(ser_string_vector(wit.scriptWitness.stack))
        else:
            commitments += 1
    return weight * 10_000 - commitments * 500_000


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
        "unrolled_bytes": e["unrolled_bytes"] <= 4000000,
        "stack_entries": e["peak_entries"] <= 32768,
        "live_payload": e["peak_payload_bytes"] <= 8000000,
        "single_element": e["peak_element_bytes"] <= 4000000,
        "verifier": e["ok"] and e["final_stack_exact_true"] and not e["immediate_success"],
    }
