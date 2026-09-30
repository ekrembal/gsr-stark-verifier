#!/usr/bin/env python3
"""Reference verifier for RISC Zero v3.0.6 succinct receipts under the `sha-256-padded` hash suite.

A line-by-line port of risc0_zkp::verify::verify and SuccinctReceipt::verify_integrity_with_context. It is
the specification the Script generator is written against: every value the Script derives (transcript
state, challenges, query positions, Merkle roots, FRI goals) is recorded in `Trace` so generated Script can be
checked against it phase by phase, and acceptance is differentially tested against the native verifier.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import babybear as bb
from babybear import P

ROOT = Path(__file__).resolve().parents[1]
PROOF_SYSTEM_INFO = b"RISC0_STARK:v1__"
QUERIES = 50
INV_RATE = 4
FRI_FOLD = 16
FRI_MIN_DEGREE = 256
MAX_CYCLES_PO2 = 24
CHECK_SIZE = INV_RATE * 4
GROUP_ACCUM, GROUP_CODE, GROUP_DATA = 0, 1, 2


class VerifyError(Exception):
    """kind mirrors risc0 VerificationError variants."""


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def words_bytes(words) -> bytes:
    return struct.pack(f"<{len(words)}I", *words)


class Rng:
    def __init__(self) -> None:
        self.pool0, self.pool1, self.used = sha(b"Hello"), sha(b"World"), 0

    def mix(self, digest: bytes) -> None:
        self.pool0 = bytes(x ^ y for x, y in zip(self.pool0, digest))
        self.step()

    def step(self) -> None:
        self.pool0 = sha(self.pool0 + self.pool1)
        self.pool1 = sha(self.pool0 + self.pool1)
        self.used = 0

    def next_u32(self) -> int:
        if self.used == 8:
            self.step()
        out = struct.unpack_from("<I", self.pool0, 4 * self.used)[0]
        self.used += 1
        return out

    def random_bits(self, bits: int) -> int:
        return ((1 << bits) - 1) & self.next_u32()

    def random_elem(self) -> int:
        val = 0
        for _ in range(6):
            val = ((val << 32) + self.next_u32()) % P
        return val

    def random_ext(self) -> tuple:
        return tuple(self.random_elem() for _ in range(4))


class ReadIOP:
    def __init__(self, seal: list[int], trace: dict) -> None:
        self.seal, self.pos, self.rng, self.trace = seal, 0, Rng(), trace

    def read_u32s(self, n: int) -> list[int]:
        if self.pos + n > len(self.seal):
            raise VerifyError("ReceiptFormatError")
        out = self.seal[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_elems(self, n: int) -> list[int]:
        """Raw (Montgomery) words, each checked to be a canonical encoding (< P)."""
        out = self.read_u32s(n)
        if any(w >= P for w in out):
            raise VerifyError("ReceiptFormatError")
        return out

    def commit(self, digest: bytes) -> None:
        self.trace.setdefault("commits", []).append(digest.hex())
        self.rng.mix(digest)

    def verify_complete(self) -> None:
        if self.pos != len(self.seal):
            raise VerifyError("ReceiptFormatError")


def top_size_for(row_size: int, queries: int = QUERIES) -> int:
    layers = row_size.bit_length() - 1
    assert 1 << layers == row_size
    top_layer = 0
    for i in range(1, layers):
        if (1 << i) > queries:
            break
        top_layer = i
    return 1 << top_layer


class MerkleVerifier:
    def __init__(self, iop: ReadIOP, row_size: int, col_size: int) -> None:
        self.row_size, self.col_size = row_size, col_size
        self.top_size = top_size_for(row_size)
        raw = iop.read_u32s(8 * self.top_size)
        self.top = [words_bytes(raw[8 * i:8 * i + 8]) for i in range(self.top_size)]
        self.rest: list = [None] * (self.top_size - 1)
        for i in reversed(range(self.top_size // 2, self.top_size)):
            t = 2 * i - self.top_size
            self.rest[i - 1] = sha(self.top[t] + self.top[t + 1])
        for i in reversed(range(1, self.top_size // 2)):
            self.rest[i - 1] = sha(self.rest[2 * i - 1] + self.rest[2 * i])
        self.root = self.rest[0] if self.rest else self.top[1 - self.top_size]
        iop.commit(self.root)

    def verify(self, iop: ReadIOP, idx: int) -> list[int]:
        if idx >= self.row_size:
            raise VerifyError("MerkleQueryOutOfRange")
        out = iop.read_elems(self.col_size)
        cur = sha(words_bytes(out))
        idx += self.row_size
        while idx >= 2 * self.top_size:
            low_bit = idx % 2
            other = words_bytes(iop.read_u32s(8))
            idx //= 2
            cur = sha(other + cur) if low_bit else sha(cur + other)
        present = self.top[idx - self.top_size] if idx >= self.top_size else self.rest[idx - 1]
        if present != cur:
            raise VerifyError("InvalidProof")
        return out


def load_circuit() -> dict:
    return json.loads((ROOT / "fixtures/circuit.json").read_text())


class TapSet:
    def __init__(self, c: dict) -> None:
        self.taps, self.combo_taps, self.combo_begin = c["taps"], c["combo_taps"], c["combo_begin"]
        self.group_begin, self.combos_count = c["group_begin"], c["combos_count"]
        self.reg_count, self.tot_combo_backs = c["reg_count"], c["tot_combo_backs"]
        self.num_taps = self.group_begin[-1]
        self.regs = []
        cursor = 0
        while cursor < len(self.taps):
            t = self.taps[cursor]
            self.regs.append({"group": t["group"], "offset": t["offset"], "combo": t["combo"],
                              "size": t["skip"],
                              "backs": [self.taps[cursor + i]["back"] for i in range(t["skip"])]})
            cursor += t["skip"]
        assert len(self.regs) == self.reg_count

    def group_size(self, g: int) -> int:
        return self.taps[self.group_begin[g + 1] - 1]["offset"] + 1

    def combo(self, i: int) -> list[int]:
        return self.combo_taps[self.combo_begin[i]:self.combo_begin[i + 1]]


def poly_ext(block: list, ret: int, mix: tuple, u: list, args: list) -> tuple:
    fp, mx = [], []
    for step in block:
        op = step[0]
        if op == "Const":
            fp.append(bb.e(step[1]))
        elif op == "ConstExt":
            fp.append(tuple(x % P for x in step[1:5]))
        elif op == "Get":
            fp.append(u[step[1]])
        elif op == "GetGlobal":
            fp.append(bb.e(args[step[1]][step[2]]))
        elif op == "Add":
            fp.append(bb.add(fp[step[1]], fp[step[2]]))
        elif op == "Sub":
            fp.append(bb.sub(fp[step[1]], fp[step[2]]))
        elif op == "Mul":
            fp.append(bb.mul(fp[step[1]], fp[step[2]]))
        elif op == "True":
            mx.append((bb.ZERO, bb.ONE))
        elif op == "AndEqz":
            tot, m = mx[step[1]]
            mx.append((bb.add(tot, bb.mul(m, fp[step[2]])), bb.mul(m, mix)))
        elif op == "AndCond":
            tot, m = mx[step[1]]
            itot, imul = mx[step[3]]
            mx.append((bb.add(tot, bb.mul(bb.mul(fp[step[2]], itot), m)), bb.mul(m, imul)))
        else:
            raise ValueError(op)
    return mx[ret][0]


def ext_from_words(raw: list[int]) -> tuple:
    return tuple(bb.from_mont(w) for w in raw)


def verify_seal(seal: list[int], trace: dict, check_code) -> list[int]:
    """risc0_zkp::verify::verify for the recursion circuit; returns the decoded output globals."""
    circuit = load_circuit()
    taps = TapSet(circuit)
    if not seal:
        raise VerifyError("ReceiptFormatError")
    iop = ReadIOP(seal, trace)

    def info_hash(info: bytes) -> bytes:
        return sha(words_bytes([bb.to_mont(b) for b in info] + [0] * (16 - len(info))))

    iop.commit(info_hash(PROOF_SYSTEM_INFO))
    iop.commit(info_hash(circuit["circuit_info"].encode()))

    raw = iop.read_elems(circuit["output_size"] + 1)
    iop.commit(sha(words_bytes(raw)))
    out = [bb.from_mont(w) for w in raw[:-1]]
    po2 = raw[-1]  # to_u32_words of an Elem is its Montgomery word
    if po2 > MAX_CYCLES_PO2:
        raise VerifyError("ReceiptFormatError")
    tot_cycles = 1 << po2
    domain = INV_RATE * tot_cycles
    trace.update(po2=po2, out=out)

    groups: list = [None] * 3
    groups[GROUP_CODE] = MerkleVerifier(iop, domain, taps.group_size(GROUP_CODE))
    check_code(po2, groups[GROUP_CODE].root)
    groups[GROUP_DATA] = MerkleVerifier(iop, domain, taps.group_size(GROUP_DATA))
    mix = [iop.rng.random_elem() for _ in range(circuit["mix_size"])]
    groups[GROUP_ACCUM] = MerkleVerifier(iop, domain, taps.group_size(GROUP_ACCUM))
    trace.update(roots=[g.root.hex() for g in groups], mix=mix)

    poly_mix = iop.rng.random_ext()
    check_merkle = MerkleVerifier(iop, domain, CHECK_SIZE)
    z = iop.rng.random_ext()
    back_one = bb.ROU_REV[po2]
    coeff_raw = iop.read_elems(4 * (taps.num_taps + CHECK_SIZE))
    iop.commit(sha(words_bytes(coeff_raw)))
    coeff_u = [ext_from_words(coeff_raw[4 * i:4 * i + 4]) for i in range(taps.num_taps + CHECK_SIZE)]

    eval_u, cur_pos = [], 0
    for reg in taps.regs:
        for i in range(reg["size"]):
            x = bb.scale(z, pow(back_one, reg["backs"][i], P))
            eval_u.append(bb.poly_eval(coeff_u[cur_pos:cur_pos + reg["size"]], x))
        cur_pos += reg["size"]
    result = poly_ext(circuit["poly_ext"]["block"], circuit["poly_ext"]["ret"], poly_mix, eval_u, [out, mix])

    check = bb.ZERO
    nt = taps.num_taps
    for i, rmi in enumerate([0, 2, 1, 3]):
        zi = bb.power(z, i)
        for k in range(4):
            unit = tuple(1 if j == k else 0 for j in range(4))
            check = bb.add(check, bb.mul(bb.mul(coeff_u[nt + rmi + 4 * k], zi), unit))
    check = bb.mul(check, bb.sub(bb.power(bb.scale(z, 3), tot_cycles), bb.ONE))
    trace.update(poly_mix=poly_mix, z=z, result=result, check=check, check_root=check_merkle.root.hex())
    if check != result:
        raise VerifyError("InvalidProof")

    fri_mix = iop.rng.random_ext()
    combo_u = [bb.ZERO] * (taps.tot_combo_backs + 1)
    cur_mix, cur_pos = bb.ONE, 0
    tap_mix_pows, check_mix_pows = [], []
    for reg in taps.regs:
        for i in range(reg["size"]):
            k = taps.combo_begin[reg["combo"]] + i
            combo_u[k] = bb.add(combo_u[k], bb.mul(cur_mix, coeff_u[cur_pos + i]))
        tap_mix_pows.append(cur_mix)
        cur_mix = bb.mul(cur_mix, fri_mix)
        cur_pos += reg["size"]
    for _ in range(CHECK_SIZE):
        k = taps.tot_combo_backs
        combo_u[k] = bb.add(combo_u[k], bb.mul(cur_mix, coeff_u[cur_pos]))
        cur_pos += 1
        check_mix_pows.append(cur_mix)
        cur_mix = bb.mul(cur_mix, fri_mix)
    trace.update(fri_mix=fri_mix, combo_u=combo_u)

    gen = bb.ROU_FWD[domain.bit_length() - 1]

    def fri_eval_taps(pos: int) -> tuple:
        x = pow(gen, pos, P)
        rows = [[bb.from_mont(w) for w in g.verify(iop, pos)] for g in groups]
        check_row = [bb.from_mont(w) for w in check_merkle.verify(iop, pos)]
        tot = [bb.ZERO] * (taps.combos_count + 1)
        for reg, cur in zip(taps.regs, tap_mix_pows):
            tot[reg["combo"]] = bb.add(tot[reg["combo"]], bb.scale(cur, rows[reg["group"]][reg["offset"]]))
        for i, cur in enumerate(check_mix_pows):
            tot[-1] = bb.add(tot[-1], bb.scale(cur, check_row[i]))
        ret = bb.ZERO
        xe = bb.e(x)
        for i in range(taps.combos_count):
            num = bb.sub(tot[i], bb.poly_eval(combo_u[taps.combo_begin[i]:taps.combo_begin[i + 1]], xe))
            divisor = bb.ONE
            for back in taps.combo(i):
                divisor = bb.mul(divisor, bb.sub(xe, bb.scale(z, pow(back_one, back, P))))
            ret = bb.add(ret, bb.mul(num, bb.inv(divisor)))
        check_num = bb.sub(tot[-1], combo_u[taps.tot_combo_backs])
        check_div = bb.sub(xe, bb.power(z, INV_RATE))
        return bb.add(ret, bb.mul(check_num, bb.inv(check_div)))

    # FRI
    degree = tot_cycles
    orig_domain = domain
    rounds: list[dict] = []
    while degree > FRI_MIN_DEGREE:
        domain //= FRI_FOLD
        merkle = MerkleVerifier(iop, domain, FRI_FOLD * 4)
        rounds.append({"domain": domain, "merkle": merkle, "mix": iop.rng.random_ext()})
        degree //= FRI_FOLD
    final_raw = iop.read_elems(4 * degree)
    iop.commit(sha(words_bytes(final_raw)))
    final_vals = [bb.from_mont(w) for w in final_raw]
    final_poly = [tuple(final_vals[j * degree + i] for j in range(4)) for i in range(degree)]
    fgen = bb.ROU_FWD[domain.bit_length() - 1]
    trace.update(fri_round_mix=[r["mix"] for r in rounds], final_poly=final_poly, queries=[])
    for _ in range(QUERIES):
        pos = iop.rng.random_bits(orig_domain.bit_length() - 1)
        q: dict = {"pos": pos}
        goal = fri_eval_taps(pos)
        q["goals"] = [goal]
        for r in rounds:
            quot, group = pos // r["domain"], pos % r["domain"]
            data = [bb.from_mont(w) for w in r["merkle"].verify(iop, group)]
            data_ext = [tuple(data[j * FRI_FOLD + i] for j in range(4)) for i in range(FRI_FOLD)]
            if data_ext[quot] != goal:
                raise VerifyError("InvalidProof")
            root_po2 = (FRI_FOLD * r["domain"]).bit_length() - 1
            inv_wk = pow(bb.ROU_REV[root_po2], group, P)
            bb.interpolate_ntt(data_ext)
            bb.bit_reverse(data_ext)
            goal = bb.poly_eval(data_ext, bb.scale(r["mix"], inv_wk))
            pos = group
            q["goals"].append(goal)
        fx = bb.poly_eval(final_poly, bb.e(pow(fgen, pos, P)))
        q["final_pos"] = pos
        trace["queries"].append(q)
        if fx != goal:
            raise VerifyError("InvalidProof")
    iop.verify_complete()
    return out


def tagged_struct(tag: str, down: list[bytes], data: list[int]) -> bytes:
    return sha(sha(tag.encode()) + b"".join(down) + b"".join(struct.pack("<I", d) for d in data)
               + struct.pack("<H", len(down)))


def verify_receipt(receipt: dict, seal_bytes: bytes, trace: dict | None = None) -> None:
    """SuccinctReceipt::verify_integrity_with_context with fixed verifier parameters from `receipt`."""
    trace = {} if trace is None else trace
    if receipt["hashfn"] != "sha-256-padded":
        raise VerifyError("InvalidHashSuite")
    if receipt["proof_system_info"] != PROOF_SYSTEM_INFO.decode():
        raise VerifyError("ProofSystemInfoMismatch")
    if receipt["circuit_info"] != load_circuit()["circuit_info"]:
        raise VerifyError("CircuitInfoMismatch")
    if len(seal_bytes) % 4:
        raise VerifyError("ReceiptFormatError")
    seal = list(struct.unpack(f"<{len(seal_bytes) // 4}I", seal_bytes))
    control_id = bytes.fromhex(receipt["control_id"])
    control_root = bytes.fromhex(receipt["control_root"])
    proof = receipt["control_inclusion_proof"]

    def check_code(_po2: int, code_root: bytes) -> None:
        if code_root != control_id:
            raise VerifyError("ControlVerificationError")
        cur, index = code_root, proof["index"]
        for sibling in proof["digests"]:
            s = bytes.fromhex(sibling)
            cur = sha(cur + s) if index & 1 == 0 else sha(s + cur)
            index >>= 1
        if cur != control_root:
            raise VerifyError("ControlVerificationError")

    out = verify_seal(seal, trace, check_code)
    inner = bytes.fromhex(receipt["inner_control_root"] or receipt["control_root"])
    if words_bytes(out[0:16:2]) != inner:
        raise VerifyError("ControlVerificationError")
    halves = out[16:32]
    if any(h >= 1 << 16 for h in halves):
        raise VerifyError("ReceiptFormatError")
    if b"".join(struct.pack("<H", h) for h in halves) != bytes.fromhex(receipt["claim_digest"]):
        raise VerifyError("JournalDigestMismatch")


def claim_digest(c: dict) -> bytes:
    """ReceiptClaim digest from its component digests (risc0-zkvm claim/receipt.rs)."""
    return tagged_struct("risc0.ReceiptClaim", [bytes.fromhex(c[k]) for k in ("input", "pre", "post", "output")],
                         [c["sys_exit"], c["user_exit"]])


def output_digest(journal_digest: bytes, assumptions_digest: bytes) -> bytes:
    return tagged_struct("risc0.Output", [journal_digest, assumptions_digest], [])


def main() -> None:
    receipt = json.loads(Path(sys.argv[1]).read_text())
    seal = Path(sys.argv[2]).read_bytes()
    try:
        verify_receipt(receipt, seal)
        print("REFERENCE_OK")
    except VerifyError as err:
        print("REFERENCE_ERR", err)


if __name__ == "__main__":
    main()
