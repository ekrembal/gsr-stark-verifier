#!/usr/bin/env python3
"""Simulate ad6c16ff Tapleaf 0xc2 varops from the generated Script and witness."""

from __future__ import annotations

import hashlib
import json
import argparse
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import gsr_tooling
from measure import limits, meter
from pairing_script import build_pairing_script

CORE_BASE = 300
OP_DEPTH, OP_SUB, OP_PICK, OP_ROLL = 0x74, 0x94, 0x79, 0x7A
OP_MACRO, OP_CALLMACRO = 0xD0, 0xD1

OPS = {
    0x63: "IF", 0x64: "NOTIF", 0x67: "ELSE", 0x68: "ENDIF",
    0x69: "VERIFY", 0x6B: "TOALTSTACK", 0x6C: "FROMALTSTACK",
    0x6D: "2DROP", 0x6E: "2DUP", 0x6F: "3DUP", 0x70: "2OVER",
    0x72: "2SWAP", 0x74: "DEPTH", 0x75: "DROP", 0x76: "DUP",
    0x77: "NIP", 0x78: "OVER", 0x79: "PICK", 0x7A: "ROLL",
    0x7B: "ROT", 0x7C: "SWAP", 0x7D: "TUCK", 0x7E: "CAT",
    0x7F: "SUBSTR", 0x80: "LEFT", 0x81: "RIGHT", 0x82: "SIZE",
    0x84: "AND", 0x85: "OR", 0x86: "XOR", 0x87: "EQUAL",
    0x88: "EQUALVERIFY", 0x8B: "1ADD", 0x8C: "1SUB",
    0x8D: "2MUL", 0x8E: "2DIV", 0x93: "ADD", 0x94: "SUB",
    0x95: "MUL", 0x96: "DIV", 0x97: "MOD", 0x98: "LSHIFT",
    0x99: "RSHIFT", 0x9C: "NUMEQUAL", 0x9D: "NUMEQUALVERIFY",
    0x9F: "LESSTHAN", 0xA8: "SHA256",
}


def word_span(n: int) -> int:
    return (n + 7) // 8 * 8


def read_cost(n: int) -> int:
    return 350 + 2 * word_span(n)


def write_cost(n: int) -> int:
    return 800 + 7 * word_span(n)


def arith_cost(n: int) -> int:
    return 200 + 3 * word_span(n)


def move_cost(entries: int) -> int:
    return 200 + 23 * entries


def mul_cost(n: int, m: int) -> int:
    n, m = word_span(max(n, m)), word_span(min(n, m))
    return 700 + n + 18 * m + n * m


def div_cost(n: int, m: int) -> int:
    n, m = word_span(n), word_span(m)
    q = max(0, n - m)
    return 1150 + 60 * q + 11 * m + q * m


def hash_cost(n: int) -> int:
    return 50 + 40 * ((n + 72) // 64 * 64)


def encode_num(value: int, width: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("unsigned Script number is negative")
    size = (value.bit_length() + 7) // 8
    if width is not None:
        size = width
    return value.to_bytes(size, "little")


def script_push_num(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    if 1 <= value <= 16:
        return bytes([0x50 + value])
    data = encode_num(value)
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes([len(data)]) + data
    if len(data) <= 0xFFFF:
        return b"\x4d" + len(data).to_bytes(2, "little") + data
    return b"\x4e" + len(data).to_bytes(4, "little") + data


def read_compact(code: bytes, pos: int) -> tuple[int, int]:
    first = code[pos]
    if first < 253:
        return first, pos + 1
    width = {253: 2, 254: 4, 255: 8}[first]
    return int.from_bytes(code[pos + 1:pos + 1 + width], "little"), pos + 1 + width


@dataclass(frozen=True)
class Instruction:
    start: int
    end: int
    opcode: int
    data: bytes | None = None
    call: int | None = None


def instructions(code: bytes) -> list[Instruction]:
    result = []
    pos = 0
    while pos < len(code):
        start = pos
        op = code[pos]
        pos += 1
        if op == OP_CALLMACRO:
            index, pos = read_compact(code, pos)
            result.append(Instruction(start, pos, op, call=index))
        elif op <= 75:
            result.append(Instruction(start, pos + op, op, code[pos:pos + op]))
            pos += op
        elif op == 0x4C:
            size, pos = code[pos], pos + 1
            result.append(Instruction(start, pos + size, op, code[pos:pos + size]))
            pos += size
        elif op == 0x4D:
            size = int.from_bytes(code[pos:pos + 2], "little")
            pos += 2
            result.append(Instruction(start, pos + size, op, code[pos:pos + size]))
            pos += size
        elif op == 0x4E:
            size = int.from_bytes(code[pos:pos + 4], "little")
            pos += 4
            result.append(Instruction(start, pos + size, op, code[pos:pos + size]))
            pos += size
        else:
            result.append(Instruction(start, pos, op))
    if pos != len(code):
        raise ValueError("truncated instruction")
    return result


@dataclass
class MacroStats:
    length: int
    instructions: int
    references: int
    substituted: int


def macro_stats(code: bytes) -> tuple[MacroStats, int]:
    pos = 0
    bodies: list[MacroStats] = []
    while pos < len(code) and code[pos] == OP_MACRO:
        pos += 1
        size, pos = read_compact(code, pos)
        body = code[pos:pos + size]
        if len(body) != size:
            raise ValueError("truncated macro declaration")
        pos += size
        length = count = refs = substituted = 0
        for ins in instructions(body):
            if ins.call is None:
                length += ins.end - ins.start
                count += 1
            else:
                target = bodies[ins.call]
                length += target.length
                count += target.instructions
                refs += 1 + target.references
                substituted += target.instructions
        bodies.append(MacroStats(length, count, refs, substituted))

    length = count = refs = substituted = 0
    for ins in instructions(code[pos:]):
        if ins.call is None:
            length += ins.end - ins.start
            count += 1
        else:
            target = bodies[ins.call]
            length += target.length
            count += target.instructions
            refs += 1 + target.references
            substituted += target.instructions
    return MacroStats(length, count, refs, substituted), len(bodies)


class CostModel:
    def __init__(self, witness: list[bytes], ranges=None):
        self.stack = list(witness)
        self.alt: list[bytes] = []
        self.ranges = ranges or []
        self.total = 0
        self.by_opcode = Counter()
        self.opcode_counts = Counter()
        self.by_stage = Counter()
        self.heights: dict[int, int] = {}

    def stage_at(self, offset: int) -> str:
        for name, start, end in self.ranges:
            if start <= offset < end:
                return name
        return "unclassified"

    def run(self, code: bytes, charge=True) -> None:
        conditions = []
        for ins in instructions(code):
            self.heights[ins.start] = len(self.stack)
            op = ins.opcode
            extra = 0
            stage = self.stage_at(ins.start)

            def pop_num() -> tuple[int, bytes]:
                value = self.stack.pop()
                if charge:
                    nonlocal extra
                    extra += read_cost(len(value))
                return int.from_bytes(value, "little"), value

            def push_num(value: int, width: int | None = None, write=True) -> None:
                data = encode_num(value, width)
                self.stack.append(data)
                if charge and write:
                    nonlocal extra
                    extra += write_cost(len(data))

            def account() -> None:
                if charge:
                    amount = CORE_BASE + extra
                    self.total += amount
                    self.by_opcode[op] += amount
                    self.by_stage[stage] += amount

            executing = all(conditions)
            if op in (0x63, 0x64):
                branch = False
                if executing:
                    raw = self.stack.pop()
                    condition = int.from_bytes(raw, "little")
                    if len(raw) > 1 or raw not in (b"", b"\x01"):
                        raise ValueError(f"non-minimal conditional value at byte {ins.start}")
                    branch = bool(condition)
                    if op == 0x64:
                        branch = not branch
                conditions.append(branch)
                self.opcode_counts[op] += 1
                account()
                continue
            if op == 0x67:
                if not conditions:
                    raise ValueError(f"unbalanced ELSE at byte {ins.start}")
                conditions[-1] = not conditions[-1]
                self.opcode_counts[op] += 1
                account()
                continue
            if op == 0x68:
                if not conditions:
                    raise ValueError(f"unbalanced ENDIF at byte {ins.start}")
                conditions.pop()
                self.opcode_counts[op] += 1
                account()
                continue
            if not executing:
                continue

            self.opcode_counts[op] += 1
            if op <= 0x4E:
                if ins.data is None:
                    raise ValueError("push is missing data")
                self.stack.append(ins.data)
                if charge:
                    extra += write_cost(len(ins.data))
            elif 0x51 <= op <= 0x60:
                push_num(op - 0x50)
            elif op == 0x00:
                self.stack.append(b"")
                if charge:
                    extra += write_cost(0)
            elif op == 0x6B:
                self.alt.append(self.stack.pop())
                if charge:
                    extra += move_cost(1)
            elif op == 0x6C:
                self.stack.append(self.alt.pop())
                if charge:
                    extra += move_cost(1)
            elif op == 0x6D:
                del self.stack[-2:]
            elif op == 0x6E:
                a, b = self.stack[-2:]
                self.stack.extend((a, b))
                if charge:
                    extra += write_cost(len(a)) + write_cost(len(b))
            elif op == 0x6F:
                values = self.stack[-3:]
                self.stack.extend(values)
                if charge:
                    extra += sum(write_cost(len(x)) for x in values)
            elif op == 0x70:
                values = self.stack[-4:-2]
                self.stack.extend(values)
                if charge:
                    extra += sum(write_cost(len(x)) for x in values)
            elif op == 0x72:
                a, b, c, d = self.stack[-4:]
                self.stack[-4:] = (c, d, a, b)
                if charge:
                    extra += move_cost(4)
            elif op == 0x74:
                push_num(len(self.stack))
            elif op == 0x75:
                self.stack.pop()
            elif op == 0x76:
                self.stack.append(self.stack[-1])
                if charge:
                    extra += write_cost(len(self.stack[-1]))
            elif op == 0x77:
                del self.stack[-2]
                if charge:
                    extra += move_cost(2)
            elif op == 0x78:
                self.stack.append(self.stack[-2])
                if charge:
                    extra += write_cost(len(self.stack[-1]))
            elif op in (0x79, 0x7A):
                depth, _ = pop_num()
                if depth >= len(self.stack):
                    raise ValueError(f"invalid stack depth {depth} at byte {ins.start}")
                if op == 0x79:
                    self.stack.append(self.stack[-1 - depth])
                    if charge:
                        extra += write_cost(len(self.stack[-1]))
                else:
                    value = self.stack.pop(-1 - depth)
                    self.stack.append(value)
                    if charge:
                        extra += move_cost(depth + 1)
            elif op == 0x7B:
                a, b, c = self.stack[-3:]
                self.stack[-3:] = (b, c, a)
                if charge:
                    extra += move_cost(3)
            elif op == 0x7C:
                self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
                if charge:
                    extra += move_cost(2)
            elif op == 0x7D:
                a, b = self.stack[-2:]
                self.stack.extend((b,))
                self.stack[-3:] = (b, a, b)
                if charge:
                    extra += write_cost(len(b)) + move_cost(2)
            elif op == 0x7E:
                b, a = self.stack.pop(), self.stack.pop()
                value = a + b
                self.stack.append(value)
                if charge:
                    extra += write_cost(len(value))
            elif op in (0x7F, 0x80, 0x81):
                size, _ = pop_num()
                begin = 0
                if op == 0x7F:
                    begin, _ = pop_num()
                value = self.stack.pop()
                start = min(begin, len(value))
                length = min(size, len(value) - start)
                if charge and op in (0x7F, 0x81):
                    extra += arith_cost(length)
                result = value[start:start + length] if op != 0x81 else value[len(value) - length:]
                self.stack.append(result)
            elif op == 0x82:
                push_num(len(self.stack[-1]))
            elif op in (0x84, 0x85, 0x86):
                b, bb = pop_num()
                a, ab = pop_num()
                if charge:
                    extra += arith_cost(max(len(ab), len(bb)))
                if op == 0x84:
                    result = a & b
                elif op == 0x85:
                    result = a | b
                else:
                    result = a ^ b
                push_num(result, max(len(ab), len(bb)), write=False)
            elif op in (0x87, 0x88):
                b, a = self.stack.pop(), self.stack.pop()
                if charge and len(a) == len(b):
                    extra += read_cost(len(a))
                result = a == b
                if op == 0x88:
                    if not result:
                        raise ValueError(f"EQUALVERIFY failed at byte {ins.start}")
                else:
                    push_num(int(result))
            elif op in (0x8B, 0x8C, 0x8D, 0x8E):
                value, raw = pop_num()
                if charge:
                    extra += arith_cost(len(raw))
                if op == 0x8B:
                    push_num(value + 1)
                elif op == 0x8C:
                    if value == 0:
                        raise ValueError(f"1SUB underflow at byte {ins.start}")
                    push_num(value - 1, write=False)
                elif op == 0x8D:
                    push_num(value * 2)
                else:
                    push_num(value // 2, write=False)
            elif op in (0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9C, 0x9D, 0x9F):
                if op in (0x98, 0x99):
                    bits, _ = pop_num()
                    value, raw = pop_num()
                    if charge:
                        extra += arith_cost(len(raw))
                    if op == 0x98:
                        width = len(raw) + (bits + 7) // 8
                        push_num(value << bits, width)
                    else:
                        push_num(value >> bits)
                elif op in (0x93, 0x94, 0x95, 0x96, 0x97):
                    b, bb = pop_num()
                    a, ab = pop_num()
                    if op in (0x93, 0x94) and charge:
                        extra += arith_cost(max(len(ab), len(bb)))
                    if op == 0x93:
                        push_num(a + b)
                    elif op == 0x94:
                        if a < b:
                            raise ValueError(f"SUB underflow at byte {ins.start}")
                        push_num(a - b, write=False)
                    elif op == 0x95:
                        extra += mul_cost(len(ab), len(bb))
                        extra += write_cost(word_span(len(ab)) + word_span(len(bb)))
                        push_num(a * b, write=False)
                    else:
                        if b == 0:
                            raise ValueError(f"division by zero at byte {ins.start}")
                        if op == 0x97:
                            extra += div_cost(len(encode_num(a)), len(encode_num(b)))
                            push_num(a % b, write=False)
                        else:
                            extra += div_cost(len(encode_num(a)), len(encode_num(b)))
                            push_num(a // b, write=False)
                else:
                    b, bb = pop_num()
                    a, ab = pop_num()
                    result = a == b if op in (0x9C, 0x9D) else a < b
                    if op == 0x9D:
                        if not result:
                            raise ValueError(f"NUMEQUALVERIFY failed at byte {ins.start}")
                    else:
                        push_num(int(result))
            elif op == 0x69:
                value, _ = pop_num()
                if value == 0:
                    raise ValueError(f"VERIFY failed at byte {ins.start}")
            elif op == 0xA8:
                value = self.stack.pop()
                if charge:
                    extra += hash_cost(len(value)) + write_cost(32)
                self.stack.append(hashlib.sha256(value).digest())
            else:
                raise ValueError(f"unsupported opcode 0x{op:02x} at byte {ins.start}")

            account()
        if conditions:
            raise ValueError("unterminated conditional")


def anchor_script(raw: bytes, stack: list[bytes], threshold: int, stage_ranges):
    scan = CostModel(stack)
    scan.run(raw, charge=False)
    ops = instructions(raw)
    output = bytearray()
    offsets = {0: 0}
    i = 0
    while i < len(ops):
        ins = ops[i]
        offsets[ins.start] = len(output)
        if (ins.data is not None or ins.opcode == 0 or 0x51 <= ins.opcode <= 0x60) and i + 1 < len(ops):
            following = ops[i + 1]
            if following.opcode in (OP_PICK, OP_ROLL):
                if ins.opcode == 0:
                    depth = 0
                elif 0x51 <= ins.opcode <= 0x60:
                    depth = ins.opcode - 0x50
                else:
                    depth = int.from_bytes(ins.data or b"", "little")
                if depth >= threshold:
                    height = scan.heights[ins.start]
                    output.extend(bytes([OP_DEPTH]))
                    output.extend(script_push_num(height - depth))
                    output.extend(bytes([OP_SUB, following.opcode]))
                    offsets[following.end] = len(output)
                    offsets[ins.end] = len(output)
                    i += 2
                    continue
        output.extend(raw[ins.start:ins.end])
        offsets[ins.end] = len(output)
        i += 1

    mapped = []
    for name, (start, end) in stage_ranges.items():
        if start not in offsets or end not in offsets:
            raise ValueError(f"stage boundary {name} is not an instruction boundary")
        mapped.append((name, offsets[start], offsets[end]))
    return bytes(output), mapped


def decode_macros(code: bytes) -> tuple[bytes, MacroStats, int]:
    stats, declarations = macro_stats(code)
    unroll = gsr_tooling.run("unroll", script=code)
    if unroll.returncode:
        raise RuntimeError(unroll.stderr.strip())
    return bytes.fromhex(unroll.stdout.strip()), stats, declarations


def meter_opcode_counts(opcodes: dict) -> Counter:
    return Counter({int(key.rsplit("_", 1)[-1]): value for key, value in opcodes.items()})


def opcode_name(op: int) -> str:
    if op == 0:
        return "OP_0"
    if 1 <= op <= 75:
        return f"OP_PUSHBYTES_{op}"
    if op == 0x4C:
        return "OP_PUSHDATA1"
    if op == 0x4D:
        return "OP_PUSHDATA2"
    if op == 0x4E:
        return "OP_PUSHDATA4"
    if 0x51 <= op <= 0x60:
        return f"OP_{op - 0x50}"
    return f"OP_{OPS.get(op, f'UNKNOWN_{op:02X}')}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "bundle",
        nargs="?",
        default=str(ROOT / "build/v1-fixed-current.json"),
    )
    parser.add_argument("--annex-bytes", type=int, default=0)
    args = parser.parse_args()
    path = Path(args.bundle)
    bundle = json.loads(path.read_text())
    fixture = json.loads((ROOT / "fixtures/receipt.json").read_text())
    raw_script, witness = build_pairing_script(fixture, "fixed")
    if [x.hex() for x in witness.stack] != bundle["witness"]:
        raise ValueError("bundle witness does not match the Python twin")

    compressed = bytes.fromhex(bundle["script"])
    depth = bundle["info"]["compression"]["anchor"]["min_depth"]
    anchored, mapped_ranges = anchor_script(raw_script.code, witness.stack, depth, witness.stage_ranges)
    external_anchor, _ = gsr_tooling.rewrite(
        "anchor", "--min-depth", str(depth), "--protect", "0", script=raw_script.code
    )
    if anchored != external_anchor:
        raise ValueError("static anchor reconstruction differs from gsr anchor")
    unrolled, stats, declarations = decode_macros(compressed)
    if unrolled != anchored or len(unrolled) != stats.length:
        raise ValueError("compressed bundle does not unroll to the modeled anchored script")

    precharge_units = stats.substituted + stats.references
    unroll_charge = precharge_units * CORE_BASE
    if declarations:
        unroll_charge += write_cost(stats.length)
    model = CostModel(witness.stack, mapped_ranges)
    model.run(unrolled)
    if len(model.stack) != 1 or not int.from_bytes(model.stack[0], "little"):
        raise ValueError("the static interpreter did not produce one truthy result")
    final_check = read_cost(len(model.stack[0]))
    model.total += final_check
    model.by_stage["final_stack_check"] += final_check
    model.total += unroll_charge
    model.by_opcode["MACRO_UNROLL"] += unroll_charge
    model.by_stage["macro_unroll"] += unroll_charge

    execution = meter(bundle, annex_bytes=args.annex_bytes)
    counts_match = model.opcode_counts == meter_opcode_counts(execution["opcodes"])
    result = {
        "model_varops": model.total,
        "meter_varops": execution["varops"],
        "difference": model.total - execution["varops"],
        "runtime_varops": model.total - unroll_charge - final_check,
        "measurement": {
            "ok": execution["ok"],
            "transaction_weight": execution["transaction_weight"],
            "budget": execution["budget"],
            "committed_script_bytes": len(compressed),
            "unrolled_script_bytes": execution["unrolled_bytes"],
            "witness_items": len(bundle["witness"]),
            "witness_bytes": sum(len(bytes.fromhex(item)) for item in bundle["witness"]),
            "peak_stack_entries": execution["peak_entries"],
            "peak_stack_payload_bytes": execution["peak_payload_bytes"],
            "largest_stack_element_bytes": execution["peak_element_bytes"],
            "limits": limits(bundle, execution),
        },
        "macro_precharge": {
            "declarations": declarations,
            "expanded_bytes": stats.length,
            "references": stats.references,
            "substituted_instructions": stats.substituted,
            "units": precharge_units,
            "varops": unroll_charge,
        },
        "opcode_counts_match": counts_match,
        "opcodes": {
            f"0x{op:02x} {opcode_name(op)}": {
                "count": model.opcode_counts[op],
                "varops": model.by_opcode[op],
            }
            for op in sorted(model.opcode_counts)
        },
        "non_opcode_varops": {"macro_unroll": unroll_charge},
        "stages": dict(sorted(model.by_stage.items())),
    }
    print(json.dumps(result, indent=2))
    if result["difference"] or not counts_match:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
