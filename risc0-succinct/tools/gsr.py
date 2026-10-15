"""Tapscript v2 assembler with a symbolic stack model, and runners for the pinned interpreter."""
import json
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BITCOIN_UTIL = REPOSITORY_ROOT / "build" / "bitcoin" / "bin" / "bitcoin-util"
EVAL_BUDGET = 4_000_000_000_000

OPS = {
    "0": 0x00, "IF": 0x63, "NOTIF": 0x64, "ELSE": 0x67, "ENDIF": 0x68, "VERIFY": 0x69, "RETURN": 0x6A,
    "TOALTSTACK": 0x6B, "FROMALTSTACK": 0x6C, "2DROP": 0x6D, "2DUP": 0x6E, "3DUP": 0x6F, "2OVER": 0x70,
    "2SWAP": 0x72, "DEPTH": 0x74, "DROP": 0x75, "DUP": 0x76, "NIP": 0x77, "OVER": 0x78, "PICK": 0x79,
    "ROLL": 0x7A, "ROT": 0x7B, "SWAP": 0x7C, "TUCK": 0x7D, "CAT": 0x7E, "SUBSTR": 0x7F, "LEFT": 0x80,
    "RIGHT": 0x81, "SIZE": 0x82, "AND": 0x84, "OR": 0x85, "XOR": 0x86, "EQUAL": 0x87, "EQUALVERIFY": 0x88,
    "1ADD": 0x8B, "1SUB": 0x8C, "2MUL": 0x8D, "2DIV": 0x8E, "ADD": 0x93, "SUB": 0x94, "MUL": 0x95,
    "DIV": 0x96, "MOD": 0x97, "LSHIFT": 0x98, "RSHIFT": 0x99, "NUMEQUAL": 0x9C, "NUMEQUALVERIFY": 0x9D,
    "LESSTHAN": 0x9F, "SHA256": 0xA8, "DEFINE": 0xBB, "INVOKE": 0xBC, "TX": 0xBD, "MULTI": 0xBF,
    "CHECKSEQUENCEVERIFY": 0xB2, "TWEAKADD": 0xBE,
}


V2_KEPT = {0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xCC, 0xCF}


def is_op_success(op: int) -> bool:
    """Core's `IsOpSuccess` for tapscript v2."""
    return (op in (0x4F, 0x50, 0x62, 0x89, 0x8A, 0x8F, 0x90)) or (187 <= op <= 254 and op not in V2_KEPT)


def op_success_offsets(code: bytes) -> list[int]:
    """Top-level OP_SUCCESSx offsets. Consensus makes any such script succeed unconditionally before executing it
    (`CheckTapscriptOpSuccess`), a pre-scan the standalone execution meter does not perform."""
    found, i = [], 0
    while i < len(code):
        op = code[i]
        if is_op_success(op):
            found.append(i)
        i += 1
        if 1 <= op <= 75:
            i += op
        elif op in (0x4C, 0x4D, 0x4E):
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            i += width + int.from_bytes(code[i:i + width], "little")
    return found


def num(n: int) -> bytes:
    """Unsigned little-endian encoding without high-order zero bytes, as Tapscript v2 arithmetic produces."""
    assert n >= 0
    return n.to_bytes((n.bit_length() + 7) // 8, "little")


class Script:
    def __init__(self) -> None:
        self.code = bytearray()

    def op(self, *names: str) -> "Script":
        for name in names:
            self.code.append(OPS[name])
        return self

    def data(self, value: bytes) -> "Script":
        """Minimal push (MINIMALDATA): empty and 1..16 use their dedicated opcodes. The single byte 0x81 has no
        legal push in tapscript v2 (MINIMALDATA demands OP_1NEGATE, which is OP_SUCCESS there), so it is built as
        0x80 + 1."""
        n = len(value)
        if n == 0:
            self.code.append(0x00)
            return self
        if n == 1 and 1 <= value[0] <= 16:
            self.code.append(0x50 + value[0])
            return self
        if value == b"\x81":
            self.code += bytes([0x01, 0x80, 0x51, OPS["ADD"]])
            return self
        if n <= 75:
            self.code += bytes([n])
        elif n <= 0xFF:
            self.code += bytes([0x4C, n])
        elif n <= 0xFFFF:
            self.code += bytes([0x4D]) + n.to_bytes(2, "little")
        else:
            self.code += bytes([0x4E]) + n.to_bytes(4, "little")
        self.code += value
        return self

    def int(self, n: int) -> "Script":
        if n == 0:
            self.code.append(0x00)
        elif n <= 16:
            self.code.append(0x50 + n)
        else:
            self.data(num(n))
        return self

    def extend(self, other: "Script") -> "Script":
        self.code += other.code
        return self


class V:
    """A symbolic stack value. `bound` is an exclusive upper bound on every 96-bit lane (or on the scalar)."""

    __slots__ = ("tag", "bound", "ext", "sid")
    serial = 0

    def __init__(self, tag: str = "", bound: int = 0, ext: bool = False) -> None:
        self.tag, self.bound, self.ext = tag, bound, ext
        self.sid = V.serial
        V.serial += 1

    def __repr__(self) -> str:
        return f"<{self.tag}>"


class Asm:
    """Emits Script while tracking the symbolic stack (top = last) so depths are computed, never hand-written."""

    def __init__(self, stack: list[V] | None = None, plan: dict[int, int] | None = None) -> None:
        self.s = Script()
        self.st: list[V] = list(stack or [])
        # Liveness: `accesses` counts pick/roll per value; with a `plan` (the counts of an identical earlier
        # pass) the last pick of a value becomes a roll, so dead values leave the stack as soon as possible.
        self.accesses: dict[int, int] = {}
        self.plan, self.active = plan, True

    def access(self, v: V) -> bool:
        """Record an access; True when a planned pick is the value's last access."""
        n = self.accesses.get(v.sid, 0) + 1
        self.accesses[v.sid] = n
        return self.active and self.plan is not None and self.plan.get(v.sid) == n

    # stack model
    def depth(self, v: V) -> int:
        st = self.st
        for i in range(len(st) - 1, -1, -1):
            if st[i] is v:
                return len(st) - 1 - i
        raise KeyError(v)

    def has(self, v: V) -> bool:
        return any(x is v for x in self.st)

    def top(self, k: int = 0) -> V:
        return self.st[-1 - k]

    # emission
    def op(self, name: str, pops: int, *pushes: V) -> "Asm":
        self.s.op(name)
        assert len(self.st) >= pops, name
        if pops:
            del self.st[-pops:]
        self.st.extend(pushes)
        return self

    def raw(self, script: Script, pops: int, *pushes: V) -> "Asm":
        self.s.extend(script)
        if pops:
            del self.st[-pops:]
        self.st.extend(pushes)
        return self

    def push(self, value, v: V | None = None) -> V:
        v = v or V("k")
        if isinstance(value, int):
            self.s.int(value)
            if not v.bound:
                v.bound = value + 1
        else:
            self.s.data(value)
        self.st.append(v)
        return v

    def pick(self, v: V) -> V:
        if self.access(v):
            V.serial += 1  # the copy a pick would have made, so serials match the planning pass
            return self._roll(v)
        d = self.depth(v)
        c = V(v.tag, v.bound, v.ext)
        if d == 0:
            self.s.op("DUP")
        elif d == 1:
            self.s.op("OVER")
        else:
            self.s.int(d).op("PICK")
        self.st.append(c)
        return c

    def roll(self, v: V) -> V:
        self.access(v)
        return self._roll(v)

    def _roll(self, v: V) -> V:
        d = self.depth(v)
        if d == 0:
            return v
        if d == 1:
            self.s.op("SWAP")
        elif d == 2:
            self.s.op("ROT")
        else:
            self.s.int(d).op("ROLL")
        del self.st[len(self.st) - 1 - d]
        self.st.append(v)
        return v

    def fetch(self, v: V, consume: bool) -> V:
        return self.roll(v) if consume else self.pick(v)

    def drop(self, v: V) -> None:
        self.roll(v)
        self.op("DROP", 1)

    def drop_top(self, n: int) -> None:
        while n >= 2:
            self.op("2DROP", 2)
            n -= 2
        if n:
            self.op("DROP", 1)

    def call(self, fid: int, pops: int, *pushes: V) -> "Asm":
        self.s.int(fid).op("INVOKE")
        if pops:
            del self.st[-pops:]
        self.st.extend(pushes)
        return self


def evalscript(script: Script, stack: list[bytes]) -> dict:
    request = {"protocol": 1, "sigversion": "tapscript_v2", "script": script.code.hex(),
               "stack": [item.hex() for item in stack], "varops_budget": EVAL_BUDGET}
    out = subprocess.run([str(BITCOIN_UTIL), "evalscript"], input=json.dumps(request), capture_output=True,
                         text=True, check=True).stdout
    result = json.loads(out)
    result["varops"] = EVAL_BUDGET - result["varops-budget-remaining"]
    return result


def assemble(ops: list) -> Script:
    """Ints become minimal pushes, bytes become data pushes, strings become opcodes."""
    s = Script()
    for o in ops:
        if isinstance(o, str):
            s.op(o)
        elif isinstance(o, int):
            s.int(o)
        else:
            s.data(bytes(o))
    return s


def probe(script: Script, stack: list[bytes]) -> tuple[list[int], int, str | None]:
    """Run `script` and return the resulting stack (top last) as integers; leaves a sentinel so it never cleanly
    succeeds, which is how the interpreter reports the final stack."""
    s = Script().extend(script).int(1).int(1)
    r = evalscript(s, stack)
    err = r["error"]
    if err and "exactly one" in err:
        err = None
    items = [int.from_bytes(bytes.fromhex(x), "little") for x in r["stack-after"]]
    return items[:-2] if err is None else items, r["varops"], err
