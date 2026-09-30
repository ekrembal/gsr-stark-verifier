"""Minimal Tapscript v2 assembler and a runner for the pinned `bitcoin-util evalscript`."""
import json
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BITCOIN_UTIL = REPOSITORY_ROOT / "build" / "bitcoin" / "bin" / "bitcoin-util"
BUDGET = 4_000_000_000_000

OPS = {
    "0": 0x00, "DEPTH": 0x74, "DROP": 0x75, "2DROP": 0x6D, "DUP": 0x76, "NIP": 0x77, "OVER": 0x78,
    "PICK": 0x79, "ROLL": 0x7A, "ROT": 0x7B, "SWAP": 0x7C, "TUCK": 0x7D, "2DUP": 0x6E,
    "TOALTSTACK": 0x6B, "FROMALTSTACK": 0x6C,
    "CAT": 0x7E, "SUBSTR": 0x7F, "LEFT": 0x80, "RIGHT": 0x81, "SIZE": 0x82, "AND": 0x84, "OR": 0x85,
    "XOR": 0x86, "EQUAL": 0x87, "EQUALVERIFY": 0x88, "ADD": 0x93, "SUB": 0x94, "MUL": 0x95, "DIV": 0x96,
    "MOD": 0x97, "LSHIFT": 0x98, "RSHIFT": 0x99, "NUMEQUALVERIFY": 0x9D, "SHA256": 0xA8, "MULTI": 0xBF,
    "DEFINE": 0xBB, "INVOKE": 0xBC,
}


def num(n: int) -> bytes:
    """Unsigned little-endian encoding without high-order zero bytes, as Tapscript v2 arithmetic produces."""
    return n.to_bytes((n.bit_length() + 7) // 8, "little")


class Script:
    def __init__(self) -> None:
        self.code = bytearray()

    def op(self, *names: str) -> "Script":
        for name in names:
            self.code.append(OPS[name])
        return self

    def data(self, value: bytes) -> "Script":
        n = len(value)
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


def run(script: Script, stack: list[bytes]) -> tuple[bool, int, list[str], str]:
    request = {
        "protocol": 1,
        "sigversion": "tapscript_v2",
        "script": script.code.hex(),
        "stack": [item.hex() for item in stack],
        "varops_budget": BUDGET,
    }
    out = subprocess.run([str(BITCOIN_UTIL), "evalscript"], input=json.dumps(request), capture_output=True,
                         text=True, check=True).stdout
    result = json.loads(out)
    return result["success"], BUDGET - result["varops-budget-remaining"], result["stack-after"], result["error"]
