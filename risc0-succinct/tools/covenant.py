#!/usr/bin/env python3
"""Covenant demo: a Taproot output that only a valid `gsr_covenant` STARK proof can spend, and only to the
outputs committed in that proof's journal.

The guest (see risc0-v3.0.6.patch) proves knowledge of a SHA-256 preimage and commits a list of serialized
Bitcoin outputs as its journal. The Script reads the spending transaction's outputs with OP_TX, recomputes the claim
digest with them as the journal, and verifies the succinct receipt against that claim (see `Gen.covenant`).

    covenant.py              generate, meter the complete spend and run the negative suite
    covenant.py --regtest    additionally fund, policy-check, broadcast and mine it on an activated regtest node
"""
import argparse
import io
import json
import subprocess
import sys
from pathlib import Path

import differential as d
import generate as g
import measure
import reference as ref
from transaction import NUMS  # noqa: E402  (measure puts recursive-stwo/tools on sys.path)
from paths import BITCOIN_BUILD, BITCOIN_SOURCE  # noqa: E402

sys.path.insert(0, str(BITCOIN_SOURCE / "test/functional"))
from test_framework.address import output_key_to_p2tr  # noqa: E402
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut  # noqa: E402
from test_framework.script import CScript, taproot_construct  # noqa: E402

ROOT = g.ROOT
LEAF = 0xC2
FUNDING_VALUE = 5_000_000_000


def parse_outputs(journal: bytes) -> list:
    f, outs = io.BytesIO(journal), []
    while f.tell() < len(journal):
        o = CTxOut()
        o.deserialize(f)
        outs.append(o)
    return outs


class Covenant:
    def __init__(self, receipt: dict, seal: bytes) -> None:
        self.receipt, self.seal = receipt, seal
        self.journal = bytes.fromhex(receipt["journal"])
        self.gen = g.Gen(g.Statement(receipt, covenant=True), ref.load_circuit())
        first = self.gen.generate()[1]
        script, info = self.gen.generate(first["accesses"], first["pool"])
        self.script = bytes(script.code)
        self.functions = info["functions"]
        self.taproot = taproot_construct(NUMS, [("verifier", CScript(self.script), LEAF)])
        self.hints = g.prover_hints(self.gen, receipt, seal)

    def tx(self, txid: str = "00" * 32, index: int = 0, outputs: list | None = None) -> CTransaction:
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(txid, 16), index))]
        tx.vout = parse_outputs(self.journal) if outputs is None else outputs
        return tx

    def spend(self, tx: CTransaction, receipt: dict | None = None, seal: bytes | None = None,
              hints: list[bytes] | None = None) -> dict:
        """Fill `tx`'s witness with the receipt (default: the covenant receipt) and return the bundle."""
        witness = g.build_witness(self.gen, receipt or self.receipt, seal or self.seal,
                                  self.hints if hints is None else hints)
        control = bytes([LEAF | self.taproot.negflag]) + NUMS
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness + [self.script, control]
        return {"script": self.script.hex(), "witness": [w.hex() for w in witness],
                "info": {"functions": self.functions}}


def run(cov: Covenant, bundle: dict, tx: CTransaction) -> tuple[bool, dict]:
    e = measure.meter(bundle, tx, FUNDING_VALUE)
    return all(measure.limits(bundle, e).values()), e


def negative_cases(cov: Covenant) -> dict:
    """name -> (bundle, tx). Every case must be rejected by the complete-transaction meter."""
    cases = {}
    outs = parse_outputs(cov.journal)

    for name, outputs in {
        "output_value_minus_one": [CTxOut(outs[0].nValue - 1, outs[0].scriptPubKey)],
        "other_destination": [CTxOut(outs[0].nValue, CScript(b"\x51\x20" + bytes(32)))],
        "extra_output_appended": outs + [CTxOut(0, CScript(b"\x6a"))],
        "outputs_split": [CTxOut(outs[0].nValue // 2, outs[0].scriptPubKey)] * 2,
    }.items():
        tx = cov.tx(outputs=outputs)
        cases[name] = (cov.spend(tx), tx)

    tx = cov.tx()  # a valid receipt for a different image (the busy-loop fixture) with this journal
    busy = json.loads((ROOT / "fixtures/receipt.json").read_text())
    busy_seal = (ROOT / "fixtures/seal.bin").read_bytes()
    cases["valid_proof_of_other_image"] = (
        cov.spend(tx, receipt=busy, seal=busy_seal, hints=g.prover_hints(cov.gen, busy, busy_seal)), tx)

    tx = cov.tx()
    cases["tampered_seal"] = (cov.spend(tx, seal=d.flip(cov.seal, 40), hints=cov.hints), tx)
    return cases


def rpc(datadir: Path, method: str, *args):
    cmd = [str(BITCOIN_BUILD / "bin/bitcoin-cli"), "-regtest", f"-datadir={datadir}", "-rpcport=19472", "-stdin",
           method]
    proc = subprocess.run(cmd, input="".join((a if isinstance(a, str) else json.dumps(a)) + "\n" for a in args),
                          text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.stdout.strip()


def regtest(cov: Covenant) -> dict:
    datadir = ROOT / "build/regtest-covenant"
    subprocess.run(["rm", "-rf", str(datadir)], check=True)
    datadir.mkdir(parents=True)
    subprocess.run([str(BITCOIN_BUILD / "bin/bitcoind"), "-regtest", f"-datadir={datadir}", "-daemonwait", "-server",
                    "-listen=0", "-rpcport=19472", "-port=19473", "-vbparams=script_restoration:0:3999999999"],
                   check=True)
    try:
        address = output_key_to_p2tr(cov.taproot.output_pubkey)
        funding_block = rpc(datadir, "generatetoaddress", 1, address)[0]
        rpc(datadir, "generatetoaddress", 100, address)
        while rpc(datadir, "getdeploymentinfo")["deployments"]["script_restoration"]["bip9"]["status"] != "active":
            rpc(datadir, "generatetoaddress", 144, address)
        funding = rpc(datadir, "getblock", funding_block, 2)["tx"][0]
        index = next(i for i, o in enumerate(funding["vout"])
                     if o["scriptPubKey"]["hex"] == cov.taproot.scriptPubKey.hex())
        assert round(funding["vout"][index]["value"] * 100_000_000) == FUNDING_VALUE
        result: dict = {"address": address, "funding_txid": funding["txid"]}

        outs = parse_outputs(cov.journal)
        bad = cov.tx(funding["txid"], index, [CTxOut(outs[0].nValue - 1, outs[0].scriptPubKey)])
        cov.spend(bad)
        result["redirected_spend_acceptance"] = rpc(datadir, "testmempoolaccept", [bad.serialize().hex()])

        tx = cov.tx(funding["txid"], index)
        cov.spend(tx)
        raw = tx.serialize().hex()
        (ROOT / "build/covenant-spend.hex").write_text(raw + "\n")
        result["weight"] = tx.get_weight()
        result["mempool_acceptance"] = rpc(datadir, "testmempoolaccept", [raw])
        txid = rpc(datadir, "sendrawtransaction", raw)
        block = rpc(datadir, "generatetoaddress", 1, address)[0]
        mined = rpc(datadir, "getrawtransaction", txid, True, block)
        result.update(txid=txid, blockhash=block, mined=mined.get("confirmations") == 1,
                      spend_outputs=[{"value": o["value"], "scriptPubKey": o["scriptPubKey"]["hex"]}
                                     for o in mined["vout"]])
        return result
    finally:
        rpc(datadir, "stop")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", default=str(ROOT / "fixtures/covenant-receipt.json"))
    ap.add_argument("--seal", default=str(ROOT / "fixtures/covenant-seal.bin"))
    ap.add_argument("--regtest", action="store_true")
    args = ap.parse_args()
    receipt = json.loads(Path(args.receipt).read_text())
    seal = Path(args.seal).read_bytes()
    cov = Covenant(receipt, seal)
    failures = []

    native = d.native(receipt, seal)[1]
    reference = d.reference(receipt, seal)[1]
    rewritten = dict(receipt, journal=bytes(1).hex(), claim_digest=cov.gen.stmt.claim_for(bytes(1)).hex())
    native_rewritten = d.native(rewritten, seal)[1]
    if native != "NATIVE_OK" or reference != "REFERENCE_OK" or native_rewritten == "NATIVE_OK":
        failures.append("native/reference")

    tx = cov.tx()
    bundle = cov.spend(tx)
    ok, e = run(cov, bundle, tx)
    if not ok:
        failures.append("valid")
    keys = ("ok", "error", "transaction_weight", "budget", "varops", "sha256_calls", "function_calls",
            "invoked_body_bytes", "peak_entries", "peak_payload_bytes", "peak_element_bytes")
    report: dict = {"image_id": cov.gen.stmt.image_id.hex(), "journal": cov.journal.hex(),
                    "claim_digest": receipt["claim_digest"], "native": native, "reference": reference,
                    "native_other_journal": native_rewritten, "script_bytes": len(cov.script),
                    "witness_items": len(bundle["witness"]), **{k: e[k] for k in keys},
                    "limits": measure.limits(bundle, e), "negative": {}}
    for name, (b, t) in negative_cases(cov).items():
        accepted, en = run(cov, b, t)
        report["negative"][name] = en["error"]
        print(f"{name:36s} {'ACCEPTED' if accepted else 'rejected'}: {en['error']}")
        if accepted:
            failures.append(name)
    if args.regtest:
        report["regtest"] = regtest(cov)
        rt = report["regtest"]
        if not (rt["mempool_acceptance"][0]["allowed"] and rt["mined"]
                and not rt["redirected_spend_acceptance"][0]["allowed"]):
            failures.append("regtest")
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build/covenant-bundle.json").write_text(json.dumps(bundle))
    (ROOT / "build/covenant-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "negative"}, indent=1))
    print("FAILURES" if failures else "ALL_OK", failures)
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
