#!/usr/bin/env python3
"""Covenant demo: a Taproot output that only a valid `gsr_covenant` STARK proof can spend, and only to the
outputs committed in that proof's journal.

The guest (see risc0-v3.0.6.patch) proves knowledge of a SHA-256 preimage and commits the spending
transaction's BIP 341 serialized outputs as its journal. The Script verifies the succinct receipt, recomputes the
claim digest from the image ID and the witness journal, and binds SHA256(journal) to the transaction's
`sha_outputs` through a CHECKSIGFROMSTACK + CHECKSIG pair over the same signature (see `Gen.covenant`).

    covenant.py              generate, sign, meter the complete spend and run the negative suite
    covenant.py --regtest    additionally fund, policy-check, broadcast and mine it on an activated regtest node
"""
import argparse
import hashlib
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
from test_framework.key import compute_xonly_pubkey, sign_schnorr  # noqa: E402
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut  # noqa: E402
from test_framework.script import CScript, TaggedHash, TaprootSignatureMsg, taproot_construct  # noqa: E402

ROOT = g.ROOT
LEAF = 0xC2
SPENDER_KEY = hashlib.sha256(b"gsr covenant demo spender").digest()
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

    def sighash_msg(self, tx: CTransaction, value: int, hash_type: int = 0) -> bytes:
        return TaprootSignatureMsg(tx, [CTxOut(value, self.taproot.scriptPubKey)], hash_type, 0, scriptpath=True,
                                   leaf_script=CScript(self.script), leaf_ver=LEAF,
                                   codeseparator_pos=0xFFFFFFFF)

    def spend(self, tx: CTransaction, value: int = FUNDING_VALUE, receipt: dict | None = None,
              seal: bytes | None = None, hints: list[bytes] | None = None, **over: bytes) -> dict:
        """Fill `tx`'s witness with an honest spend (any COVENANT_ITEMS in `over` replaced); returns the bundle."""
        msg = self.sighash_msg(tx, value)
        items = {"journal": self.journal, "sig": sign_schnorr(SPENDER_KEY, TaggedHash("TapSighash", msg)),
                 "pubkey": compute_xonly_pubkey(SPENDER_KEY)[0],
                 "sighash_prefix": msg[:g.SIGHASH_PREFIX], "sighash_suffix": msg[g.SIGHASH_PREFIX + 32:], **over}
        witness = g.build_witness(self.gen, receipt or self.receipt, seal or self.seal,
                                  self.hints if hints is None else hints, items)
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
    other = [CTxOut(outs[0].nValue - 1, outs[0].scriptPubKey)]
    other_journal = b"".join(o.serialize() for o in other)

    tx = cov.tx(outputs=other)
    cases["tx_outputs_differ_from_journal"] = (cov.spend(tx), tx)

    tx = cov.tx(outputs=other)
    cases["journal_rewritten_to_match_tx"] = (cov.spend(tx, journal=other_journal), tx)

    tx = cov.tx(outputs=other)  # a CHECKSIGFROMSTACK-valid signature over the message the journal implies
    fake = cov.sighash_msg(cov.tx(), FUNDING_VALUE)
    cases["sig_over_journal_message_not_tx"] = (
        cov.spend(tx, sig=sign_schnorr(SPENDER_KEY, TaggedHash("TapSighash", fake)),
                  sighash_prefix=fake[:g.SIGHASH_PREFIX], sighash_suffix=fake[g.SIGHASH_PREFIX + 32:]), tx)

    tx = cov.tx()
    msg = cov.sighash_msg(tx, FUNDING_VALUE)
    cases["sighash_prefix_shifted"] = (cov.spend(tx, sighash_prefix=msg[:g.SIGHASH_PREFIX - 1],
                                                 sighash_suffix=msg[g.SIGHASH_PREFIX - 1 + 32:]), tx)

    tx = cov.tx()
    msg = cov.sighash_msg(tx, FUNDING_VALUE, hash_type=1)
    cases["sighash_all_65_byte_sig"] = (
        cov.spend(tx, sig=sign_schnorr(SPENDER_KEY, TaggedHash("TapSighash", msg)) + b"\x01",
                  sighash_prefix=msg[:g.SIGHASH_PREFIX], sighash_suffix=msg[g.SIGHASH_PREFIX + 32:]), tx)

    tx = cov.tx()  # unknown (non-32-byte) public keys make both signature opcodes succeed without checking
    cases["unknown_pubkey_type"] = (cov.spend(tx, pubkey=b"\x02" + compute_xonly_pubkey(SPENDER_KEY)[0],
                                              sig=bytes(64)), tx)

    tx = cov.tx()
    cases["sig_from_other_key"] = (cov.spend(tx, pubkey=compute_xonly_pubkey(bytes(31) + b"\x07")[0]), tx)

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
