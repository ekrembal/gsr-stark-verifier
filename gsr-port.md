# Port to jmoik/bitcoin `gsr`

The `bitcoin` submodule tracks `jmoik/bitcoin` branch `gsr` (`ad6c16f`) instead of `gsr-full` (`d279905`). The
`gsr` branch uses the gsr-net opcode set.

| | `gsr-full` | `gsr` |
|---|---|---|
| `OP_TX` | 0xbd | 0xbf |
| Functions | `OP_DEFINE` 0xbb / `OP_INVOKE` 0xbc | reusable macros: `OP_MACRO` 0xd0 declarations open the script; `OP_CALLMACRO` 0xd1 `<CompactSize index>` |
| `OP_MULTI` 0xbf | yes | no |
| Deployment | `script_restoration` | `tapleaf_0xc2` |
| `bitcoin-util evalscript` sigversion | `tapscript_v2` | `tapleaf_0xc2` |

The OP_TX selector format (six bytes, versioned) is unchanged.

## Results (regtest, `gsr` @ `ad6c16f`)

| | `gsr-full` (cited) | `gsr` | `gsr`, compressed |
|---|---:|---:|---:|
| RISC Zero verifier script, fixed statement | 158,572 B | 160,600 B | 101,393 B |
| Covenant spend with the committed receipt | 388,641 WU | 390,661 WU | **331,097 WU** |
| Rollup settlement leaf | 159,265 B | 161,252 B | 101,688 B |
| Rollup settlement, one ZK deposit join-split | 392,001 WU | ≈ 394,000 WU (est.) | **334,460 WU** (measured) |

- **Port (+2 kB).** Expanding `OP_MULTI` costs about 2 kB (mostly `<6> OP_MULTI OP_ADD` at 514 sites); macro
  declarations and calls are slightly smaller than `OP_DEFINE`/`OP_INVOKE`. The uncompressed verifier is
  byte-identical to the gsr-full script converted by an independent converter whose output was mined on gsr-net.
- **Compression (−59 kB).** About three quarters of the main script is stack routing (depth pushes, `PICK`, `ROLL`)
  in short patterns that recur hundreds of times. `compress.py` moves them into 512 new, nested macros; the unrolled
  script (3,361,215 B, 84% of the 4 MB limit) is unchanged. Varops rise by the unrolling charge (1.767B → 1.793B
  for the fixed statement), about 54% of the budget.
- **Same verifier.** `risc0-succinct/tools/check_compression.py` checks that compression changes only what the
  reusable-macros BIP allows: the compressed scripts are well formed and unroll to the uncompressed ones byte for
  byte, and neither reads anything that depends on the script bytes; under `evalscript`, the inline, plain and
  compressed verifiers give the same result, error and final stack on the valid witness and 200 mutated ones, and
  (under `gsr-meter`) stop at the same instruction of the unrolled script, at 146 distinct positions, with varops
  differing by exactly the unrolling charge; the plain and compressed covenant spends get the same
  `testmempoolaccept` verdict and reject reason, valid and mutated. The rollup leaf reads its own script, so its
  unrolled form differs from the uncompressed leaf's in exactly the two splice offsets, by the declarations' length.
- **Real proof.** The covenant receipt's journal is the spending transaction's outputs, so it needs no re-proving:
  both the plain and the compressed spend are accepted under standard policy and mined; the same spend paying 1 sat
  less is rejected.
- **Rollup binding.** `privacy-rollup/tools/binding_check.py` mines a valid settlement shape (with the verifier
  replaced by a journal-digest comparison) and rejects a wrong journal digest, a redirected successor, a successor
  for another root and `nSequence = 0`. A compressed leaf spliced for a new root equals a freshly generated one.

The `gsr` uncompressed settlement is an estimate (the measured gsr-full settlement with the new leaf swapped in).
The compressed one-join-split settlement is measured: `privacy-rollup/tools/batcher_e2e.py` on this node with
`-vbparams=tapleaf_0xc2:0:3999999999` proved a real zero-knowledge deposit receipt, aggregated it with `resolve_zk`
and mined the settlement (`privacy-rollup/reports/p0-gsr-settlement.md`). A full batch of 8 join-splits
(≈ 410k WU before, estimated) should fit under 400k WU compressed (estimate: 334,460 + 7 × ≈2.6k ≈ 353k WU).

## Reproduce

```sh
bash recursive-stwo/tools/build.sh                     # node, cli, util at ad6c16f
python3 risc0-succinct/tools/generate.py [--compress]  # fixed-statement verifier
python3 -c 'import sys; sys.path.insert(0, "risc0-succinct/tools"); import json, covenant as c; \
  r = json.loads((c.ROOT / "fixtures/covenant-receipt.json").read_text()); \
  print(c.regtest(c.Covenant(r, (c.ROOT / "fixtures/covenant-seal.bin").read_bytes(), compressed=True)))'
python3 privacy-rollup/tools/binding_check.py          # writes build/binding-check.json
python3 risc0-succinct/tools/check_compression.py      # writes risc0-succinct/build/compression-check.json
(cd recursive-stwo && bash tools/test.sh && cargo run --locked -- regtest-demo)  # Stwo verifier
```

## Meter

`gsr-meter` instruments the Tapleaf 0xC2 loop, which runs the unrolled script: `pc` is an unrolled offset and
`main_pc` the committed main-script instruction it belongs to; stage ends are translated the same way. Its
gsr-full fields `function_calls` and `invoked_body_bytes` became `macro_references` and `unrolled_bytes` (limit
4,000,000). The `gsr` budget deducts one signature check (500,000 varops) per Tapleaf 0xC2 input for its commitment
check; the tools' budget calculations follow, and the meter checks them against Core's. Its varops equal
`bitcoin-util evalscript`'s. A failing script is charged only its unrolling, since execution charges are deducted
when the script ends.

## Recursive Stwo verifier

Its lowering declares the same 128 shared fragments as macros instead of `OP_DEFINE` bodies, and calls them with
`OP_CALLMACRO`; the profile `profiles/bws-v1.json` is refrozen for `ad6c16f`. `tools/test.sh` passes (the profile
reproduces, the differential run succeeds, 397 malformed witnesses are rejected) and `regtest-demo` mines the spend.

| | `gsr-full` (README) | `gsr` |
|---|---:|---:|
| Script | 144,905 B | 139,129 B |
| Transaction weight | 370,387 WU | 364,611 WU |
| Varops | 1,399,895,948 | 1,306,473,856 |
| Size under the 4 MB limit: invoked bodies / unrolled script | 973,854 B | 1,054,095 B |
| Calls / macro references | 26,625 | 26,625 |

## Not yet ported

- A full rollup settlement on `gsr` needs new `apply_batch` receipts: the covenant's bytes, hence its address and
  every bound transaction, changed.
