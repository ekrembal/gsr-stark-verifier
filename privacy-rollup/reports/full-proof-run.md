# Full real JoinSplit proving run

> Superseded: a complete JoinSplit receipt under the newer image
> `552b779f6f59ef31f79acad0a18d86a85a926d392c9c86bd1dce55214f383cb8` was proved and verified;
> see [prover-speedups.md](prover-speedups.md). This file records the earlier `fc7c9097…` run.

Status at launch: **in progress; no complete real JoinSplit receipt yet**.
The authoritative live status is `build/full-joinsplit-191m/status.json`.
Only `state: complete` plus the final independent checks establishes completion
of this proving pipeline. Script checks and actual covenant settlement have
separate acceptance criteria.

After explicit approval to proceed beyond selected-segment measurements, the
208-segment execution was captured once and a bounded, resumable full run was
started. It uses the same optimized guest, client proof, VK, witness and journal
as the 191.12M-cycle measurements. No additional AIR, precompile, security
parameter, client encoding or covenant change was made for this run.

## Frozen execution and resource policy

The capture executed 191,119,171 user cycles, 20,920,642 paging cycles and
6,063,995 reserved cycles, totaling 218,103,808 padded rows over 208 segments.
It took 6.516714 seconds and 72,376 KiB peak process RSS. The complete 196-byte
journal matched the frozen expected journal. A completed execution capture is
not a proof receipt.

The capture spool is 53,276,129 bytes; the capture limit was 64 MiB. Only one
serialized segment is extracted at a time, then removed after its verified
receipt is durable. The guest image is
`fc7c90972cfd366c450cf202c7131fea5d04f81b76f93d6925ce15e33cdd14be`.
The immutable run configuration SHA-256 is
`8739743f38b1cfded5e6ef74d2a7f4f2e0a354778507666a0f26a965f8dd1b6c`.
It includes hashes of the executable files, inputs, capture and controller.

The executor exposes four CPU cores by quota and 16 GiB RAM. It has no reported
CPU-time limit or exposed future-lifetime guarantee. A harmless detached
heartbeat survived separate tool calls. Native and standard binaries and guest
images were preserved before deleting 3.4 GiB of regenerable release build
cache. The actual normal-size leaf demonstrated safe operation under the new
limits before the full run continued.

| Guard | Limit |
|---|---:|
| Overall absolute deadline | 18 hours from initialization |
| Address space per stage | 14 GiB |
| Sampled process-group RSS | 12 GiB |
| Minimum free disk | 1.5 GiB |
| Leaf / lift / join wall time | 480 / 120 / 120 seconds |
| Padded identity / independent verification | 180 / 60 seconds |
| Output file / core dump | 512 MiB / disabled |

Native proving uses four Rayon workers and the optional CPU batch, periodic
quotient and polynomial batch paths. Nothing is rebuilt during the full run.
Each stage also has a CPU-time limit, process group termination and Linux parent
death signal. A flock and PID-start-time check reject concurrent supervisors
and still-running orphan stages. Stop conditions preserve earlier receipts.

## Receipt chain and acceptance checks

Each leaf is proved from that single captured execution, checked by the frozen
standard checker, lifted, independently checked again, then joined to the
verified prefix. Lift claim digests must match their leaves. Every join must
connect the previous post-state to the next pre-state and preserve the expected
pre-state, input, final post-state, output and exit codes. Artifacts are fsynced
before atomic checkpoint metadata becomes visible.

After all 208 leaves and 207 joins, the checker verifies the whole receipt
against the expected image and journal. It explicitly requires a successful
exit and zero assumption digest, then tests wrong-image, wrong-journal and
corrupted-seal rejection. The same full checks run after the padded identity
step, which exports `final/receipt.json` and `final/seal.bin`. There is no
assumption-discharge work to skip: a nonempty assumption digest fails acceptance.

The final Script tool additionally compares trusted verifier roots, parameter
digest, proof-system/circuit identifiers and fixed claim fields to the existing
repository profile before reference verification and metering. It will test a
complete fixed-statement transaction and changed-claim rejection. These checks
do not prove equivalence of the unaudited padded hash implementation.

## Completed preparation validation

- A complete two-segment diagnostic exercised pause/resume. A second run adopted
  an existing verified leaf and lift without checkpoint markers, then proved,
  joined and checked the complete unpadded and padded receipts. Both final
  binding and corrupted-seal rejection checks passed.
- Frozen-file hash mismatch, a concurrent lock and a live orphan stage were
  rejected before proving (`full-proof-runner-guards.json`).
- The diagnostic padded receipt passed the Python reference and pinned Script
  meter: 388,398 WU, 2,083,324,364 varops, all configured limits satisfied, exact
  true stack, no immediate-success opcode, changed claim output rejected.
- That receipt matched the trusted Script profile. Altered outer/inner roots,
  verifier-parameter digest and assumption digest were rejected.
- The actual frozen settlement's input/output digest bindings were reconstructed
  and matched the journal. Its placeholder scripts prevent actual settlement;
  see [the binding and migration report](full-proof-covenant-binding.md).

The first Script wrapper attempt encountered a Python module-name collision;
import ordering was corrected before the successful meter run. A convenience
timing command was unavailable; Python subprocess/resource measurements were
used instead. Neither was a cryptographic verification failure.

## Operation and recovery

Read status without starting a second prover:

```sh
source /workspace/.gsr-env/activate.sh
python3 privacy-rollup/tools/full_proof_runner.py \
  build/full-joinsplit-191m --status
```

The run's own `runner.py` and `config.json` are frozen. For recovery after an
actual interruption, confirm no prior supervisor/stage remains alive, preserve
all inputs, checkpoints and paths, and run that controller with the same root:

```sh
python3 -u build/full-joinsplit-191m/runner.py \
  /workspace/gsr-stark-verifier/build/full-joinsplit-191m
```

Do not run this recovery command while the existing controller is active.
`PAUSE` in the root requests stopping after the current complete prefix;
`STOP` requests stopping the active stage. Neither action removes receipts.
Do not silently extend deadlines or alter frozen hashes to bypass a guard.
The earlier image's separately captured sample segment cannot substitute for
a segment from this frozen execution.

After complete native and padded verification, run:

```sh
python3 privacy-rollup/tools/check_padded_script.py \
  --receipt build/full-joinsplit-191m/final/receipt.json \
  --seal build/full-joinsplit-191m/final/seal.bin \
  --journal build/full-joinsplit-191m/final/journal.bin \
  --image fc7c90972cfd366c450cf202c7131fea5d04f81b76f93d6925ce15e33cdd14be \
  --out build/feasibility/full-joinsplit-script-check
```

A locally verified bootstrap archive contains frozen executables, inputs,
capture, controller and first verified receipts. Its Library upload failed
before preparation because the execution environment's HTTPS proxy denied the
connection. No remote backup of that archive is claimed. Earlier saved review
artifacts remain available, and local fsynced checkpoints continue to accumulate.
Executor persistence across calls was tested; survival of executor destruction
is not guaranteed. Exact per-stage commands, outputs, errors and sampled
resources are retained under the run's `logs`, `checks` and `events.jsonl`.

This run does not by itself establish economical aggregation or spendable
JoinSplit settlement. The existing formal and audit gaps, new-image migration,
real funding/genesis requirements, and client proving costs remain relevant.
