# Remaining aggregation routes and approval boundary

This is a proposal, not an implementation or a feasibility claim. The exact
JoinSplit verifier still has substantial work after the 191.12M-cycle guest
checkpoint. No complete real JoinSplit receipt has been generated. A cost
extrapolation from selected segments is not an architectural lower bound.

## Work within the current verification design

The implemented routes include fixed-key/configuration specialization, shared
matrix coefficients, exact structured matrices, lazy matrix and blinding linear
forms, official SHA acceleration, sparse transforms, iterative equality tables,
and optional existing-AIR fused scalar/dot kernels. Full small receipts and
malformed-witness rejection validate the kernels at selected inputs.

The remaining exclusive diagnostic costs are approximately 77.45M cycles in
matrix evaluation, 26.11M in equality tables, 13.95M in Merkle verification, and
10.74M in leaf encoding/hashing. A larger field-linear-map kernel could target
matrix additions and recurrences; it has not been implemented or benchmarked.
It would require a fresh integer/carry analysis, independent vectors, malicious
witness tests and complete small receipts before integration. Reordering or
batching field operations alone does not eliminate the full proof workload.

Host C++ `-march=native` was tested on the same saved 2^18 trace: 100.58 versus
100.31 supervisor seconds, with essentially identical memory and seal size. No
improvement was established. Adding host-only Rust CPU/codegen tuning took
105.89 seconds on that same trace. Neither scalar-hash compiler candidate is adopted; see the
[compiler experiment](host-compiler-experiments.md). Subsequent optional packed
hashing and polynomial evaluation change the host computation schedule, while
retaining the same AIR and scalar verifier. Their separate native compiler
results and real-proof validation are recorded in the CPU experiment reports.

The pinned SDK rejects segment-proof hash functions other than Poseidon2 in
`risc0/zkvm/src/host/server/prove/prover_impl.rs`; its `sha256_hashfn_fails` test
documents this constraint. Changing the outer hash is therefore not an
available configuration-only shortcut. WHIR query counts, grinding, security
parameters and transcript hashes have not been changed.

Smaller RISC Zero segments were measured: they reduce memory but increase
paging, padding and recursive work. Larger segments have not been tested beyond
2^20 because a normal segment already uses about 9.15 GiB on the 16 GiB machine.
Two such provers do not fit concurrently, and one saturates the four-CPU quota.
These are measurements and resource constraints, not a universal impossibility
result.

The SDK has GPU prover backends, but this environment has no GPU. Running the
same pinned verifier and circuits on a suitably provisioned GPU is compatible
in principle; correctness, memory and complete wall time would still need to be
measured there. No GPU service, paid compute, remote worker or external agent
was invoked. Multi-machine CPU proving would likewise need resources outside
the current environment and an explicit authorization for that execution.

## Separate proposal: direct fixed-WHIR verification under recursive Stwo

This route requires the user's separate approval for custom AIR and direct
WHIR recursion. Do not interpret the current optimization approval as permission
to implement it. The existing recursive-stwo milestone verifies a pinned BWS
proof bundle; it does not already verify this JoinSplit relation.

A bounded first prototype would implement and benchmark one representative
fixed-WHIR verification phase with real transcript-derived inputs. It must use
the exact BN254 modulus, canonical encodings, field equations and SHA-256 bytes,
with every non-native carry/range constraint specified. It must expose all
deferred checks, including both final linear-form claims. Expected outputs from
the pinned native verifier are test oracles, never unverified witness hints.

The prototype would be limited to local synthetic and supplied proof inputs,
under the existing four-CPU/16-GiB resource limits, with per-run time guards.
Its gate is a real small proof, independently verified output binding, negative
range/carry/transcript tests, and measured constraints/prover wall time/memory.
It must establish a credible complete-verifier cost model before integrating
all phases. A failed or slow prototype must be reported without weakening the
relation or lowering security parameters.

Full integration is a further gate: bind the exact fixed VK/configuration,
transaction statement, full 196-byte settlement journal, commitment roots and
all proof checks to an application commitment. Only then generate the required
recursive proof layers and a new frozen verifier profile. The existing BWS
profile has 273 bound public inputs and fixed preprocessing commitments; their
mapping and commitments cannot be reused by assumption. Its existing standard
transaction has only 29,613 WU of spare space. Any new final proof must pass the
actual Script verifier, standard transaction limits and local regtest checks
without modifying those limits.

No custom AIR, direct WHIR recursion, new covenant/profile, deployment or
transaction for this proposal has been created. An application proof from the
existing RISC Zero path and this proposed direct relation are distinct designs;
neither has been shown feasible for a complete real JoinSplit in this cloud.
