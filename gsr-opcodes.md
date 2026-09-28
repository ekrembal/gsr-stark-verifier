The branch adds **Tapscript v2: seven new opcodes, fifteen restored opcodes, large unsigned-integer arithmetic, much larger stack limits, and a shared computation budget.** The main practical additions are transaction inspection, enforceable rules about where coins can move, and reusable script functions.

I reviewed the **22 commits** from the branch’s Bitcoin Core base through [`d279905`](https://github.com/jmoik/bitcoin/compare/87bc4c74c4dff3e5e25abc294934a02f28027a45...d2799052604eb138c5a79acf88514a0c8b07f4ef). These semantics apply to **Taproot script leaves with version `0xc2`**, called Tapscript v2 here. Existing scripts retain their existing rules. **Mainnet activation is disabled in this branch**: its deployment start is `NEVER_ACTIVE`. [Script versions](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/script.h#L251-L259), [activation configuration](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/kernel/chainparams.cpp#L138-L143).

The **seven new opcodes** work as follows. Stack inputs below run from left to right, with the rightmost input on top.

| New opcode | How it works | What it enables |
|---|---|---|
| **`OP_TX`** — `0xbd` | Consumes a selector describing which transaction fields to return, plus indexes/ranges where needed. Pushes those fields individually or serialized together. | Scripts can inspect amounts, destinations, inputs, and their Taproot execution context, then enforce spending constraints. |
| **`OP_CHECKSIGFROMSTACK`** — `0xcc` | `signature message pubkey → boolean`. Checks a Schnorr signature against the message supplied by the script. | Signed data and custom transaction-signature messages constructed inside Script. |
| **`OP_TWEAKADD`** — `0xbe` | `tweak32 pubkey32 → tweaked_pubkey32`. Computes the x-only public key for \(P+tG\). The tweak is a 32-byte big-endian scalar. | Public-key derivation, including the elliptic-curve operation used in Taproot key tweaking. The script supplies the tweak; this opcode does not calculate the Taproot tagged hash. |
| **`OP_DEFINE`** — `0xbb` | `function_body function_id → …`. Stores a byte string as a function under an ID. | A script can define a piece of code once and reuse it. |
| **`OP_INVOKE`** — `0xbc` | `function_id → …`. Executes that function, using the caller’s main stack, altstack, transaction context, and computation budget, then resumes the caller. | Reusable script routines and smaller programs. |
| **`OP_MULTI`** — `0xbf` | Pops a count, reads the next opcode in the script, and applies its supported aggregate operation to that many stack items. | Bulk concatenation, hashing, arithmetic, comparisons, duplication, and dropping. |
| **`OP_BYTEREV`** — `0xcf` | Reverses a byte string: `01 02 80 → 80 02 01`. | Byte-order conversion when combining hashes, public-key operations, and little-endian arithmetic. |

Sources: [opcode assignments](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/script.h#L221-L238), [new opcode implementations](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2376-L2502), [transaction inspection implementation](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/op_tx.cpp).

A few details make these more useful than their names alone suggest:

- **`OP_TX` is broad transaction inspection.** It can return transaction version, locktime, weight, input/output counts and total amounts; input outpoints, spent-output amounts and scripts, sequences and witnesses; output amounts and scripts; and the current Taproot leaf, annex, control block, internal key, and tree root. Its selectors support individual entries, ranges, or all entries. Returning fields separately supports direct comparisons; returning canonical serialized bytes supports hashing a chosen transaction template. [Selector and output logic](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/op_tx.cpp#L24-L438).
- **`OP_CHECKSIGFROMSTACK` accepts arbitrary-length message bytes in this implementation**, subject to the stack-element limit. For the normal 32-byte public-key form, it expects a 64-byte Schnorr signature. An empty signature produces false; an invalid nonempty signature fails execution. It passes the supplied message directly to the Schnorr verifier without an extra preliminary SHA-256 step. [Signature handling](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L750-L782), [message verification](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/pubkey.cpp#L236-L242).
- **`OP_MULTI` has a specific supported set:** `CAT`, `SHA256`, `DUP`, `DROP`, `ADD`, `MIN`, `MAX`, `AND`, `OR`, `XOR`, `BOOLAND`, `BOOLOR`, and `EQUAL`. For example, `1 2 3 3 OP_MULTI OP_ADD` leaves `6`. With `SHA256`, it produces **one hash of the selected items concatenated in order**. With `EQUAL`, it tests whether all selected byte strings are identical. The underlying work still consumes the computation budget. [Bulk-operation implementation](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L87-L369).
- **Functions have explicit bounds:** 256 possible IDs, no redefinition, no direct or indirect recursion, and at most 4,000,000 bytes of invoked function bodies cumulatively per execution. Calling the same body again counts its length again. [Function limits and calls](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2376-L2427).

The **fifteen restored opcodes** give previously disabled/reserved operations executable meaning in v2:

| Restored opcodes | Behavior |
|---|---|
| **`OP_CAT`** | Joins two byte strings in order: `A B → A‖B`. |
| **`OP_SUBSTR`** | `A start length → slice`. Extracts the requested bytes. It clips at the end; a start beyond the data produces an empty result. |
| **`OP_LEFT`, `OP_RIGHT`** | Return the first or last requested number of bytes. Requesting more than the available length returns the whole string. |
| **`OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`** | Bitwise operations. Binary operations allow different-length operands, treating missing high-order bytes as zero and preserving the longer width. |
| **`OP_2MUL`, `OP_2DIV`** | Double a number, or divide it by two with integer truncation. |
| **`OP_MUL`, `OP_DIV`, `OP_MOD`** | Integer multiplication, quotient, and remainder. Division or modulo by zero fails. |
| **`OP_LSHIFT`, `OP_RSHIFT`** | Shift bits toward more- or less-significant positions. Left shifts can grow the byte string within the element limit; right shifts discard low-order bits. |

Sources: [restored opcode execution](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2511-L2690), [bitwise and shift semantics](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/val64.cpp#L717-L889).

**Existing arithmetic changes too.** Operations such as `OP_ADD`, `OP_SUB`, numeric comparisons, and `OP_CHECKSIGADD` now use arbitrary-length **unsigned, little-endian integers**. Despite the implementation name `Val64`, numbers are not limited to 64 bits; the implementation processes them in 64-bit chunks. Subtracting a larger number from a smaller one fails, because negative results are unsupported. Arithmetic results remove unnecessary high-order zero bytes. [Number representation](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/val64.h#L14-L18), [arithmetic implementation](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2150-L2264).

Correspondingly, `OP_1NEGATE`, `OP_NEGATE`, and `OP_ABS` become reserved `OP_SUCCESS` opcodes in v2. They no longer provide signed-number operations; standard policy discourages their use. [Opcode classification](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/script.cpp#L384-L398).

The **raised limits** are substantial:

| Limit | Existing Tapscript | Tapscript v2 | Practical meaning |
|---|---:|---:|---|
| **One stack element** | 520 bytes | **4,000,000 bytes** | About **7,692× larger**. A single value can hold a large proof, serialized structure, or integer. |
| **Combined main-stack and altstack entries** | 1,000 | **32,768** | About **32.8× more entries**, allowing many more intermediate values. Stored function definitions also count toward the new limit. |
| **Total live data payload** | At most 520,000 bytes, implied by the old element/count limits | **8,000,000 bytes explicitly** | The combined stack, altstack, and stored function bodies must fit this cap. You cannot fill every entry with a 4 MB value. |
| **Ordinary arithmetic operands** | Four-byte signed-magnitude integers, roughly ±2.147 billion | **Unsigned integers up to the element-size limit** | Direct 64-bit, 256-bit, and larger arithmetic becomes possible, subject to execution costs. |

Sources: [old and new limits](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/script.h#L28-L52), [combined resource accounting](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2695-L2716), [old numeric range](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/script.h#L278-L301).

Those larger limits are paired with **“varops,” a shared computation budget**. V2 replaces the original Tapscript signature allowance—per-input witness size plus 50, charging 50 per nonempty signature—with a budget shared across the transaction’s v2 executions. [Original-versus-v2 signature accounting](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L707-L725).

The budget is:

\[
\text{varops budget}=10{,}000\times\text{eligible transaction weight}
\]

When every input uses v2, that is the whole transaction’s weight. For mixed transactions, the calculation subtracts the input and witness weight of non-v2 inputs. A transaction with **1,000 eligible weight units** therefore gets **10,000,000 varops units**. [Budget calculation](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2734-L2757).

Operations spend that allowance according to their work:

- A basic opcode generally costs **1,250 units**, with higher fixed charges for some operations.
- Copying costs **3 units per byte**; hashing has a **50-unit-per-byte** component.
- A normal nonempty signature attempt costs **500,000 units** including its fixed opcode cost.
- Large multiplication, division, and modulo have costs that grow quadratically with relevant operand sizes.

Thus, being allowed to *store* a huge number does not guarantee enough budget to perform expensive arithmetic on it. [Cost definitions](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/varops.h).

Several limits remain unchanged:

- **Block weight stays at 4,000,000 WU**, and the default standard-transaction limit stays at **400,000 WU**. A 4 MB in-memory stack value does not add block space. [Consensus limit](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/consensus/consensus.h#L12-L21), [transaction policy](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/policy/policy.h#L35-L38).
- The old **10,000-byte script** and **201-opcode** ceilings already did not apply to original Tapscript, so their absence is not a new increase here. [Existing interpreter checks](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L831-L856).
- **`OP_SHA1` and `OP_RIPEMD160` still reject operands larger than 520 bytes**, even in v2. [Hash restrictions](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/src/script/interpreter.cpp#L2270-L2289).

For a concrete application, the branch includes a **vault that requires a designated output to preserve the input’s value and use a permitted destination script**, while allowing additional inputs to pay fees. It also includes a stricter vault that hashes a selected transaction template and requires an exact match. These illustrate how `OP_TX` turns transaction fields into enforceable spending rules. [Vault examples](https://github.com/jmoik/bitcoin/blob/d2799052604eb138c5a79acf88514a0c8b07f4ef/test/functional/feature_tapscript_v2_op_tx_vaults.py).

The surrounding changes propagate v2 through signing, PSBT, wallet/RPC utilities, and validation, and add a standalone evaluator, tests, fuzzing, and benchmarks. This summary is based on reading the implementation and included tests; I did not build the branch or execute its test suite.