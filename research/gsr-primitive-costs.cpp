// Research helper: prices candidate verifier primitives with the pinned GSR
// cost functions. It evaluates metering formulas over hand-written opcode
// sequences; it does not execute Script, emit a verifier, or benchmark a proof.
//
// From the workspace root:
//   clang++ -std=c++20 -I bitcoin/src research/gsr-primitive-costs.cpp -o /tmp/gsr-primitive-costs
//   /tmp/gsr-primitive-costs
//
// Every sequence below is an explicit lower-bound model: it counts the
// arithmetic, bitwise and hashing opcodes of the primitive and ignores operand
// retrieval (OP_PICK/OP_ROLL), witness parsing, canonical range checks, and
// OP_INVOKE overhead. Measured verifiers therefore cost more than these rows.
#include <script/varops.h>

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

// Standalone build: Core's assertion helper lives in a library this helper does
// not link.
void assertion_fail(const std::source_location&, std::string_view) { std::abort(); }

using varops::AddCost;
using varops::AndCost;
using varops::COST_COPYING;
using varops::COST_HASH;
using varops::COST_PER_OPCODE;
using varops::ExecutionCost;
using varops::ModCost;
using varops::MulCost;
using varops::OrCost;
using varops::SubCost;
using varops::UnalignedUpShiftCost;
using varops::XorCost;

namespace {

// Push of an n-byte constant (modulus, round constant, mask).
uint64_t Push(size_t n) { return COST_PER_OPCODE + n * COST_COPYING; }

// <p> OP_MUL <p> OP_MOD on n-byte operands modulo an n-byte prime.
uint64_t MulMod(size_t n)
{
    return ExecutionCost(OP_MUL) + MulCost(n, n) + Push(n)
        + ExecutionCost(OP_MOD) + ModCost(2 * n, n);
}

// OP_ADD <p> OP_MOD.
uint64_t AddMod(size_t n)
{
    return ExecutionCost(OP_ADD) + AddCost(n, n) + Push(n)
        + ExecutionCost(OP_MOD) + ModCost(n + 1, n);
}

// (a + p - b) mod p, the subtraction used by the shipped Stwo verifier.
uint64_t SubMod(size_t n)
{
    return ExecutionCost(OP_ADD) + AddCost(n, n) + Push(n)
        + ExecutionCost(OP_SUB) + SubCost(n + 1, n) + Push(n)
        + ExecutionCost(OP_MOD) + ModCost(n + 1, n);
}

// Wrapping n-byte integer addition: OP_ADD then mask back to width.
uint64_t WrapAdd(size_t n)
{
    return ExecutionCost(OP_ADD) + AddCost(n, n) + Push(n)
        + ExecutionCost(OP_AND) + AndCost(n + 1, n);
}

uint64_t Xor(size_t n) { return ExecutionCost(OP_XOR) + XorCost(n, n); }

// Rotation: OP_DUP, two shifts, OP_OR, then mask back to width.
uint64_t Rotate(size_t n)
{
    return ExecutionCost(OP_DUP) + n * COST_COPYING
        + ExecutionCost(OP_LSHIFT) + UnalignedUpShiftCost(n, n)
        + ExecutionCost(OP_RSHIFT) + UnalignedUpShiftCost(n, 0)
        + ExecutionCost(OP_OR) + OrCost(2 * n, n)
        + Push(n) + ExecutionCost(OP_AND) + AndCost(2 * n, n);
}

// Padded SHA-256 over a message of n bytes, the OP_SHA256 the branch charges.
uint64_t Sha256(size_t n) { return ExecutionCost(OP_SHA256) + n * COST_HASH; }

// OP_CAT of two 32-byte digests followed by OP_SHA256: one Merkle parent.
uint64_t Sha256Parent()
{
    return ExecutionCost(OP_CAT) + 64 * COST_COPYING + Sha256(64);
}

// BLAKE3/BLAKE2s-style compression: 7 rounds x 8 G functions, each G being
// 6 wrapping adds, 4 XORs and 4 rotations on 32-bit words.
uint64_t Blake3Compress()
{
    const uint64_t g = 6 * WrapAdd(4) + 4 * Xor(4) + 4 * Rotate(4);
    return 7 * 8 * g;
}

// Keccak-f[1600]: 24 rounds over 25 64-bit lanes.
// theta: 20 XOR (column parities) + 5 rotations + 5 XOR (D) + 25 XOR (apply)
// rho/pi: 24 rotations; chi: 25 x (OP_INVERT + OP_AND + OP_XOR); iota: 1 XOR
uint64_t KeccakF1600()
{
    const uint64_t theta = 20 * Xor(8) + 5 * Rotate(8) + 5 * Xor(8) + 25 * Xor(8);
    const uint64_t rho_pi = 24 * Rotate(8);
    const uint64_t chi = 25 * (ExecutionCost(OP_INVERT) + varops::InvertCost(8)
                               + ExecutionCost(OP_AND) + AndCost(8, 8) + Xor(8));
    const uint64_t iota = Xor(8);
    return 24 * (theta + rho_pi + chi + iota);
}

// x^7 S-box: x2 = x*x, x3 = x2*x, x6 = x3*x3, x7 = x6*x  -> four modular muls.
uint64_t SboxPow7(size_t n) { return 4 * MulMod(n); }

// Poseidon2 over a 4-byte prime field, width 16: 8 external rounds with 16
// S-boxes each, 13 internal rounds with one S-box and a diagonal matrix.
// Linear layers are counted as modular additions only.
uint64_t Poseidon2Width16()
{
    const size_t n = 4;
    const uint64_t external = 8 * (16 * AddMod(n) + 16 * SboxPow7(n) + 60 * AddMod(n));
    const uint64_t internal = 13 * (AddMod(n) + SboxPow7(n) + 16 * MulMod(n) + 16 * AddMod(n));
    return external + internal;
}

// Rescue-Prime Optimized over Goldilocks, width 12, 7 rounds. Each round has a
// forward x^7 layer and an inverse x^(1/7) layer; the inverse layer is checked
// against a witness hint with one forward x^7 per element. MDS is a 12x12
// matrix: 144 modular multiplications and additions per half-round.
uint64_t RpoWidth12()
{
    const size_t n = 8;
    const uint64_t half = 12 * SboxPow7(n) + 144 * MulMod(n) + 144 * AddMod(n) + 12 * AddMod(n);
    return 7 * 2 * half;
}

// Tip5 over Goldilocks, width 16: 5 rounds, 4 x^7 S-boxes plus 12 lookup-table
// S-boxes per round. Each lookup S-box is modelled as a hinted byte
// decomposition of one field element: 8 range-checked limbs recomposed with
// shifts and additions, and a table membership check per limb.
uint64_t Tip5Width16()
{
    const size_t n = 8;
    const uint64_t lookup_sbox = 8 * (ExecutionCost(OP_WITHIN) + varops::WithinCost(1, 1, 1)
                                      + ExecutionCost(OP_LSHIFT) + UnalignedUpShiftCost(8, 8)
                                      + AddMod(n));
    const uint64_t round = 4 * SboxPow7(n) + 12 * lookup_sbox
        + 256 * MulMod(n) + 256 * AddMod(n) + 16 * AddMod(n);
    return 5 * round;
}

void Row(const std::string& name, uint64_t cost, uint64_t budget)
{
    std::cout << std::left << std::setw(46) << name << std::right << std::setw(14) << cost
              << std::setw(14) << (cost == 0 ? 0 : budget / cost)
              << std::setw(12) << (cost + varops::BUDGET_PER_WEIGHT_UNIT - 1) / varops::BUDGET_PER_WEIGHT_UNIT
              << '\n';
}

} // namespace

int main()
{
    // The shipped Recursive Stwo spend: 370,387 WU of eligible weight.
    const uint64_t budget = varops::TxBudget(370'387);
    const uint64_t max_budget = varops::TxBudget(400'000);

    std::cout << "Budget of the shipped 370,387 WU spend: " << budget << '\n';
    std::cout << "Budget of a maximal 400,000 WU standard spend: " << max_budget << "\n\n";
    std::cout << std::left << std::setw(46) << "Primitive" << std::right << std::setw(14) << "Varops"
              << std::setw(14) << "Fit in spend" << std::setw(12) << "WU to fund" << "\n";
    std::cout << std::string(86, '-') << '\n';

    Row("SHA-256 two-to-one Merkle parent (64 B)", Sha256Parent(), budget);
    Row("SHA-256 over 1 KiB", Sha256(1024), budget);
    Row("BLAKE3/BLAKE2s compression", Blake3Compress(), budget);
    Row("Keccak-f[1600] permutation", KeccakF1600(), budget);
    Row("Poseidon2 permutation, 31-bit field, width 16", Poseidon2Width16(), budget);
    Row("RPO permutation, Goldilocks, width 12", RpoWidth12(), budget);
    Row("Tip5 permutation, Goldilocks, width 16", Tip5Width16(), budget);
    Row("M31 multiplication mod p (4 B)", MulMod(4), budget);
    Row("M31 addition mod p (4 B)", AddMod(4), budget);
    Row("M31 subtraction mod p (4 B)", SubMod(4), budget);
    Row("Goldilocks multiplication mod p (8 B)", MulMod(8), budget);
    Row("128-bit field multiplication mod p (16 B)", MulMod(16), budget);
    Row("252-bit field multiplication mod p (32 B)", MulMod(32), budget);

    std::cout << "\nMerkle authentication, 8 queries over a depth-21 tree:\n";
    const uint64_t paths = 8 * 21;
    Row("  SHA-256 parents", paths * Sha256Parent(), budget);
    Row("  Poseidon2 compressions", paths * Poseidon2Width16(), budget);
    Row("  Keccak-f permutations", paths * KeccakF1600(), budget);

    std::cout << "\nMerkle authentication, 100 queries over a depth-21 tree:\n";
    const uint64_t many = 100 * 21;
    Row("  SHA-256 parents", many * Sha256Parent(), budget);
    Row("  Poseidon2 compressions", many * Poseidon2Width16(), budget);

    // Calibration against recursive-stwo/reports/cost-report.json: the shipped
    // verifier's measured budget divided by the same semantic model applied to
    // its reported operation counts.
    const uint64_t shipped_measured = 1'399'895'948;
    const uint64_t shipped_arithmetic =
        8'667 * (ExecutionCost(OP_MUL) + MulCost(4, 4))
        + 35'214 * (ExecutionCost(OP_MOD) + ModCost(8, 4))
        + 31'201 * (ExecutionCost(OP_ADD) + AddCost(4, 4))
        + 14'937 * (ExecutionCost(OP_SUB) + SubCost(4, 4))
        + 9'491 * ExecutionCost(OP_SHA256) + 513'141 * COST_HASH
        + 26'625 * ExecutionCost(OP_INVOKE);
    std::cout << "\nCalibration against the shipped Recursive Stwo verifier:\n";
    std::cout << "  Its 763,003 executed opcodes cost " << shipped_measured << " units, "
              << shipped_measured / 763'003 << " per opcode on average\n";
    std::cout << "  Its arithmetic, hashing and invocation opcodes alone cost "
              << shipped_arithmetic << " units\n";
    std::cout << "  Everything else (stack plumbing, parsing, control flow) is " << std::fixed
              << std::setprecision(2)
              << 100.0 * static_cast<double>(shipped_measured - shipped_arithmetic)
                  / static_cast<double>(shipped_measured)
              << "% of the spend\n";
    std::cout << "  Multiply the primitive rows above by "
              << static_cast<double>(shipped_measured) / static_cast<double>(shipped_arithmetic)
              << "x to project a comparable full verifier\n";

    std::cout << "\nWitness economics:\n";
    std::cout << "  One witness byte costs 1 WU and funds " << varops::BUDGET_PER_WEIGHT_UNIT
              << " varops units\n";
    std::cout << "  A 32-byte digest costs 32 WU and funds " << varops::TxBudget(32)
              << " varops units\n";
    std::cout << "  Verifying it with a SHA-256 parent spends " << Sha256Parent() << " units, "
              << std::fixed << std::setprecision(2)
              << 100.0 * Sha256Parent() / static_cast<double>(varops::TxBudget(32))
              << "% of what the bytes fund\n";
    std::cout << "  Verifying it with a Poseidon2 compression spends " << Poseidon2Width16()
              << " units, " << 100.0 * Poseidon2Width16() / static_cast<double>(varops::TxBudget(32))
              << "% of what the bytes fund\n";
}
