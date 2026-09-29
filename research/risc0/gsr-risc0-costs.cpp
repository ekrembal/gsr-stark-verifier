// Research helper: prices the measured RISC Zero v3.0.6 succinct-receipt verifier
// against the pinned GSR cost functions. The hash counts below are the measured
// output of research/risc0/risc0-gsr-measure.patch; see research/risc0/README.md.
//
// From the workspace root:
//   clang++ -std=c++20 -I bitcoin/src research/risc0/gsr-risc0-costs.cpp -o /tmp/gsr-risc0-costs
//   /tmp/gsr-risc0-costs
//
// Like research/gsr-primitive-costs.cpp, every row is an explicit lower bound: it
// counts hashing only, and ignores FRI folding arithmetic, constraint evaluation,
// witness parsing and stack plumbing. The calibrated row multiplies by the 4.05x
// factor derived from the shipped Recursive Stwo verifier.
#include <script/varops.h>

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

void assertion_fail(const std::source_location&, std::string_view) { std::abort(); }

using varops::COST_COPYING;
using varops::COST_HASH;
using varops::COST_PER_OPCODE;
using varops::ExecutionCost;

namespace {

// Measured with the instrumented risc0-zkp hash suites, verification only.
constexpr uint64_t SHA_PAIRS = 4'363;       // digest-pair hashes (Merkle parents, Fiat-Shamir)
constexpr uint64_t SHA_SLICES = 355;        // hashes over field-element slices (Merkle leaves)
constexpr uint64_t SHA_SLICE_BYTES = 86'028;
constexpr uint64_t P2_PERMUTATIONS = 5'693; // the stock poseidon2 configuration

constexpr uint64_t SEAL_BYTES = 222'668;
constexpr double OVERHEAD = 4.05; // calibration from research/gsr-primitive-costs.txt

// Padded SHA-256 over an n-byte message: the OP_SHA256 the branch charges.
uint64_t Sha256(size_t n) { return ExecutionCost(OP_SHA256) + n * COST_HASH; }

// OP_CAT of two 32-byte digests followed by OP_SHA256: one Merkle parent.
uint64_t Sha256Parent() { return ExecutionCost(OP_CAT) + 64 * COST_COPYING + Sha256(64); }

// Poseidon2 width 16 over a 31-bit field, as priced in research/gsr-primitive-costs.cpp.
uint64_t Poseidon2Width16()
{
    const size_t n = 4;
    auto Push = [](size_t k) { return COST_PER_OPCODE + k * COST_COPYING; };
    auto MulMod = [&](size_t k) {
        return ExecutionCost(OP_MUL) + varops::MulCost(k, k) + Push(k)
            + ExecutionCost(OP_MOD) + varops::ModCost(2 * k, k);
    };
    auto AddMod = [&](size_t k) {
        return ExecutionCost(OP_ADD) + varops::AddCost(k, k) + Push(k)
            + ExecutionCost(OP_MOD) + varops::ModCost(k + 1, k);
    };
    auto Sbox = [&](size_t k) { return 4 * MulMod(k); };
    const uint64_t external = 8 * (16 * AddMod(n) + 16 * Sbox(n) + 60 * AddMod(n));
    const uint64_t internal = 13 * (AddMod(n) + Sbox(n) + 16 * MulMod(n) + 16 * AddMod(n));
    return external + internal;
}

void Row(const std::string& name, uint64_t cost, uint64_t budget)
{
    std::cout << std::left << std::setw(52) << name << std::right << std::setw(16) << cost
              << std::setw(12) << std::fixed << std::setprecision(2)
              << 100.0 * static_cast<double>(cost) / static_cast<double>(budget) << "%\n";
}

} // namespace

int main()
{
    const uint64_t max_budget = varops::TxBudget(400'000);
    const uint64_t seal_budget = varops::TxBudget(400'000 - SEAL_BYTES);

    std::cout << "Measured RISC Zero v3.0.6 succinct receipt (3 and 18 segments, identical):\n";
    std::cout << "  seal bytes                 " << SEAL_BYTES << '\n';
    std::cout << "  sha-256 digest-pair hashes " << SHA_PAIRS << '\n';
    std::cout << "  sha-256 slice hashes       " << SHA_SLICES << " over " << SHA_SLICE_BYTES
              << " bytes\n";
    std::cout << "  poseidon2 permutations     " << P2_PERMUTATIONS << " (stock configuration)\n\n";

    std::cout << "Budget of a maximal 400,000 WU standard spend: " << max_budget << '\n';
    std::cout << "Budget left after paying for the seal as witness: " << seal_budget << "\n\n";

    std::cout << std::left << std::setw(52) << "Verifier hashing" << std::right << std::setw(16)
              << "Varops" << std::setw(12) << "Of budget" << '\n';
    std::cout << std::string(80, '-') << '\n';

    const uint64_t pairs = SHA_PAIRS * Sha256Parent();
    const uint64_t slices = SHA_SLICES * ExecutionCost(OP_SHA256) + SHA_SLICE_BYTES * COST_HASH;
    const uint64_t sha_total = pairs + slices;
    Row("sha-256 digest pairs", pairs, max_budget);
    Row("sha-256 leaf slices", slices, max_budget);
    Row("sha-256 total, primitive lower bound", sha_total, max_budget);
    Row("sha-256 total, x4.05 calibrated projection",
        static_cast<uint64_t>(sha_total * OVERHEAD), max_budget);
    Row("sha-256 total against post-seal budget",
        static_cast<uint64_t>(sha_total * OVERHEAD), seal_budget);

    const uint64_t p2_total = P2_PERMUTATIONS * Poseidon2Width16();
    Row("poseidon2 total, primitive lower bound", p2_total, max_budget);
    Row("poseidon2 total, x4.05 calibrated projection",
        static_cast<uint64_t>(p2_total * OVERHEAD), max_budget);

    std::cout << "\nRatios:\n";
    std::cout << "  poseidon2 / sha-256 verifier hashing: "
              << static_cast<double>(p2_total) / static_cast<double>(sha_total) << "x\n";
    std::cout << "  seal bytes as a share of 400,000 WU:  "
              << 100.0 * SEAL_BYTES / 400'000.0 << "%\n";
    std::cout << "  weight left for script and overhead:  " << 400'000 - SEAL_BYTES << " WU\n";
    std::cout << "  shipped Recursive Stwo script:        144905 bytes\n";
}
