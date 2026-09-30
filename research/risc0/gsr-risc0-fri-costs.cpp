// Research helper: prices the *whole* measured RISC Zero v3.0.6 succinct-receipt
// verifier -- BabyBear field arithmetic as well as hashing -- against the pinned
// GSR cost functions. Counts come from research/risc0/risc0-gsr-measure.patch,
// which instruments risc0-core's BabyBear operators and attributes every
// operation to a verifier phase; see research/risc0/README.md.
//
// From the workspace root:
//   g++ -std=c++20 -I bitcoin/src research/risc0/gsr-risc0-fri-costs.cpp -o /tmp/gsr-risc0-fri-costs
//   /tmp/gsr-risc0-fri-costs
//
// The arithmetic rows price one modular operation per counted field operation
// and nothing else: no operand retrieval (OP_PICK/OP_ROLL), no witness parsing,
// no canonical range checks, no OP_INVOKE overhead. They are lower bounds in
// exactly the same sense as research/gsr-primitive-costs.cpp, and the calibrated
// rows multiply by the 4.05x factor derived from the shipped Stwo verifier.
#include <script/varops.h>

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

void assertion_fail(const std::source_location&, std::string_view) { std::abort(); }

using varops::AddCost;
using varops::COST_COPYING;
using varops::COST_HASH;
using varops::COST_PER_OPCODE;
using varops::ExecutionCost;
using varops::ModCost;
using varops::MulCost;
using varops::SubCost;

namespace {

// BabyBear is a 31-bit prime field, so every element is a 4-byte operand.
constexpr size_t N = 4;

constexpr uint64_t SEAL_BYTES = 222'668;
constexpr double OVERHEAD = 4.05;

// Measured under the sha-256-padded suite, verification only, 3-segment receipt.
// Base-field counters already include the base operations performed inside
// extension operations, so pricing base_mul/base_add/base_sub covers everything.
struct Phase {
    const char* name;
    uint64_t base_mul;
    uint64_t base_add;
    uint64_t base_sub;
    uint64_t ext_inv;
};

constexpr Phase PHASES[] = {
    // Transcript setup, mix powers for 163 taps, DEEP coefficients, roots of unity.
    {"setup and mixing", 152'942, 110'016, 4, 0},
    // The 12,359-step recursion constraint program, evaluated once at z.
    {"constraint eval", 138'453, 108'600, 5'540, 0},
    // 50 queries x 3 rounds: 16-point NTT interpolation, fold, final poly eval.
    {"FRI folding", 259'376, 176'000, 19'200, 0},
    // 50 queries: DEEP-ALI combination over the tap rows and check row.
    {"DEEP-ALI per query", 136'589, 85'400, 6'900, 300},
};

constexpr uint64_t SHA_PAIRS = 4'363;
constexpr uint64_t SHA_SLICES = 355;
constexpr uint64_t SHA_SLICE_BYTES = 86'028;

uint64_t Push(size_t n) { return COST_PER_OPCODE + n * COST_COPYING; }

uint64_t MulMod(size_t n)
{
    return ExecutionCost(OP_MUL) + MulCost(n, n) + Push(n) + ExecutionCost(OP_MOD)
        + ModCost(2 * n, n);
}

uint64_t AddMod(size_t n)
{
    return ExecutionCost(OP_ADD) + AddCost(n, n) + Push(n) + ExecutionCost(OP_MOD)
        + ModCost(n + 1, n);
}

uint64_t SubMod(size_t n)
{
    return ExecutionCost(OP_ADD) + AddCost(n, n) + Push(n) + ExecutionCost(OP_SUB)
        + SubCost(n + 1, n) + Push(n) + ExecutionCost(OP_MOD) + ModCost(n + 1, n);
}

uint64_t Sha256(size_t n) { return ExecutionCost(OP_SHA256) + n * COST_HASH; }

uint64_t Sha256Parent() { return ExecutionCost(OP_CAT) + 64 * COST_COPYING + Sha256(64); }

uint64_t PhaseCost(const Phase& p)
{
    return p.base_mul * MulMod(N) + p.base_add * AddMod(N) + p.base_sub * SubMod(N);
}

void Row(const std::string& name, uint64_t cost, uint64_t budget)
{
    std::cout << std::left << std::setw(46) << name << std::right << std::setw(18) << cost
              << std::setw(12) << std::fixed << std::setprecision(2)
              << 100.0 * static_cast<double>(cost) / static_cast<double>(budget) << "%\n";
}

} // namespace

int main()
{
    const uint64_t max_budget = varops::TxBudget(400'000);
    const uint64_t seal_budget = varops::TxBudget(400'000 - SEAL_BYTES);

    std::cout << "Unit costs (varops):\n";
    std::cout << "  BabyBear mul mod p       " << MulMod(N) << '\n';
    std::cout << "  BabyBear add mod p       " << AddMod(N) << '\n';
    std::cout << "  BabyBear sub mod p       " << SubMod(N) << '\n';
    std::cout << "  SHA-256 Merkle parent    " << Sha256Parent() << "\n\n";

    std::cout << "Budget of a maximal 400,000 WU spend:        " << max_budget << '\n';
    std::cout << "Budget left after the seal is paid as witness: " << seal_budget << "\n\n";

    std::cout << std::left << std::setw(46) << "Verifier work" << std::right << std::setw(18)
              << "Varops" << std::setw(12) << "Of budget" << '\n';
    std::cout << std::string(76, '-') << '\n';

    uint64_t arith_total = 0;
    uint64_t mul_total = 0;
    uint64_t add_total = 0;
    uint64_t sub_total = 0;
    for (const Phase& p : PHASES) {
        const uint64_t cost = PhaseCost(p);
        arith_total += cost;
        mul_total += p.base_mul;
        add_total += p.base_add;
        sub_total += p.base_sub;
        Row(std::string("arithmetic: ") + p.name, cost, max_budget);
    }

    const uint64_t hash_total = SHA_PAIRS * Sha256Parent() + SHA_SLICES * ExecutionCost(OP_SHA256)
        + SHA_SLICE_BYTES * COST_HASH;
    Row("hashing: padded SHA-256, all phases", hash_total, max_budget);

    const uint64_t total = arith_total + hash_total;
    std::cout << std::string(76, '-') << '\n';
    Row("total, primitive lower bound", total, max_budget);
    Row("total, x4.05 calibrated projection", static_cast<uint64_t>(total * OVERHEAD), max_budget);
    Row("total, calibrated, post-seal budget", static_cast<uint64_t>(total * OVERHEAD),
        seal_budget);

    std::cout << "\nOperation totals: " << mul_total << " mul, " << add_total << " add, "
              << sub_total << " sub\n";
    std::cout << "Arithmetic share of the primitive lower bound: "
              << 100.0 * static_cast<double>(arith_total) / static_cast<double>(total) << "%\n";

    // How much weight a spend would need for the measured work to fit, at both
    // the primitive lower bound and the calibrated projection. TxBudget is
    // linear in weight, so invert it against a 1 WU quantum.
    const uint64_t per_wu = varops::TxBudget(1);
    std::cout << "\nWeight required for the measured verifier alone:\n";
    std::cout << "  primitive lower bound      " << total / per_wu << " WU\n";
    std::cout << "  x4.05 calibrated           " << static_cast<uint64_t>(total * OVERHEAD) / per_wu
              << " WU\n";
    std::cout << "  plus seal witness bytes    " << SEAL_BYTES << " WU\n";
}
