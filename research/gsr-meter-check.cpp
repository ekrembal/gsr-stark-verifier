// Research helper: evaluates formulas from the pinned GSR checkout.
// It does not execute Script or benchmark a proof verifier.
// From the workspace root:
// clang++ -std=c++20 -I bitcoin/src research/gsr-meter-check.cpp -o /tmp/gsr-meter-check
// /tmp/gsr-meter-check
#include <script/varops.h>
#include <iostream>

int main()
{
    for (size_t n : {4, 8, 32}) {
        const auto cost = varops::ExecutionCost(OP_MUL) + varops::MulCost(n, n)
            + varops::COST_PER_OPCODE + n * varops::COST_COPYING
            + varops::ExecutionCost(OP_MOD) + varops::ModCost(2 * n, n);
        std::cout << n << "-byte mul/mod: " << cost << '\n';
    }
    const auto parent = varops::ExecutionCost(OP_CAT) + 64 * varops::COST_COPYING
        + varops::ExecutionCost(OP_SHA256) + 64 * varops::COST_HASH;
    const auto multi = varops::ExecutionCost(OP_2) + varops::LengthConversionCost(1)
        + 2 * varops::ExecutionCost(OP_SHA256) + 64 * varops::COST_HASH;
    std::cout << "CAT+SHA256 parent: " << parent << '\n';
    std::cout << "OP_2 MULTI SHA256 parent: " << multi << '\n';
    std::cout << "6400 parents: " << 6400 * parent << '\n';
    std::cout << "200 KiB witness budget contribution: " << varops::TxBudget(204800) << '\n';
}
