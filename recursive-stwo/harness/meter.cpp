// Test-only translation unit: unchanged Core execution with observational hooks.
#include <array>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <vector>
struct Measurements {
    std::array<uint64_t,256> opcodes{};
    uint64_t sha256_bytes=0, invoked_bytes=0, peak_entries=0, peak_payload=0, peak_element=0;
    uint64_t main_pc=0, pc=0;
} measurements;
std::vector<uint64_t> stage_ends;
std::vector<std::pair<Measurements,uint64_t>> stage_snapshots;
#include "interpreter-instrumented.cpp"
#include <policy/policy.h>
#include <core_io.h>
#include <consensus/validation.h>
#include <univalue.h>
#include <util/strencodings.h>
int main(int argc, char** argv) {
    if(argc != 2) { std::cerr << "usage: gsr-meter input.json\n"; return 2; }
    std::ifstream stream(argv[1]);
    std::string input((std::istreambuf_iterator<char>(stream)), {});
    UniValue request;
    if(!request.read(input)) return 2;
    if(!request["stage_script_ends"].isNull()) for(const auto& e:request["stage_script_ends"].getValues())stage_ends.push_back(e.getInt<uint64_t>());
    const auto raw=ParseHex(request["script"].get_str());
    CScript script(raw.begin(),raw.end());
    std::vector<valtype> initial;
    for(const auto& item:request["witness"].getValues()) initial.push_back(ParseHex(item.get_str()));
    ValtypeStack stack(initial);
    measurements.peak_entries=stack.size(); measurements.peak_payload=stack.GetTotalSize(); measurements.peak_element=stack.GetMaxElementSize();
    ScriptExecutionData execution;
    execution.m_annex_present=false; execution.m_annex_init=true;
    uint64_t budget=request["budget"].getInt<uint64_t>();
    uint64_t weight=0;
    std::optional<CTransaction> transaction;
    PrecomputedTransactionData txdata;
    std::unique_ptr<BaseSignatureChecker> checker=std::make_unique<BaseSignatureChecker>();
    if(!request["transaction_hex"].isNull()) {
        CMutableTransaction tx;
        if(!DecodeHexTx(tx,request["transaction_hex"].get_str()))return 2;
        std::vector<CTxOut> spent;
        for(const auto& item:request["spent_outputs"].getValues()) {
            auto bytes=ParseHex(item["script_pub_key"].get_str());
            spent.emplace_back(item["value"].getInt<int64_t>(),CScript(bytes.begin(),bytes.end()));
        }
        transaction.emplace(tx);
        weight=GetTransactionWeight(*transaction);
        budget=GetTransactionVaropsBudget(*transaction,spent);
        if(budget!=request["budget"].getInt<uint64_t>())return 3;
        // Signature opcodes check against input 0 of this transaction, as in script-path validation of the leaf.
        const CAmount amount=spent.at(0).nValue;
        txdata.Init(*transaction,std::move(spent));
        checker=std::make_unique<TransactionSignatureChecker>(&*transaction,0,amount,txdata,MissingDataBehavior::FAIL);
        execution.m_tapleaf_hash=ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT_V2,raw);
        execution.m_tapleaf_hash_init=true;
    }
    varops::Budget meter(budget);
    ScriptError error=SCRIPT_ERR_UNKNOWN_ERROR;
    bool immediate=false;
    const bool evaluated=EvalTapscriptV2(stack,script,STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORATION,*checker,execution,meter,&error,&immediate);
    const auto final_stack=stack.GetStack();
    const bool ok=evaluated && !immediate && CheckTapscriptV2ScriptResult(stack,meter,&error);
    UniValue result(UniValue::VOBJ), counts(UniValue::VOBJ), top(UniValue::VARR);
    result.pushKV("ok",ok);result.pushKV("error",ScriptErrorString(error));result.pushKV("immediate_success",immediate);
    result.pushKV("transaction_weight",weight);result.pushKV("varops",budget-*meter.Remaining()); result.pushKV("budget",budget);
    result.pushKV("main_pc",measurements.main_pc);result.pushKV("pc",measurements.pc);
    result.pushKV("sha256_calls",measurements.opcodes[OP_SHA256]);result.pushKV("sha256_input_bytes",measurements.sha256_bytes);
    result.pushKV("function_calls",measurements.opcodes[OP_INVOKE]);result.pushKV("invoked_body_bytes",measurements.invoked_bytes);
    result.pushKV("peak_entries",measurements.peak_entries);result.pushKV("peak_payload_bytes",measurements.peak_payload);result.pushKV("peak_element_bytes",measurements.peak_element);
    result.pushKV("final_stack_entries",final_stack.size());
    result.pushKV("final_stack_exact_true",final_stack==std::vector<valtype>{{1}});
    for(size_t i=0;i<256;++i) if(measurements.opcodes[i]) counts.pushKV(GetOpName(opcodetype(i))+"_"+std::to_string(i),measurements.opcodes[i]);
    for(size_t i=stack.size()>12?stack.size()-12:0;i<stack.size();++i) top.push_back(HexStr(stack.at(i)));
    result.pushKV("opcodes",counts);result.pushKV("stack_top",top);
    UniValue stages(UniValue::VARR);
    uint64_t prior_cost=0,prior_hashes=0,prior_calls=0,prior_bytes=0;
    for(size_t i=0;i<stage_snapshots.size();++i) {
        const auto& [m,remaining]=stage_snapshots[i];const auto cost=budget-remaining;UniValue stage(UniValue::VOBJ);
        stage.pushKV("index",i);stage.pushKV("varops",cost-prior_cost);stage.pushKV("sha256_calls",m.opcodes[OP_SHA256]-prior_hashes);stage.pushKV("function_calls",m.opcodes[OP_INVOKE]-prior_calls);stage.pushKV("invoked_body_bytes",m.invoked_bytes-prior_bytes);
        prior_cost=cost;prior_hashes=m.opcodes[OP_SHA256];prior_calls=m.opcodes[OP_INVOKE];prior_bytes=m.invoked_bytes;stages.push_back(stage);
    }
    result.pushKV("stages",stages);
    std::cout<<result.write(2)<<"\n";
    return ok?0:1;
}
