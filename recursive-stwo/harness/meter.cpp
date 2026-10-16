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
    uint64_t sha256_bytes=0, peak_entries=0, peak_payload=0, peak_element=0;
    uint64_t pc=0;
} measurements;
std::vector<uint64_t> stage_ends;
std::vector<std::pair<Measurements,uint64_t>> stage_snapshots;
#include "interpreter-instrumented.cpp"
#include <policy/policy.h>
#include <core_io.h>
#include <consensus/validation.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <script/reusable_macros.h>
#include <serialize.h>
#include <streams.h>
int main(int argc, char** argv) {
    if(argc != 2) { std::cerr << "usage: gsr-meter input.json\n"; return 2; }
    std::ifstream stream(argv[1]);
    std::string input((std::istreambuf_iterator<char>(stream)), {});
    UniValue request;
    if(!request.read(input)) return 2;
    const auto raw=ParseHex(request["script"].get_str());
    CScript script(raw.begin(),raw.end());
    // The interpreter runs the unrolled script. Record the unrolled and committed offsets of every main-script
    // instruction, so stage ends (committed offsets) and the last executed position can be translated.
    reusable_macros::Program program{script};
    std::vector<std::pair<uint64_t,uint64_t>> main_offsets;
    if(reusable_macros::Decode(program)==reusable_macros::DecodeResult::WELL_FORMED) {
        uint64_t unrolled=0;
        for(auto pc=program.main_begin;pc<script.end();) {
            main_offsets.emplace_back(unrolled,pc-script.begin());
            const auto begin=pc;opcodetype opcode;
            GetScriptOp(pc,script.end(),opcode,nullptr);
            if(opcode==OP_CALLMACRO) {
                SpanReader reader{std::span{pc,script.end()}};
                const auto index=ReadCompactSize(reader,false);
                pc=script.end()-reader.size();
                unrolled+=program.bodies.at(index).length;
            } else unrolled+=pc-begin;
        }
        main_offsets.emplace_back(unrolled,script.size());
    }
    if(!request["stage_script_ends"].isNull()) for(const auto& e:request["stage_script_ends"].getValues()) {
        const auto it=std::lower_bound(main_offsets.begin(),main_offsets.end(),e.getInt<uint64_t>(),[](const auto& m,uint64_t c){return m.second<c;});
        stage_ends.push_back(it==main_offsets.end()?std::numeric_limits<uint64_t>::max():it->first);
    }
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
        // Transaction-aware opcodes see input 0 of this transaction, as in script-path validation of the leaf.
        const CAmount amount=spent.at(0).nValue;
        txdata.Init(*transaction,std::move(spent));
        checker=std::make_unique<TransactionSignatureChecker>(&*transaction,0,amount,txdata,MissingDataBehavior::FAIL);
        execution.m_tapleaf_hash=ComputeTapleafHash(TAPROOT_LEAF_0XC2,raw);
        execution.m_tapleaf_hash_init=true;
        // The last witness item is the control block (or the annex, then the control block), as in script-path
        // validation (read by OP_TX).
        const auto& witness=transaction->vin.at(0).scriptWitness.stack;
        const bool has_annex=witness.size()>=2 && !witness.back().empty() && witness.back()[0]==ANNEX_TAG;
        if(has_annex) {
            execution.m_annex=witness.back();
            execution.m_annex_hash=(HashWriter{}<<witness.back()).GetSHA256();
            execution.m_annex_present=true;
        }
        const auto& control=witness.at(witness.size()-(has_annex?2:1));
        execution.m_control_block=control;
        execution.m_control_block_init=true;
        execution.m_taptree_root=ComputeTaprootMerkleRoot(control,execution.m_tapleaf_hash);
        execution.m_taptree_root_init=true;
    }
    varops::Budget meter(budget);
    ScriptError error=SCRIPT_ERR_UNKNOWN_ERROR;
    bool immediate=false;
    const bool evaluated=EvalTapleaf0xC2(stack,script,STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_TAPLEAF_0XC2,*checker,execution,meter,&error,&immediate);
    const auto final_stack=stack.GetStack();
    const bool ok=evaluated && !immediate && CheckTapleaf0xC2ScriptResult(stack,meter,&error);
    // The committed main-script instruction that the last executed position belongs to.
    uint64_t main_pc=measurements.pc;
    const auto last=std::upper_bound(main_offsets.begin(),main_offsets.end(),measurements.pc,[](uint64_t u,const auto& m){return u<m.first;});
    if(last!=main_offsets.begin()) main_pc=std::prev(last)->second;
    UniValue result(UniValue::VOBJ), counts(UniValue::VOBJ), top(UniValue::VARR);
    result.pushKV("ok",ok);result.pushKV("error",ScriptErrorString(error));result.pushKV("immediate_success",immediate);
    result.pushKV("transaction_weight",weight);result.pushKV("varops",budget-meter.Remaining()); result.pushKV("budget",budget);
    result.pushKV("main_pc",main_pc);result.pushKV("pc",measurements.pc);
    result.pushKV("sha256_calls",measurements.opcodes[OP_SHA256]);result.pushKV("sha256_input_bytes",measurements.sha256_bytes);
    result.pushKV("macro_references",program.main_totals.references);result.pushKV("unrolled_bytes",program.main_totals.length);
    result.pushKV("peak_entries",measurements.peak_entries);result.pushKV("peak_payload_bytes",measurements.peak_payload);result.pushKV("peak_element_bytes",measurements.peak_element);
    result.pushKV("final_stack_entries",final_stack.size());
    result.pushKV("final_stack_exact_true",final_stack==std::vector<valtype>{{1}});
    for(size_t i=0;i<256;++i) if(measurements.opcodes[i]) counts.pushKV(GetOpName(opcodetype(i))+"_"+std::to_string(i),measurements.opcodes[i]);
    for(size_t i=stack.size()>12?stack.size()-12:0;i<stack.size();++i) top.push_back(HexStr(stack.GetStack()[i]));
    result.pushKV("opcodes",counts);result.pushKV("stack_top",top);
    UniValue stages(UniValue::VARR);
    uint64_t prior_cost=0,prior_hashes=0;
    for(size_t i=0;i<stage_snapshots.size();++i) {
        const auto& [m,remaining]=stage_snapshots[i];const auto cost=budget-remaining;UniValue stage(UniValue::VOBJ);
        stage.pushKV("index",i);stage.pushKV("varops",cost-prior_cost);stage.pushKV("sha256_calls",m.opcodes[OP_SHA256]-prior_hashes);
        prior_cost=cost;prior_hashes=m.opcodes[OP_SHA256];stages.push_back(stage);
    }
    result.pushKV("stages",stages);
    std::cout<<result.write(2)<<"\n";
    return ok?0:1;
}
