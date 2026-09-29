#!/usr/bin/env python3
"""Build observational instrumentation against the pinned Core interpreter."""
import subprocess
from paths import VERIFIER_ROOT as root, BITCOIN_SOURCE, BITCOIN_BUILD
assert subprocess.check_output(['git','-C',str(BITCOIN_SOURCE),'rev-parse','HEAD'],text=True).strip()=='d2799052604eb138c5a79acf88514a0c8b07f4ef', 'Wrong Core revision'
build=root/'build/harness';build.mkdir(parents=True,exist_ok=True)
s=(BITCOIN_SOURCE/'src/script/interpreter.cpp').read_text()
start=s.index('static bool EvalTapscriptV2Impl(')
# The forward declaration occurs earlier; instrument only the definition containing the local state.
start=s.index('static bool EvalTapscriptV2Impl(',start+1) if s.find('static bool EvalTapscriptV2Impl(',start+1)>=0 else start
head,body=s[:start],s[start:]
needle='            const bool executes_opcode{fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)};'
assert body.count(needle)==1
body=body.replace(needle,needle+'''
            measurements.pc=pc-script.begin();
            if(!in_function) measurements.main_pc=measurements.pc;
            if(executes_opcode) {
                ++measurements.opcodes[static_cast<unsigned char>(opcode)];
                if(opcode==OP_SHA256 && stack.size()) measurements.sha256_bytes+=stack.back().size();
            }
''')
needle='            // Size limits\n            const size_t stack_entries{stack.size() + altstack.size()};'
assert body.count(needle)==1
body=body.replace(needle,'''
            measurements.peak_entries=std::max<uint64_t>(measurements.peak_entries,stack.size()+altstack.size()+function_state.definition_count);
            measurements.peak_payload=std::max<uint64_t>(measurements.peak_payload,stack.GetTotalSize()+altstack.GetTotalSize()+function_state.stored_body_bytes);
            measurements.peak_element=std::max<uint64_t>(measurements.peak_element,std::max(stack.GetMaxElementSize(),altstack.GetMaxElementSize()));
            measurements.invoked_bytes=function_state.invoked_body_bytes;
'''+needle)
needle='            if (!varops_budget.Spend(varcost)) return set_error(serror, SCRIPT_ERR_VAROP_COUNT);'
assert body.count(needle)==1
body=body.replace(needle,needle+"\n            if(!in_function) while(stage_snapshots.size()<stage_ends.size() && static_cast<uint64_t>(pc-script.begin())>=stage_ends[stage_snapshots.size()]) stage_snapshots.emplace_back(measurements, *varops_budget.Remaining());")
(build/'interpreter-instrumented.cpp').write_text(head+body)
cmd=['c++','-std=c++20','-O2','-g',str(root/'harness/meter.cpp'),'-o',str(build/'gsr-meter')]
for p in [build,BITCOIN_BUILD/'src',BITCOIN_SOURCE/'src',BITCOIN_SOURCE/'src/univalue/include',BITCOIN_SOURCE/'src/secp256k1/include']:cmd+=['-I'+str(p)]
# Dependants precede their dependencies; GNU ld resolves static archives in order.
for p in ['lib/libbitcoin_common.a','lib/libbitcoin_util.a','lib/libbitcoin_clientversion.a','lib/libbitcoin_consensus.a','lib/libbitcoin_crypto.a','src/secp256k1/lib/libsecp256k1.a','src/univalue/libunivalue.a']:cmd.append(str(BITCOIN_BUILD/p))
subprocess.run(cmd,check=True)
