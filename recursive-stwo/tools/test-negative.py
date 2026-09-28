#!/usr/bin/env python3
"""Malformed witness tests against Core, after all host proof checks have ended."""
import bisect,copy,json,subprocess,sys
from pathlib import Path
from transaction import ROOT

def main():
    full=json.loads(Path(sys.argv[1] if len(sys.argv)>1 else ROOT/'build/verifier.json').read_text())
    base={k:full[k]for k in ['script','witness']};base['budget']=4_000_000_000
    cases=[]
    def mutate_hint(label,i,replacement=None):
        case=copy.deepcopy(base);chunk,offset,length,numeric=full['hint_layout'][i]
        data=bytearray.fromhex(case['witness'][chunk]);
        if replacement is None:data[offset]^=1
        else:data[offset:offset+length]=replacement
        case['witness'][chunk]=data.hex();cases.append((label,case))
    for i,hint in enumerate(full['hint_layout']):
        if hint[2]==8:mutate_hint('nonce_'+str(i),i)
    for needle in ['inverse_hint','last_layer_poly','commitment','delegated_decommit_preprocessed_input_','delegated_decommit_trace_input_','delegated_first_layer_input_']:
        found=[i for i,labels in enumerate(full['hint_labels']) if any(needle in x for x in labels)]
        for i in found[:3]:mutate_hint(needle+str(i),i)
    # Every stage that imports data gets a changed opening/value. Stages that
    # only compute values are covered by the full intermediate differential run.
    by_stage={}
    for i,t in enumerate(full['hint_traces']):by_stage.setdefault(bisect.bisect_right(full['stage_trace_ends'],t),[]).append(i)
    for stage,indices in by_stage.items():
        for i in set([indices[0],indices[len(indices)//2],indices[-1]]):mutate_hint(f'stage_{stage}_hint_{i}',i)
    numeric=[i for i,x in enumerate(full['hint_layout'])if x[3]]
    for i in [numeric[0],numeric[len(numeric)//2],numeric[-1]]:
        mutate_hint('noncanonical_field_'+str(i),i,(0x7fffffff).to_bytes(4,'little'))
        mutate_hint('oversized_field_'+str(i),i,(0xffffffff).to_bytes(4,'little'))
    for i in [0,len(base['witness'])//2,len(base['witness'])-1]:
        c=copy.deepcopy(base);c['witness'][i]=c['witness'][i][:-2];cases.append((f'truncated_section_{i}',c))
        c=copy.deepcopy(base);c['witness'][i]+='00';cases.append((f'surplus_section_byte_{i}',c))
    c=copy.deepcopy(base);c['witness'].append('');cases.append(('surplus_witness_element',c))
    c=copy.deepcopy(base);c['witness'].pop();cases.append(('missing_witness_element',c))
    for name,root in [('hybrid','88d94cb6dd4f967ca786fdc7f14dd116947d76480131d3ba39102db4bf917080'),('final','d298373351a8a964ab461c5f657c61b83c2ef6cfa95baec14fa6d72c455e6fbb')]:
        c=copy.deepcopy(base);assert root in c['script'];c['script']=c['script'].replace(root,'00'+root[2:],1);cases.append((name+'_incorrect_expected_circuit_commitment',c))
    for trace,labels in full['labeled_constants']:
        if 'public_input_basis_one' not in labels:continue
        start,end,_=next(s for s in full['spans']if s[2]==trace)
        if full['script'][2*start:2*end]!='51':continue
        c=copy.deepcopy(base);c['script']=c['script'][:2*start]+'52'+c['script'][2*end:]
        cases.append(('incorrect_basis_public_input',c));break
    else:raise AssertionError('public input test target missing')
    path=ROOT/'build/negative-case.json';results=[]
    for name,case in cases:
        path.write_text(json.dumps(case))
        run=subprocess.run([str(ROOT/'build/harness/gsr-meter'),str(path)],capture_output=True,text=True)
        result=json.loads(run.stdout)
        if result['ok']:raise AssertionError('mutated proof accepted: '+name)
        if run.returncode not in [0,1]:raise RuntimeError(run.stderr)
        results.append({'case':name,'error':result['error'],'main_pc':result['main_pc']})
    report={'passed':True,'cases':len(results),'results':results,'scope':'Post-preparation mutations; Core executes the verifier for each case.'}
    (ROOT/'build/negative-test-results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"Rejected all {len(results)} malformed witnesses/profiles; covered {len(by_stage)} stages importing proof data.")
if __name__=='__main__':main()
