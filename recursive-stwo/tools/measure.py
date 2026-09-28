#!/usr/bin/env python3
"""Measure the complete verifier with Core's transaction-derived budget."""
import json,sys,subprocess
from transaction import ROOT,meter_request

def main():
    bundle=json.loads(open(sys.argv[1] if len(sys.argv)>1 else ROOT/'build/verifier.json').read())
    request=meter_request(bundle);path=ROOT/'build/measurement-input.json';path.write_text(json.dumps(request))
    proc=subprocess.run([str(ROOT/'build/harness/gsr-meter'),str(path)],capture_output=True,text=True)
    execution=json.loads(proc.stdout)
    (ROOT/'build/execution-costs.json').write_text(json.dumps(execution,indent=2)+'\n')
    previous={}
    for stage,cumulative in zip(execution['stages'],bundle['stage_field_operations']):
        stage['semantic_field_operations']={k:v-previous.get(k,0)for k,v in cumulative.items() if v!=previous.get(k,0)}
        previous=cumulative
    fields=bundle['semantic_field_operations'];get=lambda key:fields.get(key,0)
    equivalent={
        'm31_add':get('m31_add')+2*get('cm31_add')+2*get('cm31_mul')+4*get('qm31_add')+15*get('qm31_mul'),
        'm31_sub':get('m31_sub')+2*get('cm31_sub')+3*get('cm31_mul')+4*get('qm31_sub')+14*get('qm31_mul'),
        'm31_mul':get('m31_mul')+3*get('cm31_mul')+9*get('qm31_mul')+4*get('qm31_scalar_mul'),
        'm31_neg':get('m31_neg'),
    }
    checks={
        'standard_weight':execution['transaction_weight']<=400000,
        'varops':execution['varops']<=execution['budget'],
        'invoked_body_bytes':execution['invoked_body_bytes']<=4000000,
        'function_ids':len(bundle['functions'])<=256,
        'stack_entries':execution['peak_entries']<=32768,
        'live_payload':execution['peak_payload_bytes']<=8000000,
        'single_element':execution['peak_element_bytes']<=4000000,
        'verifier':execution['ok'] and execution['final_stack_exact_true'] and not execution['immediate_success'],
    }
    result={'profile_id':'bws-recursion-v1','script_sha256':bundle['script_sha256'],'script_bytes':len(bytes.fromhex(bundle['script'])),
        'witness_payload_bytes':sum(len(bytes.fromhex(w))for w in bundle['witness']),
        'witness_sections':bundle['sections'],'transaction_weight':execution['transaction_weight'],
        'eligible_weight':execution['budget']//10000,'execution':execution,
        'semantic_field_operations':fields,'equivalent_base_field_operations':equivalent,
        'limits':checks,'limits_pass':all(checks.values()),
        'measurement_scope':'Complete 1-input, 1-output transaction; NUMS internal key; leaf 0xc2. Core independently derives weight and varops budget.'}
    (ROOT/'build/cost-report.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k]for k in ['script_bytes','witness_payload_bytes','transaction_weight','eligible_weight','semantic_field_operations','equivalent_base_field_operations','limits_pass']},indent=2))
    if proc.returncode or not result['limits_pass']:sys.exit(1)
if __name__=='__main__':main()
