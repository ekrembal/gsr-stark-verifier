#!/usr/bin/env python3
"""Check a real padded receipt with the Python reference and pinned Script meter.

This exercises a fixed-statement Taproot spend. It does not assert that a
privacy-rollup covenant bound to an older image/transaction can spend it.
All outputs go to a fresh directory; existing fixtures and profiles are untouched.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'recursive-stwo/tools'))
sys.path.insert(0,str(ROOT/'risc0-succinct/tools'))
import generate as g
import reference as ref
import measure
from transaction import meter_request


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--seal',type=Path,required=True)
    p.add_argument('--journal',type=Path,required=True)
    p.add_argument('--image',required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    start=time.monotonic()
    receipt=json.loads(a.receipt.read_text());seal=a.seal.read_bytes()
    assert receipt['claim']['pre']==a.image
    assert bytes.fromhex(receipt['journal'])==a.journal.read_bytes()
    assert receipt['claim']['assumptions_digest']=='00'*32
    assert receipt['claim']['sys_exit']==receipt['claim']['user_exit']==0
    assert ref.claim_digest(receipt['claim'])==bytes.fromhex(receipt['claim_digest'])
    assert ref.output_digest(hashlib.sha256(a.journal.read_bytes()).digest(),bytes(32))==bytes.fromhex(receipt['claim']['output'])
    ref.verify_receipt(receipt,seal)
    gen=g.Gen(g.Statement(receipt),ref.load_circuit())
    first=gen.generate()[1]
    script,info=gen.generate(first['accesses'],first['pool'])
    info['pooled']=len(info.pop('pool'));del info['accesses']
    stack=g.build_witness(gen,receipt,seal)
    bundle={'script':script.code.hex(),'witness':[x.hex() for x in stack],'info':info}
    (a.out/'bundle.json').write_text(json.dumps(bundle)+'\n')
    def execute(name,bundle):
        request=meter_request(bundle)
        path=a.out/(name+'-request.json');path.write_text(json.dumps(request)+'\n')
        command=[str(measure.METER),str(path)]
        r=subprocess.run(command,capture_output=True,text=True)
        (a.out/(name+'.stdout')).write_text(r.stdout)
        (a.out/(name+'.stderr')).write_text(r.stderr)
        execution=json.loads(r.stdout)
        return {'command':command,'exit_code':r.returncode,'execution':execution}
    good=execute('valid',bundle)
    limits=measure.limits(bundle,good['execution'])
    assert all(limits.values()),limits
    corrupt=copy.deepcopy(bundle)
    out_index=len(stack)-len(g.SETUP_ITEMS)+list(reversed(g.SETUP_ITEMS)).index('out')
    changed=bytearray.fromhex(corrupt['witness'][out_index])
    # The claim digest uses all 16 halfwords in output slot 1. Mutate its
    # first byte, preserving the witness length and every other proof byte.
    assert len(changed)>=68
    changed[64]^=1
    corrupt['witness'][out_index]=changed.hex()
    bad=execute('wrong-claim-output',corrupt)
    assert not bad['execution']['ok']
    report={'scope':'Real padded receipt; complete fixed-statement transaction, not privacy covenant migration',
            'image_id':a.image,'reference_verified':True,'limits':limits,
            'wrong_claim_output_rejected':True,'valid':good,'negative':bad,
            'seconds':time.monotonic()-start,'receipt_sha256':hashlib.sha256(a.receipt.read_bytes()).hexdigest(),
            'seal_sha256':hashlib.sha256(seal).hexdigest()}
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    keys=['ok','transaction_weight','budget','varops','peak_entries','peak_payload_bytes']
    print(json.dumps({'seconds':report['seconds'],'image_id':a.image,'reference_verified':True,
                      'wrong_claim_output_rejected':True,'limits':limits,
                      'execution':{k:good['execution'][k] for k in keys}}))


if __name__=='__main__':
    main()
