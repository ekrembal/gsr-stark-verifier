"""Deterministic transaction construction; uses pinned Core's test primitives."""
import sys
from paths import VERIFIER_ROOT as ROOT, BITCOIN_SOURCE
sys.path.insert(0,str(BITCOIN_SOURCE/'test/functional'))
from test_framework.script import CScript,taproot_construct
from test_framework.messages import CTransaction,CTxIn,CTxOut,COutPoint,CTxInWitness
NUMS=bytes.fromhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
def build(bundle,txid='00'*32,index=0,value=5_000_000_000):
    script=bytes.fromhex(bundle['script']);taproot=taproot_construct(NUMS,[('verifier',CScript(script),0xc2)])
    tx=CTransaction();tx.vin=[CTxIn(COutPoint(int(txid,16),index))]
    tx.vout=[CTxOut(value-200_000,taproot.scriptPubKey)]
    control=bytes([0xc2|taproot.negflag])+NUMS
    tx.wit.vtxinwit=[CTxInWitness()];tx.wit.vtxinwit[0].scriptWitness.stack=[bytes.fromhex(x)for x in bundle['witness']]+[script,control]
    return tx,taproot,control

def meter_request(bundle,tx=None,spent_value=5_000_000_000):
    if tx is None:tx,taproot,_=build(bundle)
    else:_,taproot,_=build(bundle)
    # Exact size is known before funding. Core independently recomputes weight
    # and eligibility from the complete serialized transaction and spent output.
    out={**bundle,'budget':tx.get_weight()*10000,'transaction_hex':tx.serialize().hex(),
         'spent_outputs':[{'value':spent_value,'script_pub_key':taproot.scriptPubKey.hex()}]}
    spans=bundle.get('spans',[])
    out['stage_script_ends']=[max((end for _,end,t in spans if t<cutoff),default=0)for cutoff in bundle.get('stage_trace_ends',[])]
    return out
