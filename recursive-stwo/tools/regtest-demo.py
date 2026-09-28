#!/usr/bin/env python3
"""Build, fund, policy-check, broadcast and mine one 0xc2 Taproot spend."""
from pathlib import Path
import sys,json,subprocess
from paths import VERIFIER_ROOT as root, BITCOIN_SOURCE, BITCOIN_BUILD
sys.path.insert(0,str(BITCOIN_SOURCE/'test/functional'))
from transaction import build,meter_request
from test_framework.script import CScript,taproot_construct
from test_framework.address import output_key_to_p2tr

def rpc(method,*args):
    cmd=[str(BITCOIN_BUILD/'bin/bitcoin-cli'),'-regtest','-datadir='+str(root/'build/regtest'),'-rpcport=19452','-stdin',method]
    proc=subprocess.run(cmd,input=''.join((a if isinstance(a,str) else json.dumps(a,separators=(',',':')))+'\n' for a in args),text=True,capture_output=True)
    if proc.returncode:raise RuntimeError(proc.stderr)
    try:return json.loads(proc.stdout)
    except json.JSONDecodeError:return proc.stdout.strip()

def main():
    try:rpc('getblockcount')
    except RuntimeError:
        data=root/'build/regtest';data.mkdir(parents=True,exist_ok=True)
        subprocess.run([str(BITCOIN_BUILD/'bin/bitcoind'),'-regtest','-datadir='+str(data),'-daemonwait','-server','-listen=0','-rpcport=19452','-port=19453','-vbparams=script_restoration:0:3999999999'],check=True)
    deployment=rpc('getdeploymentinfo')['deployments']['script_restoration']
    assert deployment['bip9']['start_time']==0,'Regtest must explicitly enable script_restoration.'
    path=Path(sys.argv[1] if len(sys.argv)>1 else root/'build/verifier.json')
    bundle=json.loads(path.read_text());script=bytes.fromhex(bundle['script'])
    internal=bytes.fromhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
    taproot=taproot_construct(internal,[('verifier',CScript(script),0xc2)])
    address=output_key_to_p2tr(taproot.output_pubkey)
    # Mine a dedicated funding coinbase. No wallet or external funds are used.
    funding_block=rpc('generatetoaddress',1,address)[0]
    rpc('generatetoaddress',100,address)
    while rpc('getdeploymentinfo')['deployments']['script_restoration']['bip9']['status']!='active':
        rpc('generatetoaddress',144,address)
    funding=rpc('getblock',funding_block,2)['tx'][0]
    index=next(i for i,out in enumerate(funding['vout']) if out['scriptPubKey']['hex']==taproot.scriptPubKey.hex())
    value=round(funding['vout'][index]['value']*100_000_000)
    tx,taproot,control=build(bundle,funding['txid'],index,value)
    raw=tx.serialize().hex();weight=tx.get_weight()
    measurement=meter_request(bundle,tx,value)
    (root/'build/transaction-meter-input.json').write_text(json.dumps(measurement))
    (root/'build/spend.hex').write_text(raw+'\n')
    result={'script_sha256':bundle['script_sha256'],'node_commit':subprocess.check_output(['git','-C',str(BITCOIN_SOURCE),'rev-parse','HEAD'],text=True).strip(),'node_version':rpc('getnetworkinfo')['subversion'],'weight':weight,'eligible_weight':weight,'varops_budget':weight*10000,'internal_key':internal.hex(),'leaf_version':194,'control_block':control.hex(),'funding_txid':funding['txid'],'activation':rpc('getdeploymentinfo')['deployments']['script_restoration']}
    acceptance=rpc('testmempoolaccept',[raw]);result['mempool_acceptance']=acceptance
    if weight<=400000 and acceptance[0]['allowed']:
        txid=rpc('sendrawtransaction',raw);block=rpc('generatetoaddress',1,address)[0]
        result.update(txid=txid,blockhash=block,mined=txid in rpc('getblock',block)['tx'])
    (root/'build/regtest-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if not result.get('mined'):sys.exit(1)
if __name__=='__main__':main()
