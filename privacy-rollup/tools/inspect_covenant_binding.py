#!/usr/bin/env python3
"""Inspect frozen settlement/covenant commitments without asserting a proof.

The receipt template is used only to generate scripts. A substituted image or
journal does not turn it into a verified receipt. This tool never edits inputs.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct

import rollup_covenant as rc


def sha(data):
    return hashlib.sha256(data).digest()


def varbytes(data):
    data = bytes(data)
    n = len(data)
    prefix = (bytes([n]) if n < 253 else b'\xfd' + struct.pack('<H', n)
              if n <= 65535 else b'\xfe' + struct.pack('<I', n)
              if n <= 0xffffffff else b'\xff' + struct.pack('<Q', n))
    return prefix + data


def transaction_digests(tx):
    inputs = struct.pack('<II', tx['version'], tx['lock_time'])
    for item in tx['inputs']:
        inputs += bytes(item['prevout']['txid'])
        inputs += struct.pack('<IQ', item['prevout']['vout'], item['amount'])
        inputs += varbytes(item['script_pubkey']) + varbytes(item['script_sig'])
        inputs += struct.pack('<I', item['sequence'])
    outputs = b''.join(struct.pack('<Q', o['value']) + varbytes(o['script_pubkey'])
                       for o in tx['outputs'])
    return sha(inputs), sha(outputs)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--witness', type=Path, required=True)
    p.add_argument('--journal', type=Path, required=True)
    p.add_argument('--template', type=Path, required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    witness = json.loads(a.witness.read_text())
    journal = a.journal.read_bytes()
    assert len(journal) == 196 and len(bytes.fromhex(a.image)) == 32
    assert journal[4:36] == bytes(witness['old_state']['rollup_id'])
    tx = witness['settlement']
    inputs, outputs = transaction_digests(tx)
    assert inputs == journal[100:132] and outputs == journal[132:164]
    template = json.loads(a.template.read_text())
    result = {'scope': 'Commitment inspection only; no receipt verification or chain settlement',
              'witness_sha256': sha(a.witness.read_bytes()).hex(),
              'journal_sha256': sha(journal).hex(),
              'frozen_transaction_digests_match_journal': True,
              'frozen_input_scripts': [bytes(i['script_pubkey']).hex() for i in tx['inputs']],
              'frozen_output_scripts': [bytes(o['script_pubkey']).hex() for o in tx['outputs']],
              'images': {}}
    for name, image in [('old_template', template['claim']['pre']), ('optimized', a.image)]:
        parameters = copy.deepcopy(template)
        parameters['claim']['pre'] = image
        parameters['journal'] = journal.hex()
        parameters['claim']['journal_digest'] = sha(journal).hex()
        parameters['claim']['output'] = rc.ref.output_digest(
            sha(journal), bytes.fromhex(parameters['claim']['assumptions_digest'])).hex()
        parameters['claim_digest'] = rc.ref.claim_digest(parameters['claim']).hex()
        covenant = rc.Covenant(parameters, journal[4:36], journal[36:68])
        successor = covenant.for_root(journal[68:100])
        changed = copy.deepcopy(tx)
        changed['inputs'][0]['script_pubkey'] = list(covenant.script_pubkey)
        changed['outputs'][0]['script_pubkey'] = list(successor.script_pubkey)
        new_inputs, new_outputs = transaction_digests(changed)
        (a.out / (name + '.script')).write_bytes(covenant.script)
        result['images'][name] = {
            'image_id': image, 'script_bytes': len(covenant.script),
            'script_sha256': sha(covenant.script).hex(),
            'input_script_pubkey': covenant.script_pubkey.hex(),
            'successor_script_pubkey': successor.script_pubkey.hex(),
            'frozen_input_matches': bytes(tx['inputs'][0]['script_pubkey']) == covenant.script_pubkey,
            'frozen_successor_matches': bytes(tx['outputs'][0]['script_pubkey']) == successor.script_pubkey,
            'replacing_scripts_preserves_inputs_digest': new_inputs == inputs,
            'replacing_scripts_preserves_outputs_digest': new_outputs == outputs,
            'replacement_inputs_digest': new_inputs.hex(),
            'replacement_outputs_digest': new_outputs.hex(),
        }
    (a.out / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
