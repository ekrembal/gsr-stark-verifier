#!/usr/bin/env python3
"""Import the exact upstream binary fixtures and verify their SHA-256 digests."""
import hashlib,json,sys,urllib.request
from pathlib import Path
PIN='083df955a7588ae1bb5e4e251dbf7df6733a08bc'
FILES={'hybrid_hash.bin':'9c4026acc92e86d59c52a2eae4ea7c9966fa1220948ad34739c521aee4e66c96','bitcoin_proof.bin':'a7add69c2025bf42d9b9490db99b8d9570f75400776231c67e84466d319afcb7'}
out=Path(sys.argv[1] if len(sys.argv)>1 else 'fixtures');out.mkdir(parents=True,exist_ok=True)
for name,digest in FILES.items():
    url=f'https://raw.githubusercontent.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin/{PIN}/data/{name}'
    with urllib.request.urlopen(url,timeout=60)as response:data=response.read()
    if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('digest mismatch: '+name)
    (out/name).write_bytes(data)
    print(f'{name}: {len(data)} bytes, SHA-256 {digest}')
(out/'source-manifest.json').write_text(json.dumps({'repository':'https://github.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin','commit':PIN,'sha256':FILES},indent=2)+'\n')
