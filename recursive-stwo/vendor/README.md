These source snapshots retain their upstream licenses. They are vendored because the proof fixtures require the older backend layout and several original manifests used unpublished relative paths.

| Directory | Upstream | Revision |
|---|---|---|
| bws-bitcoin | Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin | 083df955a7588ae1bb5e4e251dbf7df6733a08bc |
| bws-recursion | Bitcoin-Wildlife-Sanctuary/recursive-stwo | caea77fe70b0d313c90250c13e893cec22ad8bb0 |
| bws-stwo | Bitcoin-Wildlife-Sanctuary/stwo-circle-poseidon-plonk | 73d9970a24012a194f90fc74adeac63d1fee00e3 |

Local changes: manifest paths/pinned Git dependencies; GSR lowering and shared live values in `bws-bitcoin/bitcoin_dsl`; unsigned arithmetic, hash-boundary encoding, transcript extraction and grinding in `bws-bitcoin/primitives`; explicit circuit commitment checks and public-input diagnostic labels in the verifier stages. One upstream debug print was removed. The original native backend and proof parameters are unchanged. `Cargo.lock` pins all transitive dependencies.
