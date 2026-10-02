# Frozen JoinSplit fixture and covenant binding

The full 208-segment proving run uses the frozen real JoinSplit proof and
196-byte settlement journal. Its settlement transaction contains placeholder
scripts. This prevents that particular receipt, if completed, from demonstrating
an actual privacy covenant settlement. It does not remove the value of complete
native, recursive, padded-hash and fixed-statement Script verification.

`inspect_covenant_binding.py` reconstructs the exact transaction input/output
digest encodings from `pr_bitcoin_adapter`, verifies both against the frozen
journal, and generates the covenant commitments for the earlier template image
and the optimized image. It uses template metadata solely to generate scripts;
it does not treat a modified template as a verified receipt.

The measured inspection passed in 4.135 seconds at 31,200 KiB peak process RSS.
It ran at reduced CPU priority alongside the full prover; this is not a timing
benchmark. The complete comparison is in
[`full-proof-covenant-binding.json`](full-proof-covenant-binding.json).

| Binding | Frozen fixture | Optimized covenant |
|---|---|---|
| Input zero script | `5120` followed by 32 `aa` bytes | `51205b8ddb7f31f57faa2247b607e4b7effc0b64f3e6c3d9e9b9f705430166884822` |
| Output zero script | Same placeholder | `512099f6e5f9c4191d487d27518f8733d7564774272141852e69890ecf00f84b7ba7` |
| Funding input script | `512041` | Must be an actually spendable funded input |

Neither placeholder matches the earlier template's generated covenant either.
Replacing the two rollup scripts changes **both** bound transaction digests.
Changing prevouts, funding scripts, values or other bound fields likewise needs
a corresponding new journal and application proof. The frozen inputs have not
been changed. The inspection covers only the two transaction digest fields;
complete receipt verification separately checks the whole journal.

The earlier image is
`a55fa2f95eb766642b9bd933c834775aa90e71dd8054b129107eea7030cbf761`;
the optimized image is
`fc7c90972cfd366c450cf202c7131fea5d04f81b76f93d6925ce15e33cdd14be`.
Both generated scripts are 159,229 bytes, but their commitments differ. The
existing covenant hardcodes the image and derives its successor from its own
script, changing only the state-root prefix. It therefore provides no implicit
guest-image upgrade. `RollupDescriptor::rollup_id` also commits to the image;
under the existing protocol, a fresh descriptor changes the rollup identity and
the domain of client statements and notes. Actual migration of existing funds
requires an explicitly designed and reviewed mechanism, not replacing an image
constant in tooling.

An applicable follow-up demonstration needs authenticated local genesis,
spendable local funding inputs, client statements for the correct rollup and
outpoints, the generated successor script, a new bound application proof, and
complete covenant/consensus checks. Existing anchor-only regtest results and
fixed-statement Script checks do not cover that complete JoinSplit flow. No
covenant migration or protocol redesign is implemented by this inspection.

Reproduce from the repository root (outputs must not already exist):

```sh
source /workspace/.gsr-env/activate.sh
python3 privacy-rollup/tools/inspect_covenant_binding.py \
  --witness build/full-joinsplit-191m/inputs/witness.json \
  --journal build/full-joinsplit-191m/inputs/expected-journal.bin \
  --template privacy-rollup/fixtures/apply-batch/receipt-template.json \
  --image fc7c90972cfd366c450cf202c7131fea5d04f81b76f93d6925ce15e33cdd14be \
  --out build/feasibility/full-proof-covenant-binding-reproduction
```

The source/template assumptions, padded hash audit gap and formal coverage gaps
remain as described in the aggregation review. Script commitment comparison is
neither proof verification nor a protocol soundness proof.
