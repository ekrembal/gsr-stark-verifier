//! ProveKit integration: proving join-splits, native verification, and guest input encoding.
use std::path::Path;

use anyhow::{ensure, Context, Result};
use pr_crypto::{to_fe, to_fr};
use pr_protocol_types::{JoinSplitPublic, RollupTransaction};
use provekit_common::{file::read, Format, NoirProof, Prover, PublicInputs, Verifier, WhirR1CSProof};
use provekit_prover::Prove;
use provekit_verifier::Verify;

pub fn load_prover(pkp: &Path) -> Result<Prover> {
    read(pkp).context("reading ProveKit prover key")
}

pub fn load_verifier(pkv: &Path) -> Result<Verifier> {
    read(pkv).context("reading ProveKit verifier key")
}

/// Proves a join-split from its Noir `Prover.toml` and checks the proof's public inputs.
pub fn prove(prover: Prover, prover_toml: &str, public: &JoinSplitPublic) -> Result<NoirProof> {
    let proof = prover.prove_with_inputs(prover_toml, Format::Toml).context("ProveKit proving")?;
    check_public_inputs(&proof, public)?;
    Ok(proof)
}

pub fn check_public_inputs(proof: &NoirProof, public: &JoinSplitPublic) -> Result<()> {
    let got: Vec<_> = proof.public_inputs.0.iter().map(to_fe).collect();
    ensure!(got == public.public_inputs(), "proof public inputs differ from the statement");
    Ok(())
}

/// Rebuilds the ProveKit proof object carried by a rollup transaction.
pub fn proof_of(tx: &RollupTransaction) -> NoirProof {
    NoirProof {
        public_inputs: PublicInputs(tx.public.public_inputs().iter().map(to_fr).collect()),
        whir_r1cs_proof: WhirR1CSProof {
            narg_string: tx.proof_narg.clone(),
            hints: tx.proof_hints.clone(),
            #[cfg(debug_assertions)]
            pattern: Vec::new(),
        },
    }
}

/// Native verification of a rollup transaction's proof against its own statement.
pub fn verify(verifier: &Verifier, tx: &RollupTransaction) -> Result<()> {
    verifier.verify_ref(&proof_of(tx)).context("ProveKit verification")
}

/// Uncompressed postcard encoding of the verifier key, as read by the RISC Zero guest.
pub fn guest_verifier_bytes(verifier: &Verifier) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(verifier)?)
}

pub fn guest_proof_bytes(proof: &NoirProof) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(proof)?)
}
