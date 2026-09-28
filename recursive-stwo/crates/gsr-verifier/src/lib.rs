//! A fixed-shape, single-spend verifier for the pinned BWS recursion bundle.
mod pipeline;
use anyhow::{ensure, Context, Result};
use bincode::Options as _;
use num_traits::One;
use recursive_stwo_bitcoin_dsl::{gsr, gsr_compiler};
use recursive_stwo_delegation::script::compute_delegation_inputs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::core::{fields::qm31::QM31, fri::FriConfig, pcs::PcsConfig};
use stwo_prover::examples::plonk_with_poseidon::air::{
    verify_plonk_with_poseidon, PlonkWithPoseidonProof,
};
use stwo_prover::examples::plonk_without_poseidon::air::{
    verify_plonk_without_poseidon, PlonkWithoutPoseidonProof,
};
pub const GSR_COMMIT: &str = "d2799052604eb138c5a79acf88514a0c8b07f4ef";
pub const HYBRID_DIGEST: &str = "9c4026acc92e86d59c52a2eae4ea7c9966fa1220948ad34739c521aee4e66c96";
pub const FINAL_DIGEST: &str = "a7add69c2025bf42d9b9490db99b8d9570f75400776231c67e84466d319afcb7";
pub const HYBRID_ROOT: &str = "88d94cb6dd4f967ca786fdc7f14dd116947d76480131d3ba39102db4bf917080";
pub const FINAL_ROOT: &str = "d298373351a8a964ab461c5f657c61b83c2ef6cfa95baec14fa6d72c455e6fbb";
pub fn sha256(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data))
}
pub fn hybrid_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8),
    }
}
pub fn final_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(0, 9, 8),
    }
}
fn base_inputs() -> [(usize, QM31); 3] {
    [
        (1, QM31::one()),
        (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
        (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
    ]
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierProfile {
    pub id: String,
    pub gsr_commit: String,
    pub hybrid_fri: [u32; 3],
    pub final_fri: [u32; 3],
    pub grinding_bits: u32,
    pub hybrid_log_sizes: [u32; 2],
    pub final_log_size: u32,
    pub expected_preprocessed_commitments: [String; 2],
    pub public_input_count: usize,
    pub compiled: CompiledVerifier,
}
impl VerifierProfile {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let p: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            p.gsr_commit == GSR_COMMIT
                && p.hybrid_fri == [7, 9, 8]
                && p.final_fri == [0, 9, 8]
                && p.grinding_bits == 28,
            "unsupported protocol parameters"
        );
        ensure!(
            p.expected_preprocessed_commitments == [HYBRID_ROOT, FINAL_ROOT]
                && p.public_input_count == 273,
            "unsupported circuit commitments or public inputs"
        );
        ensure!(
            sha256(hex::decode(&p.compiled.script)?) == p.compiled.script_sha256,
            "corrupted compiled profile"
        );
        Ok(p)
    }
    /// Compilation reads the frozen profile only. It takes no proof or witness.
    pub fn compile(&self) -> CompiledVerifier {
        self.compiled.clone()
    }
}

pub struct ProofBundle {
    pub hybrid: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    pub final_proof: PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    pub fixture_digests: [String; 2],
}
impl ProofBundle {
    pub fn import(hybrid: &[u8], final_proof: &[u8]) -> Result<Self> {
        Ok(Self {
            hybrid: bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .deserialize(hybrid)
                .context("hybrid proof import")?,
            final_proof: bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .deserialize(final_proof)
                .context("final proof import")?,
            fixture_digests: [sha256(hybrid), sha256(final_proof)],
        })
    }
    pub fn reference() -> Result<Self> {
        let b = Self::import(
            include_bytes!("../../../vendor/bws-bitcoin/data/hybrid_hash.bin"),
            include_bytes!("../../../vendor/bws-bitcoin/data/bitcoin_proof.bin"),
        )?;
        ensure!(
            b.fixture_digests == [HYBRID_DIGEST, FINAL_DIGEST],
            "reference fixture digest mismatch"
        );
        Ok(b)
    }
    pub fn verify_native(&self) -> Result<Vec<(usize, QM31)>> {
        ensure!(
            self.hybrid.stmt0.log_size_plonk == 15
                && self.hybrid.stmt0.log_size_poseidon == 15
                && self.final_proof.stmt0.log_size_plonk == 17,
            "unsupported proof shape"
        );
        ensure!(
            hex::encode(self.hybrid.stark_proof.commitments[0].as_ref()) == HYBRID_ROOT
                && hex::encode(self.final_proof.stark_proof.commitments[0].as_ref()) == FINAL_ROOT,
            "unexpected preprocessed circuit commitment"
        );
        verify_plonk_with_poseidon::<Sha256Poseidon31MerkleChannel>(
            self.hybrid.clone(),
            hybrid_config(),
            &base_inputs(),
        )?;
        let inputs = compute_delegation_inputs(&self.hybrid, hybrid_config());
        ensure!(inputs.len() == 273, "delegation shape mismatch");
        verify_plonk_without_poseidon::<Sha256MerkleChannel>(
            self.final_proof.clone(),
            final_config(),
            &inputs,
        )?;
        Ok(inputs)
    }
    pub fn reference_report(&self) -> Result<serde_json::Value> {
        let inputs = self.verify_native()?;
        let h = circle_plonk_dsl_hints::FiatShamirHints::<Sha256Poseidon31MerkleChannel>::new(
            &self.hybrid,
            hybrid_config(),
            &base_inputs(),
        );
        let f = recursive_stwo_last::script::hints::fiat_shamir::LastFiatShamirHints::<
            Sha256MerkleChannel,
        >::new(&self.final_proof, final_config(), &inputs);
        macro_rules! transcript {($x:expr)=>{serde_json::json!({"alpha":$x.alpha,"z":$x.z,"random_coeff":$x.random_coeff,"after_sampled_values_random_coeff":$x.after_sampled_values_random_coeff,"oods_t":$x.oods_t,"oods_x":$x.oods_point.x,"oods_y":$x.oods_point.y,"first_layer_commitment":hex::encode($x.first_layer_commitment.as_ref()),"inner_layer_commitments":$x.inner_layer_commitments.iter().map(|x|hex::encode(x.as_ref())).collect::<Vec<_>>(),"fri_alphas":$x.fri_alphas,"last_layer_coeffs":$x.last_layer_coeffs,"queries":$x.unsorted_query_positions_per_log_size,"column_log_sizes":$x.column_log_sizes})};}
        Ok(
            serde_json::json!({"native_verified":true,"fixture_digests":self.fixture_digests,"hybrid_log_sizes":[15,15],"final_log_size":17,"hybrid_fri":[7,9,8],"final_fri":[0,9,8],"grinding_bits":28,"hybrid_roots":self.hybrid.stark_proof.commitments.iter().map(|x|hex::encode(x.as_ref())).collect::<Vec<_>>(),"final_roots":self.final_proof.stark_proof.commitments.iter().map(|x|hex::encode(x.as_ref())).collect::<Vec<_>>(),"delegated_inputs":inputs.iter().map(|(i,v)|serde_json::json!([i,v.to_m31_array().map(|x|x.0)])).collect::<Vec<_>>(),"hybrid_transcript":transcript!(h),"final_transcript":transcript!(f)}),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedWitness {
    pub profile_id: String,
    pub fixture_digests: [String; 2],
    pub witness: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    pub id: u8,
    pub bytes: String,
    pub calls: usize,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CompiledVerifier {
    pub script: String,
    pub script_sha256: String,
    pub functions: Vec<FunctionDefinition>,
    pub spans: Vec<(usize, usize, usize)>,
    pub hint_layout: Vec<(usize, usize, usize, bool)>,
    pub labeled_constants: Vec<(usize, Vec<String>)>,
    pub hint_traces: Vec<usize>,
    pub hint_labels: Vec<Vec<String>>,
    pub diagnostic_checks: usize,
    pub sections: Vec<(String, usize, usize)>,
    pub stage_trace_ends: Vec<usize>,
    pub semantic_field_operations: BTreeMap<String, u64>,
    pub stage_field_operations: Vec<BTreeMap<String, u64>>,
}
#[derive(Serialize, Deserialize)]
pub struct CostReport {
    pub profile_id: String,
    pub script_sha256: String,
    pub script_bytes: usize,
    pub witness_payload_bytes: usize,
    pub transaction_weight: u64,
    pub eligible_weight: u64,
    pub execution: serde_json::Value,
    pub semantic_field_operations: BTreeMap<String, u64>,
    pub equivalent_base_field_operations: BTreeMap<String, u64>,
    pub limits: BTreeMap<String, bool>,
    pub limits_pass: bool,
}

/// Build a candidate lowering to prepare witness data. Accept it only when its
/// code and layout exactly match the independently frozen verifier profile.
fn lower(bundle: &ProofBundle, differential: bool) -> Result<(CompiledVerifier, Vec<String>)> {
    let inputs = bundle.verify_native()?;
    let (_, result) = gsr::capture(|| {
        let mut stages = vec![];
        let ldm =
            pipeline::push_delegated_information(&bundle.hybrid, hybrid_config(), &mut stages);
        pipeline::push_last_information(
            &bundle.final_proof,
            final_config(),
            &inputs,
            ldm,
            &mut stages,
        );
        let program = if differential {
            gsr_compiler::compile_differential(gsr::current().unwrap())?
        } else {
            gsr_compiler::compile(gsr::current().unwrap())?
        };
        let compiled = CompiledVerifier {
            script: hex::encode(&program.script),
            script_sha256: sha256(&program.script),
            functions: program
                .functions
                .into_iter()
                .map(|(id, b, calls)| FunctionDefinition {
                    id,
                    bytes: hex::encode(b),
                    calls,
                })
                .collect(),
            labeled_constants: program.labeled_constants,
            hint_traces: program.hint_traces,
            hint_labels: program.hint_labels,
            diagnostic_checks: program.diagnostic_checks,
            spans: program.spans,
            hint_layout: program.hint_layout,
            sections: program.sections,
            stage_trace_ends: stages,
            semantic_field_operations: gsr::counts(),
            stage_field_operations: gsr::stages(),
        };
        Ok((compiled, program.witness.iter().map(hex::encode).collect()))
    })?;
    Ok(result)
}
pub fn freeze_reference_profile() -> Result<VerifierProfile> {
    let (compiled, _) = lower(&ProofBundle::reference()?, false)?;
    Ok(VerifierProfile {
        id: "bws-recursion-v1".into(),
        gsr_commit: GSR_COMMIT.into(),
        hybrid_fri: [7, 9, 8],
        final_fri: [0, 9, 8],
        grinding_bits: 28,
        hybrid_log_sizes: [15, 15],
        final_log_size: 17,
        expected_preprocessed_commitments: [HYBRID_ROOT.into(), FINAL_ROOT.into()],
        public_input_count: 273,
        compiled,
    })
}
pub fn prepare_witness(profile: &VerifierProfile, bundle: &ProofBundle) -> Result<PreparedWitness> {
    let (candidate, witness) = lower(bundle, false)?;
    ensure!(
        candidate.script == profile.compiled.script
            && candidate.hint_layout == profile.compiled.hint_layout,
        "proof does not match the frozen verifier shape"
    );
    Ok(PreparedWitness {
        profile_id: profile.id.clone(),
        fixture_digests: bundle.fixture_digests.clone(),
        witness,
    })
}
pub fn meter_input(
    verifier: &CompiledVerifier,
    witness: &PreparedWitness,
    budget: u64,
) -> serde_json::Value {
    let mut v = serde_json::to_value(verifier).unwrap();
    v["witness"] = serde_json::json!(witness.witness);
    v["budget"] = budget.into();
    v
}
#[cfg(test)]
mod tests;

/// A diagnostic verifier that compares every symbolic function output to the
/// pinned native implementation, including each quotient and FRI intermediate.
pub fn differential_reference() -> Result<serde_json::Value> {
    let (v, w) = lower(&ProofBundle::reference()?, true)?;
    let witness = PreparedWitness {
        profile_id: "diagnostic-only".into(),
        fixture_digests: [HYBRID_DIGEST.into(), FINAL_DIGEST.into()],
        witness: w,
    };
    let mut input = meter_input(&v, &witness, 100_000_000_000);
    input["diagnostic_only"] = true.into();
    Ok(input)
}
