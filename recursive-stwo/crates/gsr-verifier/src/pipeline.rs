// Pinned BWS stage orchestration.
use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
use num_traits::One;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_delegation::folding::{DelegatedFirstLayerHints, DelegatedInnerLayersHints};
use recursive_stwo_delegation::script::{compute_input_labels, part1, part2, part3, part4, part5};
use recursive_stwo_last::script::global::part12_line_coeffs::generate_oods_shifted_logsize_26_labels;
use recursive_stwo_last::script::global::part13_line_coeffs::{
    generate_oods_original_logsize_26_labels, generate_oods_original_logsize_28_labels,
};
use recursive_stwo_last::script::global::{
    part10_logup, part11_point_shift, part12_line_coeffs, part13_line_coeffs, part14_line_coeffs,
    part1_fiat_shamir, part2_input_sum, part3_fiat_shamir, part4_composition, part5_composition,
    part6_composition, part7_coset_vanishing, part8_coset_vanishing, part9_coset_vanishing,
};
use recursive_stwo_last::script::hints::answer::LastAnswerHints;
use recursive_stwo_last::script::hints::decommit::LastDecommitHints;
use recursive_stwo_last::script::hints::fiat_shamir::LastFiatShamirHints;
use recursive_stwo_last::script::hints::folding::{LastFirstLayerHints, LastInnerLayersHints};
use recursive_stwo_last::script::part_last;
use recursive_stwo_last::script::per_query::{
    part10_folding, part11_folding, part12_folding, part13_clear, part1_domain_point,
    part2_numerator, part3_numerator, part4_numerator, part5_numerator, part6_numerator,
    part7_numerator, part8_fri_decommitment, part9_folding,
};
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::examples::plonk_with_poseidon::air::{
    verify_plonk_with_poseidon, PlonkWithPoseidonProof,
};
use stwo_prover::examples::plonk_without_poseidon::air::{
    verify_plonk_without_poseidon, PlonkWithoutPoseidonProof,
};

fn record_stage(cs: &BitcoinSystemRef, stages: &mut Vec<usize>) {
    stages.push(recursive_stwo_bitcoin_dsl::gsr::trace_len(&cs));
    recursive_stwo_bitcoin_dsl::gsr::stage();
}
pub fn push_delegated_information(
    proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    config: PcsConfig,
    stages: &mut Vec<usize>,
) -> LDM {
    verify_plonk_with_poseidon::<Sha256Poseidon31MerkleChannel>(
        proof.clone(),
        config,
        &[
            (1, QM31::one()),
            (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
            (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        ],
    )
    .unwrap();

    let fiat_shamir_hints = FiatShamirHints::<Sha256Poseidon31MerkleChannel>::new(
        &proof,
        config,
        &[
            (1, QM31::one()),
            (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
            (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        ],
    );
    let fri_answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
    let first_layer_hints =
        DelegatedFirstLayerHints::compute(&fiat_shamir_hints, &fri_answer_hints, &proof);
    let inner_layers_hints = DelegatedInnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );

    let mut ldm_delegated = LDM::new();

    recursive_stwo_bitcoin_dsl::gsr::section("delegation");
    let cs = part1::generate_cs(&fiat_shamir_hints, &proof, config, &mut ldm_delegated).unwrap();
    record_stage(&cs, stages);

    let cs = part2::generate_cs(
        &fiat_shamir_hints,
        &proof,
        &first_layer_hints,
        &mut ldm_delegated,
    )
    .unwrap();
    record_stage(&cs, stages);

    let cs =
        part3::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated).unwrap();
    record_stage(&cs, stages);

    let cs =
        part4::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated).unwrap();
    record_stage(&cs, stages);

    let cs =
        part5::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated).unwrap();
    record_stage(&cs, stages);

    ldm_delegated
}

pub fn push_last_information(
    proof_last: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    config_last: PcsConfig,
    inputs: &[(usize, QM31)],
    mut ldm: LDM,
    stages: &mut Vec<usize>,
) {
    verify_plonk_without_poseidon::<Sha256MerkleChannel>(proof_last.clone(), config_last, &inputs)
        .unwrap();

    let last_fiat_shamir_hints =
        LastFiatShamirHints::<Sha256MerkleChannel>::new(&proof_last, config_last, &inputs);
    let last_decommit_preprocessed_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 0);
    let last_decommit_trace_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 1);
    let last_decommit_interaction_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 2);
    let last_decommit_composition_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 3);
    let last_answer_hints = LastAnswerHints::compute(&last_fiat_shamir_hints, &proof_last);
    let last_first_layer_hints =
        LastFirstLayerHints::compute(&last_fiat_shamir_hints, &last_answer_hints, &proof_last);
    let last_inner_layers_hints = LastInnerLayersHints::compute(
        &last_first_layer_hints.folded_evals_by_column,
        &last_fiat_shamir_hints,
        &proof_last,
    );

    recursive_stwo_bitcoin_dsl::gsr::section("final_global");
    let cs = part1_fiat_shamir::generate_cs(&proof_last, &mut ldm).unwrap();
    record_stage(&cs, stages);

    let input_labels = compute_input_labels();
    for counter in 0..39 {
        let cs = part2_input_sum::generate_cs(&mut ldm, counter, &input_labels).unwrap();
        record_stage(&cs, stages);
    }

    let cs =
        part3_fiat_shamir::generate_cs(&last_fiat_shamir_hints, &proof_last, config_last, &mut ldm)
            .unwrap();
    record_stage(&cs, stages);

    let cs = part4_composition::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part5_composition::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part6_composition::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part7_coset_vanishing::generate_cs(&proof_last, &mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part8_coset_vanishing::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part9_coset_vanishing::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part10_logup::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);

    let cs = part11_point_shift::generate_cs(&proof_last, &mut ldm).unwrap();
    record_stage(&cs, stages);

    let oods_shifted_logsize_26_labels = generate_oods_shifted_logsize_26_labels();
    for counter in 0..2 {
        let cs =
            part12_line_coeffs::generate_cs(&mut ldm, counter, &oods_shifted_logsize_26_labels)
                .unwrap();
        record_stage(&cs, stages);
    }

    let oods_original_logsize_26_labels = generate_oods_original_logsize_26_labels();
    for counter in 0..12 {
        let cs =
            part13_line_coeffs::generate_cs(&mut ldm, counter, &oods_original_logsize_26_labels)
                .unwrap();
        record_stage(&cs, stages);
    }

    let oods_original_logsize_28_labels = generate_oods_original_logsize_28_labels();
    for counter in 0..2 {
        let cs =
            part14_line_coeffs::generate_cs(&mut ldm, counter, &oods_original_logsize_28_labels)
                .unwrap();
        record_stage(&cs, stages);
    }

    for query_idx in 0..8 {
        recursive_stwo_bitcoin_dsl::gsr::section(format!("query_{query_idx}"));
        let mut ldm_per_query = LDM::new();
        let cs = part1_domain_point::generate_cs(
            query_idx,
            &last_decommit_composition_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        record_stage(&cs, stages);

        let cs = part2_numerator::generate_cs(
            query_idx,
            &last_decommit_preprocessed_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        record_stage(&cs, stages);

        let cs = part3_numerator::generate_cs(
            query_idx,
            &last_decommit_trace_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        record_stage(&cs, stages);

        let cs = part4_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part5_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part6_numerator::generate_cs(
            query_idx,
            &last_decommit_interaction_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        record_stage(&cs, stages);

        let cs = part7_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part8_fri_decommitment::generate_cs(
            query_idx,
            &last_first_layer_hints,
            &last_inner_layers_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        record_stage(&cs, stages);

        let cs = part9_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part10_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part11_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part12_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);

        let cs = part13_clear::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        record_stage(&cs, stages);
    }

    let cs = part_last::generate_cs(&mut ldm).unwrap();
    record_stage(&cs, stages);
}
