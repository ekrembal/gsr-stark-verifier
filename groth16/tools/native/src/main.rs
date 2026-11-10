use std::{env, fs, path::PathBuf};

use borsh::{from_slice, to_vec};
use groth16_methods::{GROTH16_GUEST_ELF, GROTH16_GUEST_ID};
use num_bigint::BigUint;
use risc0_groth16::Seal;
use risc0_zkvm::{
    default_prover, sha::Digestible, ExecutorEnv, InnerReceipt, Prover, ProverOpts, Receipt,
    VerifierContext,
};
use serde_json::{json, Value};

const VK: [&str; 18] = [
    "20491192805390485299153009773594534940189261866228447918068658471970481763042",
    "9383485363053290200918347156157836566562967994039712273449902621266178545958",
    "4252822878758300859123897981450591353533073413197771768651442665752259397132",
    "6375614351688725206403948262868962793625744043794305715222011528459656738731",
    "21847035105528745403288232691147584728191162732299865338377159692350059136679",
    "10505242626370262277552901082094356697409835680220590971873171140371331206856",
    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    "1668323501672964604911431804142266013250380587483576094566949227275849579036",
    "12043754404802191763554326994664886008979042643626290185762540825416902247219",
    "7710631539206257456743780535472368339139328733484942210876916214502466455394",
    "13740680757317479711909903993315946540841369848973133181051452051592786724563",
    "8446592859352799428420270221449902464741693648963397251242447530457567083492",
    "1064796367193003797175961162477173481551615790032213185848276823815288302804",
    "3179835575189816632597428042194253779818690147323192973511715175294048485951",
    "20895841676865356752879376687052266198216014795822152491318012491767775979074",
];

const IC: [[&str; 2]; 4] = [
    [
        "5332723250224941161709478398807683311971555792614491788690328996478511465287",
        "21199491073419440416471372042641226693637837098357067793586556692319371762571",
    ],
    [
        "12457994489566736295787256452575216703923664299075106359829199968023158780583",
        "19706766271952591897761291684837117091856807401404423804318744964752784280790",
    ],
    [
        "19617808913178163826953378459323299110911217259216006187355745713323154132237",
        "21663537384585072695701846972542344484111393047775983928357046779215877070466",
    ],
    [
        "6834578911681792552110317589222010969491336870276623105249474534788043166867",
        "15060583660288623605191393599883223885678013570733629274538391874953353488393",
    ],
];

fn split_digest(bytes: &[u8]) -> [BigUint; 2] {
    assert_eq!(bytes.len(), 32);
    [
        BigUint::from_bytes_le(&bytes[..16]),
        BigUint::from_bytes_le(&bytes[16..]),
    ]
}

fn decimal(bytes: &[u8]) -> String {
    BigUint::from_bytes_be(bytes).to_str_radix(10)
}

fn point_g1(coords: &[Vec<u8>]) -> Value {
    json!([decimal(&coords[0]), decimal(&coords[1])])
}

fn point_g2(coords: &[Vec<Vec<u8>>]) -> Value {
    json!([
        [decimal(&coords[0][0]), decimal(&coords[0][1])],
        [decimal(&coords[1][0]), decimal(&coords[1][1])]
    ])
}

fn export(receipt: Receipt, output: PathBuf) -> anyhow::Result<()> {
    receipt.verify(GROTH16_GUEST_ID)?;
    let InnerReceipt::Groth16(groth16) = &receipt.inner else {
        anyhow::bail!("prover returned a non-Groth16 receipt");
    };
    if groth16.seal.len() != 256 {
        anyhow::bail!(
            "unexpected RISC Zero Groth16 seal length: {}",
            groth16.seal.len()
        );
    }

    let params = VerifierContext::default()
        .groth16_verifier_parameters
        .expect("default Groth16 verifier parameters");
    let claim_digest = groth16.claim.digest();
    let [a0, a1] = split_digest(params.control_root.as_bytes());
    let [c0, c1] = split_digest(claim_digest.as_bytes());
    let id = BigUint::from_bytes_le(params.bn254_control_id.as_bytes());
    let seal = Seal::decode(&groth16.seal)?;

    fs::create_dir_all(&output)?;
    fs::write(output.join("seal.bin"), &groth16.seal)?;
    fs::write(output.join("receipt.borsh"), to_vec(&receipt)?)?;

    let vk = json!({
        "alpha_g1": [&VK[0], &VK[1]],
        "beta_g2": [[&VK[2], &VK[3]], [&VK[4], &VK[5]]],
        "gamma_g2": [[&VK[6], &VK[7]], [&VK[8], &VK[9]]],
        "delta_g2": [[&VK[10], &VK[11]], [&VK[12], &VK[13]]],
        "ic": [
            [&VK[14], &VK[15]],
            [&VK[16], &VK[17]],
            [&IC[0][0], &IC[0][1]],
            [&IC[1][0], &IC[1][1]],
            [&IC[2][0], &IC[2][1]],
            [&IC[3][0], &IC[3][1]]
        ]
    });
    let fixture = json!({
        "risc0_version": "3.0.6",
        "image_id": hex::encode(risc0_zkvm::Digest::from(GROTH16_GUEST_ID).as_bytes()),
        "journal": hex::encode(&receipt.journal.bytes),
        "claim_digest": hex::encode(claim_digest.as_bytes()),
        "control_root": hex::encode(params.control_root.as_bytes()),
        "bn254_control_id": hex::encode(params.bn254_control_id.as_bytes()),
        "public_inputs": [a0.to_string(), a1.to_string(), c0.to_string(), c1.to_string(), id.to_string()],
        "seal": {
            "a": point_g1(&seal.a),
            "b": point_g2(&seal.b),
            "c": point_g1(&seal.c)
        },
        "verifying_key": vk,
        "native_verification": "passed: Receipt::verify(GROTH16_GUEST_ID)"
    });
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&fixture)?,
    )?;
    println!(
        "verified and exported Groth16 receipt: {}",
        output.display()
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args_os().skip(1);
    let command = args.next().unwrap_or_else(|| "generate".into());
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"));

    match command.to_str() {
        Some("generate") => {
            let env = ExecutorEnv::builder().build()?;
            let info =
                default_prover().prove_with_opts(env, GROTH16_GUEST_ELF, &ProverOpts::groth16())?;
            export(info.receipt, output)
        }
        Some("verify") => {
            let receipt = from_slice(&fs::read(output.join("receipt.borsh"))?)?;
            export(receipt, output)
        }
        _ => anyhow::bail!("usage: groth16-fixture [generate|verify] [fixture-directory]"),
    }
}
