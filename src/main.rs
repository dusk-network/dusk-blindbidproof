extern crate bulletproofs;
extern crate core;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate subtle;

use rand::Rng;

use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

use std::time::{Duration, Instant};

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use curve25519_dalek::scalar::Scalar;

const MIMC_ROUNDS: usize = 90;

fn main() {
    let mut blinding_rng = rand::thread_rng();

    let constants = [Scalar::random(&mut blinding_rng); MIMC_ROUNDS];

    let k = Scalar::random(&mut blinding_rng);
    let d = Scalar::random(&mut blinding_rng);

    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let seed_rs = Scalar::from_bytes_mod_order(seed);

    let (q, y, y_inv, z) = prog(seed_rs, k, d, &constants);

    let bp_gens = BulletproofGens::new(4096, 1);

    let mut total_proving = Duration::new(0, 0);
    let now = Instant::now();

    println!(
        "{:#?}",
        proof_gadget_roundtrip_helper(bp_gens, d, k, y, y_inv, q, z, seed_rs, constants)
    );

    let elapsed = now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1000_000_000.0);
    println!("Seconds: {}", sec);
}

fn prog(
    seed: Scalar,
    k: Scalar,
    d: Scalar,
    constants: &[Scalar],
) -> (Scalar, Scalar, Scalar, Scalar) {
    let m = mimc_hash(&k, &Scalar::from(0 as u8), constants);

    let x = mimc_hash(&d, &m, constants);

    let y = mimc_hash(&seed, &x, constants);

    let z = mimc_hash(&seed, &m, constants);

    let y_inv = y.invert();
    let q = d * y_inv;

    (q, y, y_inv, z)
}

fn proof_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    d: LinearCombination,
    k: LinearCombination,
    y: LinearCombination,
    y_inv: LinearCombination,
    q: LinearCombination,
    z_img: LinearCombination,
    seed: LinearCombination,
    constants: [Scalar; MIMC_ROUNDS],
) {
    // Prove z
    let m = mimc_gadget(cs, k, Scalar::from(0 as u8).into(), constants);

    let x = mimc_gadget(cs, d.clone(), m.clone(), constants);

    let y = mimc_gadget(cs, seed.clone(), x, constants);

    let z = mimc_gadget(cs, seed, m, constants);

    cs.constrain(z_img - z);

    // Prove Q
    score_gadget(cs, d, y, y_inv, q);
}

fn mimc_hash(left: &Scalar, right: &Scalar, constants: &[Scalar]) -> Scalar {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    let mut x = left.clone();
    let key = right.clone();

    for i in 0..MIMC_ROUNDS {
        let a: Scalar = x + key + constants[i];
        let a_2 = a * a;
        let a_3 = a_2 * a;
        let a_4 = a_2 * a_2;
        x = a_3 * a_4;
    }
    x + key
}

// N.B. the constrain on the image has been removed, as we will not know the intermediate images
fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: LinearCombination,
    right: LinearCombination,
    constants: [Scalar; MIMC_ROUNDS],
) -> LinearCombination {
    assert_eq!(MIMC_ROUNDS, constants.len());

    let mut x = left.clone();
    let mut key = right.clone();

    for i in 0..MIMC_ROUNDS {

        // x + k + c[i]
        let a = x + key.clone() + constants[i];

        // (a)^2
        let (_, _, a_2) = cs.multiply(a.clone(), a.clone());

        // (a)^3
        let (_, _, a_3) = cs.multiply(a_2.clone().into(), a.clone().into());

        // (a)^4
        let (_, _, a_4) = cs.multiply(a_2.clone().into(), a_2.clone().into());

        // (a)^7
        let (_, _, a_7) = cs.multiply(a_4.into(), a_3.into());

        x = a_7.into();
    }

    x + key
}

fn score_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    d: LinearCombination,
    y: LinearCombination,
    y_inv: LinearCombination,
    q: LinearCombination,
) {
    let one = Scalar::from(1 as u8);

    // check that Yinv * Y = 1
    let (_, _, one_var) = cs.multiply(y, y_inv.clone());
    cs.constrain(one_var - one);

    // Q = F(d,Y)
    let (_, _, q_var) = cs.multiply(d, y_inv);
    cs.constrain(q - q_var);
}

fn proof_gadget_roundtrip_helper(
    bp_gens: BulletproofGens,
    d: Scalar,
    k: Scalar,
    y: Scalar,
    y_inv: Scalar,
    q: Scalar,
    z_img: Scalar,
    seed: Scalar,
    constants: [Scalar; MIMC_ROUNDS],
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();

    // Prover's scope
    let (proof, commitments) = {
        let mut transcript = Transcript::new(b"BlindBidProofGadget");

        // 1. Create a prover
        let mut prover = Prover::new(&bp_gens, &pc_gens, &mut transcript);

        // 2. Commit high-level variables
        let mut blinding_rng = rand::thread_rng();

        let (commitments, mut vars): (Vec<_>, Vec<_>) = [d, k, y, y_inv]
            .into_iter()
            .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
            .unzip();

        // 3. Build a CS
        proof_gadget(
            &mut prover,
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
            q.into(),
            z_img.into(),
            seed.into(),
            constants.clone(),
        );

        // 4. Make a proof
        let proof = prover.prove()?;

        (proof, commitments)
    };

    // Verifier logic

    let mut transcript = Transcript::new(b"BlindBidProofGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let mut vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    // 3. Build a CS
    proof_gadget(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        q.into(),
        z_img.into(),
        seed.into(),
        constants.clone(),
    );

    // 4. Verify the proof
    verifier
        .verify(&proof)
        .map_err(|_| R1CSError::VerificationError)
}
