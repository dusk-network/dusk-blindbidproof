#![feature(test)]
extern crate bulletproofs;
extern crate core;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate subtle;
use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::{thread_rng, Rng};

use crate::gadgets::*;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError, R1CSProof, Variable};
use curve25519_dalek::scalar::Scalar;

fn prog(
    seed: Scalar,
    k: Scalar,
    d: Scalar,
    constants: &[Scalar],
) -> (Scalar, Scalar, Scalar, Scalar, Scalar) {
    let m = mimc_hash(&k, &Scalar::from(0 as u8), constants);

    let x = mimc_hash(&d, &m, constants);

    let y = mimc_hash(&seed, &x, constants);

    let z = mimc_hash(&seed, &m, constants);

    let y_inv = y.invert();
    let q = d * y_inv;

    (q, x, y, y_inv, z)
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

fn prove(
    d: Scalar,
    k: Scalar,
    y: Scalar,
    y_inv: Scalar,
    q: Scalar,
    z_img: Scalar,
    seed: Scalar,
    constants: [Scalar; MIMC_ROUNDS],
    list: Vec<Scalar>,
    toggle: &[u64],
) -> Result<
    (
        R1CSProof,
        Vec<CompressedRistretto>,
        Vec<CompressedRistretto>,
    ),
    R1CSError,
> {
    let pc_gens = PedersenGens::default();
    let mut bp_gens = BulletproofGens::new(2048, 1);

    let mut transcript = Transcript::new(b"BlindBidProofGadget");

    // 1. Create a prover
    let mut prover = Prover::new(&bp_gens, &pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let mut blinding_rng = rand::thread_rng();

    let (commitments, mut vars): (Vec<_>, Vec<_>) = [d, k, y, y_inv]
        .into_iter()
        .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
        .unzip();

    // // Secret toggle list
    let (t_c, t_v): (Vec<_>, Vec<_>) = toggle
        .into_iter()
        .map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng())))
        .unzip();

    // public list of numbers
    let l_v: Vec<LinearCombination> = list.iter().map(|&x| x.into()).collect::<Vec<_>>();

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
        t_v,
        l_v,
    );

    // 4. Make a proof
    let proof = prover.prove()?;

    Ok((proof, commitments, t_c))
}

fn verify(
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
    t_c: Vec<CompressedRistretto>,
    seed: Scalar,
    constants: [Scalar; MIMC_ROUNDS],
    list: Vec<Scalar>,
    q: Scalar,
    z_img: Scalar,
) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::default();
    let mut bp_gens = BulletproofGens::new(2048, 1);

    // Verifier logic

    let mut transcript = Transcript::new(b"BlindBidProofGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let mut vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    let t_c_v: Vec<Variable> = t_c.iter().map(|V| verifier.commit(*V).into()).collect();

    // public list of numbers
    let l_v: Vec<LinearCombination> = list
        .iter()
        .map(|&x| Scalar::from(x).into())
        .collect::<Vec<_>>();

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
        t_c_v,
        l_v,
    );

    // 4. Verify the proof
    verifier
        .verify(&proof)
        .map_err(|_| R1CSError::VerificationError)
}
