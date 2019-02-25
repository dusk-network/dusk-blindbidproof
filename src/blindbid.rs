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
use rand::thread_rng;

use crate::gadgets::*;
use bulletproofs::r1cs::{LinearCombination, R1CSError, R1CSProof, Variable};
use curve25519_dalek::scalar::Scalar;

use crate::buffer::slice_to_scalar;

const MIMC_ROUNDS: usize = 90;

lazy_static! {
  static ref CONSTANTS: [Scalar; MIMC_ROUNDS] = {
    let mut blinding_rng = rand::thread_rng();
    [Scalar::random(&mut blinding_rng); MIMC_ROUNDS]
  };
}

pub fn prog(
  seed_u8: [u8; 32],
  k_u8: [u8; 32],
  d_u8: [u8; 32],
) -> (Scalar, Scalar, Scalar, Scalar, Scalar) {
  let d = Scalar::from_bytes_mod_order(d_u8);
  let k = Scalar::from_bytes_mod_order(k_u8);
  let seed = Scalar::from_bytes_mod_order(seed_u8);

  let m = mimc_hash(&k, &Scalar::zero());

  let x = mimc_hash(&d, &m);

  let y = mimc_hash(&seed, &x);

  let z = mimc_hash(&seed, &m);

  let y_inv = y.invert();
  let q = d * y_inv;

  (q, x, y, y_inv, z)
}

fn mimc_hash(left: &Scalar, right: &Scalar) -> Scalar {
  let mut x = left.clone();
  let key = right.clone();

  for i in 0..MIMC_ROUNDS {
    let a: Scalar = x + key + CONSTANTS[i];
    let a_2 = a * a;
    let a_3 = a_2 * a;
    let a_4 = a_2 * a_2;
    x = a_3 * a_4;
  }
  x + key
}

pub fn prove(
  d_u8: [u8; 32],
  k_u8: [u8; 32],
  y_u8: [u8; 32],
  y_inv_u8: [u8; 32],
  q_u8: [u8; 32],
  z_img_u8: [u8; 32],
  seed_u8: [u8; 32],
  pub_list_u8: Vec<u8>,
  toggle: usize,
) -> Result<
  (
    R1CSProof,
    Vec<CompressedRistretto>,
    Vec<CompressedRistretto>,
  ),
  R1CSError,
> {
  let d = Scalar::from_bytes_mod_order(d_u8);
  let k = Scalar::from_bytes_mod_order(k_u8);
  let y = Scalar::from_bytes_mod_order(y_u8);
  let y_inv = Scalar::from_bytes_mod_order(y_inv_u8);
  let q = Scalar::from_bytes_mod_order(q_u8);
  let z_img = Scalar::from_bytes_mod_order(z_img_u8);
  let seed = Scalar::from_bytes_mod_order(seed_u8);

  let pub_list: Vec<Scalar> = pub_list_u8.chunks(32).map(slice_to_scalar).collect();

  let pc_gens = PedersenGens::default();
  let bp_gens = BulletproofGens::new(2048, 1);

  let mut transcript = Transcript::new(b"BlindBidProofGadget");

  // 1. Create a prover
  let mut prover = Prover::new(&bp_gens, &pc_gens, &mut transcript);

  // 2. Commit high-level variables
  let mut blinding_rng = rand::thread_rng();

  let (commitments, vars): (Vec<_>, Vec<_>) = [d, k, y, y_inv]
    .into_iter()
    .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
    .unzip();

  let (t_c, t_v): (Vec<_>, Vec<_>) = (0..pub_list.len())
    .map(|x| {
      let scalar = if x == toggle {
        Scalar::one()
      } else {
        Scalar::zero()
      };
      prover.commit(scalar, Scalar::random(&mut thread_rng()))
    })
    .unzip();

  // public list of numbers
  let l_v: Vec<LinearCombination> = pub_list.iter().map(|&x| x.into()).collect::<Vec<_>>();

  // 3. Build a CS
  proof_gadget(
    &mut prover,
    vars[0].into(),
    vars[1].into(),
    vars[3].into(),
    q.into(),
    z_img.into(),
    seed.into(),
    *CONSTANTS,
    t_v,
    l_v,
  );

  // 4. Make a proof
  let proof = prover.prove()?;

  Ok((proof, commitments, t_c))
}

pub fn verify(
  proof_u8: Vec<u8>,
  commitments_u8: Vec<u8>,
  t_c_u8: Vec<u8>,
  seed_u8: [u8; 32],
  pub_list_u8: Vec<u8>,
  q_u8: [u8; 32],
  z_img_u8: [u8; 32],
) -> Result<(), R1CSError> {
  let q = Scalar::from_bytes_mod_order(q_u8);
  let z_img = Scalar::from_bytes_mod_order(z_img_u8);
  let seed = Scalar::from_bytes_mod_order(seed_u8);
  let commitments: Vec<CompressedRistretto> = commitments_u8
    .chunks(32)
    .map(CompressedRistretto::from_slice)
    .collect();
  let t_c: Vec<CompressedRistretto> = t_c_u8
    .chunks(32)
    .map(CompressedRistretto::from_slice)
    .collect();
  let proof = R1CSProof::from_bytes(&proof_u8)?;
  let pub_list: Vec<Scalar> = pub_list_u8.chunks(32).map(slice_to_scalar).collect();

  let pc_gens = PedersenGens::default();
  let bp_gens = BulletproofGens::new(2048, 1);

  // Verifier logic

  let mut transcript = Transcript::new(b"BlindBidProofGadget");

  // 1. Create a verifier
  let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut transcript);

  // 2. Commit high-level variables
  let vars: Vec<_> = commitments.iter().map(|v| verifier.commit(*v)).collect();

  let t_c_v: Vec<Variable> = t_c.iter().map(|v| verifier.commit(*v).into()).collect();

  // public list of numbers
  let l_v: Vec<LinearCombination> = pub_list
    .iter()
    .map(|&x| Scalar::from(x).into())
    .collect::<Vec<_>>();

  // 3. Build a CS
  proof_gadget(
    &mut verifier,
    vars[0].into(),
    vars[1].into(),
    vars[3].into(),
    q.into(),
    z_img.into(),
    seed.into(),
    *CONSTANTS,
    t_c_v,
    l_v,
  );

  // 4. Verify the proof
  verifier
    .verify(&proof)
    .map_err(|_| R1CSError::VerificationError)
}
