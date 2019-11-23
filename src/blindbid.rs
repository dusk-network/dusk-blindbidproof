use crate::Error;

use std::convert::TryInto;

use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;

use crate::gadgets::*;
use bulletproofs::r1cs::{LinearCombination, R1CSProof, Variable};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha512;

lazy_static! {
    static ref CONSTANTS: Vec<Scalar> = {
        let mut constants: Vec<Scalar> = Vec::with_capacity(90);

        let h = Sha512::digest(b"blind bid");
        let mut hash: [u8; 64] = [0; 64];
        hash.copy_from_slice(h.as_slice());

        for _ in 0..90 {
            let c = Scalar::from_bytes_mod_order_wide(&hash);
            constants.push(c);
            let h = Sha512::digest(&c.to_bytes());
            hash.copy_from_slice(h.as_slice());
        }

        constants
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub proof: R1CSProof,
    pub commitments: Vec<CompressedRistretto>,
    pub t_c: Vec<CompressedRistretto>,
}

impl Proof {
    pub fn new(
        proof: R1CSProof,
        commitments: Vec<CompressedRistretto>,
        t_c: Vec<CompressedRistretto>,
    ) -> Self {
        Proof {
            proof,
            commitments,
            t_c,
        }
    }

    pub fn prove(
        d: Scalar,
        k: Scalar,
        y: Scalar,
        y_inv: Scalar,
        q: Scalar,
        z_img: Scalar,
        seed: Scalar,
        pub_list: Vec<Scalar>,
        toggle: usize,
    ) -> Result<Self, Error> {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2048, 1);

        let mut transcript = Transcript::new(b"BlindBidProofGadget");

        // 1. Create a prover
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // 2. Commit high-level variables
        let mut blinding_rng = rand::thread_rng();

        let (commitments, vars): (Vec<_>, Vec<_>) = [d, k, y, y_inv]
            .iter()
            .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
            .unzip();

        let (t_c, t_v): (Vec<_>, Vec<_>) = (0..pub_list.len())
            .map(|x| {
                prover.commit(
                    Scalar::from((x == toggle) as u8),
                    Scalar::random(&mut thread_rng()),
                )
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
            &CONSTANTS,
            t_v,
            l_v,
        );

        // 4. Make a proof
        let proof = prover.prove(&bp_gens)?;

        Ok(Proof::new(proof, commitments, t_c))
    }

    pub fn verify(
        &self,
        seed: Scalar,
        pub_list: Vec<Scalar>,
        q: Scalar,
        z_img: Scalar,
    ) -> Result<(), Error> {
        let proof = &self.proof;
        let commitments = &self.commitments;
        let t_c = &self.t_c;

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2048, 1);

        // Verifier logic

        let mut transcript = Transcript::new(b"BlindBidProofGadget");

        // 1. Create a verifier
        let mut verifier = Verifier::new(&mut transcript);

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
            &*CONSTANTS,
            t_c_v,
            l_v,
        );

        // 4. Verify the proof
        verifier.verify(&proof, &pc_gens, &bp_gens)?;

        Ok(())
    }
}

impl TryInto<Vec<u8>> for Proof {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        Ok(bincode::serialize(&self)?)
    }
}
