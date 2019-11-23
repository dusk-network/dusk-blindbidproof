use super::{generate_cs_transcript, Proof, CONSTANTS};
use crate::gadgets::proof_gadget;
use crate::Error;

use std::io::Read;

use bulletproofs::r1cs::Verifier;
use bulletproofs::r1cs::{LinearCombination, R1CSProof, Variable};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use dusk_tlv::TlvReader;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verify {
    pub proof: R1CSProof,
    pub commitments: Vec<CompressedRistretto>,
    pub t_c: Vec<CompressedRistretto>,
    pub q: Scalar,
    pub z_img: Scalar,
    pub seed: Scalar,
    pub pub_list: Vec<Scalar>,
}

impl Verify {
    pub fn new(
        proof: R1CSProof,
        commitments: Vec<CompressedRistretto>,
        t_c: Vec<CompressedRistretto>,
        q: Scalar,
        z_img: Scalar,
        seed: Scalar,
        pub_list: Vec<Scalar>,
    ) -> Self {
        Verify {
            proof,
            commitments,
            t_c,
            q,
            z_img,
            seed,
            pub_list,
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        let (pc_gens, bp_gens, mut transcript) = generate_cs_transcript();

        // 1. Create a verifier
        let mut verifier = Verifier::new(&mut transcript);

        // 2. Commit high-level variables
        let vars: Vec<_> = self
            .commitments
            .iter()
            .map(|v| verifier.commit(*v))
            .collect();

        let t_c_v: Vec<Variable> = self
            .t_c
            .iter()
            .map(|v| verifier.commit(*v).into())
            .collect();

        // public list of numbers
        let l_v: Vec<LinearCombination> = self
            .pub_list
            .iter()
            .map(|&x| Scalar::from(x).into())
            .collect::<Vec<_>>();

        // 3. Build a CS
        proof_gadget(
            &mut verifier,
            vars[0].into(),
            vars[1].into(),
            vars[3].into(),
            self.q.into(),
            self.z_img.into(),
            self.seed.into(),
            &*CONSTANTS,
            t_c_v,
            l_v,
        );

        // 4. Verify the proof
        Ok(verifier.verify(&self.proof, &pc_gens, &bp_gens)?)
    }

    pub fn try_from_reader_variables<R: Read>(mut reader: R) -> Result<Self, Error> {
        let proof = Proof::try_from_reader_variables(&mut reader)?;
        let (proof, commitments, t_c) = (proof.proof, proof.commitments, proof.t_c);

        let mut reader = TlvReader::new(&mut reader);

        let q: Scalar =
            bincode::deserialize(reader.next().ok_or(Error::UnexpectedEof)??.as_slice())?;
        let z_img: Scalar =
            bincode::deserialize(reader.next().ok_or(Error::UnexpectedEof)??.as_slice())?;
        let seed: Scalar =
            bincode::deserialize(reader.next().ok_or(Error::UnexpectedEof)??.as_slice())?;

        let mut pub_list = vec![];
        for bytes in reader.read_list::<Vec<u8>>()? {
            pub_list.push(bincode::deserialize::<Scalar>(bytes.as_slice())?);
        }

        Ok(Verify::new(
            proof,
            commitments,
            t_c,
            q,
            z_img,
            seed,
            pub_list,
        ))
    }
}
