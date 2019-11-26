use super::{generate_cs_transcript, CONSTANTS};
use crate::gadgets::proof_gadget;
use crate::Error;

use std::convert::TryInto;
use std::io::{Read, Write};

use bulletproofs::r1cs::Prover;
use bulletproofs::r1cs::{LinearCombination, R1CSProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use dusk_tlv::{TlvReader, TlvWriter};
use rand::thread_rng;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
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
        toggle: u64,
    ) -> Result<Self, Error> {
        let (pc_gens, bp_gens, mut transcript) = generate_cs_transcript();

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
                    Scalar::from((x as u64 == toggle) as u8),
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

    /// Perform the deserialization of a request.
    ///
    /// Currently the recommended method from TlvReaderis read_list instead of standard list
    /// deserialization
    pub fn try_from_reader_variables<R: Read>(reader: R) -> Result<Self, Error> {
        let mut reader = TlvReader::new(reader);

        let d = Deserialize::deserialize(&mut reader)?;
        let k = Deserialize::deserialize(&mut reader)?;
        let y = Deserialize::deserialize(&mut reader)?;
        let y_inv = Deserialize::deserialize(&mut reader)?;
        let q = Deserialize::deserialize(&mut reader)?;
        let z_img = Deserialize::deserialize(&mut reader)?;
        let seed = Deserialize::deserialize(&mut reader)?;

        let mut pub_list = vec![];
        for bytes in reader.read_list::<Vec<u8>>()? {
            pub_list.push(bincode::deserialize::<Scalar>(bytes.as_slice())?);
        }

        let toggle = Deserialize::deserialize(&mut reader)?;

        Proof::prove(d, k, y, y_inv, q, z_img, seed, pub_list, toggle)
    }
}

impl TryInto<Vec<u8>> for Proof {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let buf = vec![];
        let mut buf = TlvWriter::new(buf);

        buf.write(self.proof.to_bytes().as_slice())?;
        buf.write_list(
            self.commitments
                .iter()
                .map(|c| c.to_bytes()[..].to_vec())
                .collect::<Vec<Vec<u8>>>()
                .as_slice(),
        )?;
        buf.write_list(
            self.t_c
                .iter()
                .map(|c| c.to_bytes()[..].to_vec())
                .collect::<Vec<Vec<u8>>>()
                .as_slice(),
        )?;

        Ok(buf.into_inner())
    }
}
