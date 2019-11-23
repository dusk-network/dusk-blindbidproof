use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
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

pub use proof::Proof;
pub use verify::Verify;

mod proof;
mod verify;

pub fn generate_cs_transcript() -> (PedersenGens, BulletproofGens, Transcript) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2048, 1);
    let transcript = Transcript::new(b"BlindBidProofGadget");

    (pc_gens, bp_gens, transcript)
}
