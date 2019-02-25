use libc::{c_uchar, size_t};

use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

fn flatten(points: Vec<CompressedRistretto>) -> Vec<u8> {
  points
    .iter()
    .flat_map(|item| item.to_bytes().to_vec())
    .collect()
}

pub fn slice_to_scalar(slice: &[u8]) -> Scalar {
  let mut raw_digest: [u8; 32] = [0; 32];
  raw_digest.copy_from_slice(&slice);
  Scalar::from_bytes_mod_order(raw_digest)
}

#[repr(C)]
#[derive(Debug)]
pub struct Buffer {
  pub ptr: *mut c_uchar,
  pub len: size_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct ProofBuffer {
  pub proof: Buffer,
  pub commitments: Buffer,
  pub t_c: Buffer,
}

impl Buffer {
  pub fn new(bytes: Vec<c_uchar>) -> Buffer {
    let mut buff = bytes.into_boxed_slice();
    let ptr = buff.as_mut_ptr();
    let len = buff.len();
    std::mem::forget(buff);
    Buffer { ptr, len }
  }

  pub unsafe fn free(&self) {
    let slice = std::slice::from_raw_parts_mut(self.ptr, self.len);
    let ptr = slice.as_mut_ptr();
    Box::from_raw(ptr);
  }
}

impl ProofBuffer {
  pub fn new(
    (proof, commitments, t_c): (
      R1CSProof,
      Vec<CompressedRistretto>,
      Vec<CompressedRistretto>,
    ),
  ) -> ProofBuffer {
    let proof_bytes = proof.to_bytes();
    let commitments_bytes = flatten(commitments);
    let t_c_bytes = flatten(t_c);
    ProofBuffer {
      proof: Buffer::new(proof_bytes),
      commitments: Buffer::new(commitments_bytes),
      t_c: Buffer::new(t_c_bytes),
    }
  }
}
