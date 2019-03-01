use libc::{c_uchar, size_t};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

pub fn flatten(points: Vec<CompressedRistretto>) -> Vec<u8> {
  points
    .iter()
    .flat_map(|item| item.to_bytes().to_vec())
    .collect()
}

// be
pub fn len(slice: &[u8]) -> [u8; 4] {
  let x = slice.len();
  let b1: u8 = ((x >> 24) & 0xff) as u8;
  let b2: u8 = ((x >> 16) & 0xff) as u8;
  let b3: u8 = ((x >> 8) & 0xff) as u8;
  let b4: u8 = (x & 0xff) as u8;
  [b1, b2, b3, b4]
}

// be
pub fn to_u32(x: &[u8]) -> u32 {
  let b1: u32 = (x[0] as u32) << 24;
  let b2: u32 = (x[1] as u32) << 16;
  let b3: u32 = (x[2] as u32) << 8;
  let b4: u32 = x[3] as u32;
  b1 + b2 + b3 + b4
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
