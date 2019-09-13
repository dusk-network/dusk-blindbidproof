use libc::{c_uchar, size_t};

use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use std::slice;

#[repr(transparent)]
#[derive(Debug)]
pub struct Bytes(pub Vec<u8>);

#[repr(transparent)]
#[derive(Debug)]
pub struct Bytes32([u8; 32]);

#[repr(C)]
#[derive(Debug)]
pub struct BytesArray(Bytes);

#[repr(C)]
#[derive(Debug)]
pub struct FatPtr {
    pub ptr: *mut c_uchar,
    pub len: size_t,
}

impl From<Scalar> for Bytes32 {
    fn from(item: Scalar) -> Bytes32 {
        Bytes32(item.to_bytes())
    }
}

impl<'a> From<&'a [u8]> for Bytes32 {
    fn from(item: &'a [u8]) -> Bytes32 {
        let mut raw: [u8; 32] = [0; 32];
        raw.copy_from_slice(&item);
        Bytes32(raw)
    }
}

impl From<Bytes32> for Scalar {
    fn from(item: Bytes32) -> Scalar {
        Scalar::from_bytes_mod_order(item.0)
    }
}

impl<'a> From<&'a Bytes32> for Scalar {
    fn from(item: &'a Bytes32) -> Scalar {
        Scalar::from_bytes_mod_order(item.0)
    }
}

impl<'a> From<&'a FatPtr> for &'a [u8] {
    fn from(item: &'a FatPtr) -> &'a [u8] {
        unsafe { slice::from_raw_parts(item.ptr, item.len) }
    }
}

impl<'a> From<FatPtr> for &'a [u8] {
    fn from(item: FatPtr) -> &'a [u8] {
        unsafe { slice::from_raw_parts(item.ptr, item.len) }
    }
}

impl<'a> From<&'a FatPtr> for Vec<Scalar> {
    fn from(item: &'a FatPtr) -> Vec<Scalar> {
        let s: &[u8] = item.into();
        s.chunks(32).map(|x| Bytes32::from(x).into()).collect()
    }
}

impl Bytes {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<CompressedRistretto>> for Bytes {
    fn from(item: Vec<CompressedRistretto>) -> Bytes {
        Bytes(
            item.iter()
                .flat_map(|item| item.to_bytes().to_vec())
                .collect(),
        )
    }
}

impl From<Bytes> for Vec<CompressedRistretto> {
    fn from(item: Bytes) -> Vec<CompressedRistretto> {
        item.0
            .chunks(32)
            .map(CompressedRistretto::from_slice)
            .collect()
    }
}

impl From<Bytes> for Vec<Scalar> {
    fn from(item: Bytes) -> Vec<Scalar> {
        item.0
            .chunks(32)
            .map(|x| {
                let mut raw: [u8; 32] = [0; 32];
                raw.copy_from_slice(x);
                Scalar::from_bytes_mod_order(raw)
            })
            .collect()
    }
}

impl From<R1CSProof> for Bytes {
    fn from(item: R1CSProof) -> Bytes {
        Bytes(item.to_bytes())
    }
}

impl From<Bytes> for R1CSProof {
    fn from(item: Bytes) -> R1CSProof {
        R1CSProof::from_bytes(&item.0).unwrap()
    }
}

impl From<Bytes> for FatPtr {
    fn from(item: Bytes) -> FatPtr {
        let mut buff = item.0.into_boxed_slice();
        let ptr = buff.as_mut_ptr();
        let len = buff.len();
        std::mem::forget(buff);

        FatPtr { ptr, len }
    }
}

// le
fn len(slice: &[u8]) -> [u8; 4] {
    let x = slice.len();
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    [b4, b3, b2, b1]
}

// le
fn to_u32(x: &[u8]) -> u32 {
    let b1: u32 = (x[3] as u32) << 24;
    let b2: u32 = (x[2] as u32) << 16;
    let b3: u32 = (x[1] as u32) << 8;
    let b4: u32 = x[0] as u32;
    b1 + b2 + b3 + b4
}

impl BytesArray {
    pub fn new() -> Self {
        BytesArray(Bytes(Vec::new()))
    }
    pub fn push(&mut self, bytes: Bytes) {
        let v = &mut (&mut self.0).0;
        v.extend_from_slice(&len(&bytes.0));
        v.extend(bytes.0)
    }
}

impl<'a> From<BytesArray> for Vec<u8> {
    fn from(item: BytesArray) -> Vec<u8> {
        (item.0).0
    }
}
impl From<BytesArray> for FatPtr {
    fn from(item: BytesArray) -> FatPtr {
        item.0.into()
    }
}

impl From<FatPtr> for BytesArray {
    fn from(item: FatPtr) -> BytesArray {
        let s: &[u8] = item.into();
        BytesArray(Bytes(s.to_vec()))
    }
}

impl<'a> From<&'a FatPtr> for BytesArray {
    fn from(item: &'a FatPtr) -> BytesArray {
        let s: &[u8] = item.into();
        BytesArray(Bytes(s.to_vec()))
    }
}

impl<'a> From<&'a [u8]> for BytesArray {
    fn from(item: &'a [u8]) -> BytesArray {
        BytesArray(Bytes(item.to_vec()))
    }
}

impl From<Bytes> for Scalar {
    fn from(item: Bytes) -> Scalar {
        let mut raw: [u8; 32] = [0; 32];
        raw.copy_from_slice(&item.0);
        Scalar::from_bytes_mod_order(raw)
    }
}

impl From<Bytes> for BytesArray {
    fn from(item: Bytes) -> BytesArray {
        BytesArray(item)
    }
}

impl IntoIterator for BytesArray {
    type Item = Bytes;
    type IntoIter = BytesArrayIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        BytesArrayIntoIterator {
            array: self,
            index: 0,
        }
    }
}

pub struct BytesArrayIntoIterator {
    array: BytesArray,
    index: usize,
}

impl Iterator for BytesArrayIntoIterator {
    type Item = Bytes;
    fn next(&mut self) -> Option<Bytes> {
        if self.index >= self.array.0.len() {
            return None;
        }
        let bytes = &(self.array.0).0;

        let len = to_u32(&bytes[self.index..self.index + 4]) as usize;
        self.index += 4;
        let bytes = &bytes[self.index..self.index + len];
        self.index += len;
        Some(Bytes(bytes.to_vec()))
    }
}
