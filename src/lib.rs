mod blindbid;
mod gadgets;

use curve25519_dalek::scalar::Scalar;
use std::slice::from_raw_parts;

const scalar_len: usize = 32;

#[no_mangle]
// DESTROY ALL SENSITIVE DATA
pub unsafe extern "C" fn prover(
    d_ptr: *const u8,
    k_ptr: *const u8,
    y_ptr: *const u8,
    y_inv_ptr: *const u8,
    q_ptr: *const u8,
    z_img_ptr: *const u8,
    seed_ptr: *const u8,
    pub_list_ptr: *const u8,
    pub_list_len: libc::size_t,
    // constants: [Scalar; MIMC_ROUNDS], -- These will be generated in Rust
    // toggle: &[u64],
) {
    let d_bytes = from_raw_parts(d_ptr, scalar_len);
    let k_bytes = from_raw_parts(k_ptr, scalar_len);
    let y_bytes = from_raw_parts(y_ptr, scalar_len);
    let y_inv_bytes = from_raw_parts(y_inv_ptr, scalar_len);
    let q_bytes = from_raw_parts(q_ptr, scalar_len);
    let z_img__bytes = from_raw_parts(z_img_ptr, scalar_len);
    let seed_bytes = from_raw_parts(seed_ptr, scalar_len);

    let d = slice_to_scalar(d_bytes);
    let k = slice_to_scalar(k_bytes);
    let y = slice_to_scalar(k_bytes);
    let y_inv = slice_to_scalar(k_bytes);
    let q = slice_to_scalar(k_bytes);
    let z_img = slice_to_scalar(k_bytes);
    let seed = slice_to_scalar(k_bytes);

    let pub_list: Vec<Scalar> = from_raw_parts(pub_list_ptr, pub_list_len)
        .iter()
        .step_by(scalar_len)
        .map(|item| {
            let slice = from_raw_parts(item, scalar_len);
            slice_to_scalar(slice)
        })
        .collect();

        println!("d {:?}", d);
        println!("pub_list: {:?}", pub_list);
}

pub fn slice_to_scalar(slice: &[u8]) -> Scalar {
    let mut raw_digest: [u8; 32] = [0; 32];
    raw_digest.copy_from_slice(&slice);
    Scalar::from_bytes_mod_order(raw_digest)
}
