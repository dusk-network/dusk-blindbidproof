mod blindbid;
mod gadgets;

use curve25519_dalek::scalar::Scalar;
use libc::{c_uchar, size_t};
use std::slice;

#[no_mangle]
// DESTROY ALL SENSITIVE DATA
pub unsafe extern "C" fn prover(
    d_ptr: *const [c_uchar; 32],
    k_ptr: *const [c_uchar; 32],
    y_ptr: *const [c_uchar; 32],
    y_inv_ptr: *const [c_uchar; 32],
    q_ptr: *const [c_uchar; 32],
    z_img_ptr: *const [c_uchar; 32],
    seed_ptr: *const [c_uchar; 32],
    pub_list_ptr: *const c_uchar,
    pub_list_len: size_t, // constants: [Scalar; MIMC_ROUNDS], -- These will be generated in Rust
                          // toggle: &[u64]
) {
    let pub_list: Vec<c_uchar> = slice::from_raw_parts(pub_list_ptr, pub_list_len).to_vec();
    blindbid::prover(
        *d_ptr, *k_ptr, *y_ptr, *y_inv_ptr, *q_ptr, *z_img_ptr, *seed_ptr, pub_list,
    );
}
