mod blindbid;
mod buffer;
mod gadgets;

use libc::c_uchar;
use std::slice;

use crate::buffer::{Buffer, ProofBuffer};


#[no_mangle]
// DESTROY ALL SENSITIVE DATA
pub unsafe extern "C" fn prove(
    d_ptr: *const [c_uchar; 32],
    k_ptr: *const [c_uchar; 32],
    y_ptr: *const [c_uchar; 32],
    y_inv_ptr: *const [c_uchar; 32],
    q_ptr: *const [c_uchar; 32],
    z_img_ptr: *const [c_uchar; 32],
    seed_ptr: *const [c_uchar; 32],
    pub_list: *mut Buffer,
    constants:*mut Buffer,
    toggle: usize,
) -> *mut ProofBuffer {

    let pub_list: Vec<c_uchar> = slice::from_raw_parts((*pub_list).ptr, (*pub_list).len).to_vec();
    let constants: Vec<c_uchar>= slice::from_raw_parts((*constants).ptr, (*constants).len).to_vec();

    match blindbid::prove(
        *d_ptr, *k_ptr, *y_ptr, *y_inv_ptr, *q_ptr, *z_img_ptr, *seed_ptr, pub_list,constants, toggle,
    ) {
        Ok(result) => {
            let buff = ProofBuffer::new(result);
            Box::into_raw(Box::new(buff))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn verify(
    buff: *mut ProofBuffer,
    seed_ptr: *const [c_uchar; 32],
    pub_list: *mut Buffer,
    q_ptr: *const [c_uchar; 32],
    z_img_ptr: *const [c_uchar; 32],
    constants: *mut Buffer,
) -> bool {
    let pub_list: Vec<c_uchar> = slice::from_raw_parts((*pub_list).ptr, (*pub_list).len).to_vec();
    let constants = slice::from_raw_parts((*constants).ptr, (*constants).len).to_vec();
    let proof: Vec<c_uchar> = slice::from_raw_parts((*buff).proof.ptr, (*buff).proof.len).to_vec();
    let commitments: Vec<c_uchar> =
        slice::from_raw_parts((*buff).commitments.ptr, (*buff).commitments.len).to_vec();
    let t_c: Vec<c_uchar> = slice::from_raw_parts((*buff).t_c.ptr, (*buff).t_c.len).to_vec();

    match blindbid::verify(
        proof,
        commitments,
        t_c,
        *seed_ptr,
        pub_list,
        *q_ptr,
        *z_img_ptr,
        constants,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dealloc_proof(buff: *mut ProofBuffer) {
    (*buff).proof.free();
    (*buff).commitments.free();
    (*buff).t_c.free();
    Box::from_raw(buff);
}
