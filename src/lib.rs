mod blindbid;
mod buffer;
mod gadgets;

use libc::c_uchar;
use std::slice;

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
    pub_list_buff: *mut buffer::Buffer,
    constants_buff: *mut buffer::Buffer,
    toggle: usize,
) -> *mut buffer::Buffer {
    let pub_list: Vec<c_uchar> =
        slice::from_raw_parts((*pub_list_buff).ptr, (*pub_list_buff).len).to_vec();
    let constants: Vec<c_uchar> =
        slice::from_raw_parts((*constants_buff).ptr, (*constants_buff).len).to_vec();

    match blindbid::prove(
        *d_ptr, *k_ptr, *y_ptr, *y_inv_ptr, *q_ptr, *z_img_ptr, *seed_ptr, pub_list, constants,
        toggle,
    ) {
        Ok((proof, commitments, t_c)) => {
            let proof_bytes = proof.to_bytes();
            let commitments_bytes = buffer::flatten(commitments);
            let t_c_bytes = buffer::flatten(t_c);

            let mut bytes: Vec<u8> = Vec::new();

            bytes.extend_from_slice(&mut buffer::len(&proof_bytes));
            bytes.extend(&proof_bytes);

            bytes.extend_from_slice(&mut buffer::len(&commitments_bytes));
            bytes.extend(&commitments_bytes);

            bytes.extend_from_slice(&mut buffer::len(&t_c_bytes));
            bytes.extend(&t_c_bytes);

            Box::into_raw(Box::new(buffer::Buffer::new(bytes)))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn verify(
    buff: *mut buffer::Buffer,
    seed_ptr: *const [c_uchar; 32],
    pub_list_buff: *mut buffer::Buffer,
    q_ptr: *const [c_uchar; 32],
    z_img_ptr: *const [c_uchar; 32],
    constants_buff: *mut buffer::Buffer,
) -> bool {
    let buff_list = slice::from_raw_parts((*buff).ptr, (*buff).len);
    let proof_len = buffer::to_u32(&buff_list[..4]) as usize;
    let commitments_len = buffer::to_u32(&buff_list[proof_len + 4..proof_len + 4 + 4]) as usize;

    let proof = &buff_list[4..4 + proof_len].to_vec();
    let commitments = &buff_list[proof_len + 4 + 4..proof_len + 4 + 4 + commitments_len].to_vec();
    let t_c = &buff_list[proof_len + 4 + 4 + commitments_len + 4..].to_vec();

    let pub_list: Vec<c_uchar> =
        slice::from_raw_parts((*pub_list_buff).ptr, (*pub_list_buff).len).to_vec();
    let constants: Vec<c_uchar> =
        slice::from_raw_parts((*constants_buff).ptr, (*constants_buff).len).to_vec();

    match blindbid::verify(
        &proof,
        &commitments,
        &t_c,
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
