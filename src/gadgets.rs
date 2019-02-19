#![feature(test)]
extern crate bulletproofs;
extern crate core;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate subtle;
use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::{thread_rng, Rng};

use std::time::{Duration, Instant};

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError, R1CSProof, Variable};
use curve25519_dalek::scalar::Scalar;

pub const MIMC_ROUNDS: usize = 90;

pub fn proof_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    d: LinearCombination,
    k: LinearCombination,
    y: LinearCombination,
    y_inv: LinearCombination,
    q: LinearCombination,
    z_img: LinearCombination,
    seed: LinearCombination,
    constants: [Scalar; MIMC_ROUNDS],
    toggle: Vec<Variable>, // private: binary list indicating private number is somewhere in list
    items: Vec<LinearCombination>, // public list
) {
    // Prove z
    let m = mimc_gadget(cs, k, Scalar::from(0 as u8).into(), constants);

    let x = mimc_gadget(cs, d.clone(), m.clone(), constants);

    one_of_many_gadget(cs, x.clone(), toggle, items);

    let y = mimc_gadget(cs, seed.clone(), x, constants);

    let z = mimc_gadget(cs, seed, m, constants);

    cs.constrain(z_img - z);

    // Prove Q
    score_gadget(cs, d, y, y_inv, q);
}

// N.B. the constrain on the image has been removed, as we will not know the intermediate images
fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: LinearCombination,
    right: LinearCombination,
    constants: [Scalar; MIMC_ROUNDS],
) -> LinearCombination {
    assert_eq!(MIMC_ROUNDS, constants.len());

    let mut x = left.clone();
    let mut key = right.clone();

    for i in 0..MIMC_ROUNDS {
        // x + k + c[i]
        let a = x + key.clone() + constants[i];

        // (a)^2
        let (_, _, a_2) = cs.multiply(a.clone(), a.clone());

        // (a)^3
        let (_, _, a_3) = cs.multiply(a_2.clone().into(), a.clone().into());

        // (a)^4
        let (_, _, a_4) = cs.multiply(a_2.clone().into(), a_2.clone().into());

        // (a)^7
        let (_, _, a_7) = cs.multiply(a_4.into(), a_3.into());

        x = a_7.into();
    }

    x + key
}

fn score_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    d: LinearCombination,
    y: LinearCombination,
    y_inv: LinearCombination,
    q: LinearCombination,
) {
    let one = Scalar::from(1 as u8);

    // check that Yinv * Y = 1
    let (_, _, one_var) = cs.multiply(y, y_inv.clone());
    cs.constrain(one_var - one);

    // Q = F(d,Y)
    let (_, _, q_var) = cs.multiply(d, y_inv);
    cs.constrain(q - q_var);
}

fn one_of_many_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: LinearCombination,          // private: our item x
    toggle: Vec<Variable>,         // private: binary list indicating it is somewhere in list
    items: Vec<LinearCombination>, // public list
) {
    let toggle_len = toggle.len();

    // ensure every item in toggle is binary
    for i in toggle.iter() {
        boolean_gadget(cs, i.clone().into());
    }

    // toggle_sum[i] = toggle_sum(i-1) + toggle(i)
    let mut toggle_sum: Vec<LinearCombination> = Vec::with_capacity(toggle_len);
    toggle_sum.push(toggle[0].clone().into());
    for i in 1..toggle_len {
        let prev_toggle_sum = toggle_sum[i - 1].clone();
        let curr_toggle = toggle[i].clone();

        toggle_sum.push(prev_toggle_sum + (curr_toggle.clone()));
    }

    // ensure sum of toggles = 1
    for i in 1..toggle_len {
        let prev_toggle_sum = toggle_sum[i - 1].clone();
        let curr_toggle = toggle[i].clone();
        let curr_toggle_sum = toggle_sum[i].clone();

        toggle_sum[i] = toggle_sum[i - 1].clone() + (toggle[i].clone());

        cs.constrain(prev_toggle_sum + (curr_toggle) - (curr_toggle_sum));
    }
    let one: Scalar = Scalar::from(1 as u8);
    let last_item = toggle_sum[toggle_len - 1].clone();
    cs.constrain(last_item - one);

    // now check if item is in list
    // item[i] * toggle[i] = toggle[i] * our item (x)
    for i in 0..toggle_len {
        let (_, _, left) = cs.multiply(items[i].clone(), toggle[i].clone().into());
        let (_, _, right) = cs.multiply(toggle[i].clone().into(), x.clone());
        cs.constrain(left - right);
    }
}

fn boolean_gadget<CS: ConstraintSystem>(cs: &mut CS, a1: LinearCombination) {
    // a *(1-a) = 0
    let a = a1.clone();
    let one: LinearCombination = Scalar::from(1 as u8).into();
    let (_, _, c_var) = cs.multiply(a, one - a1);
    cs.constrain(c_var.into());
}
