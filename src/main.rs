extern crate bulletproofs;
extern crate core;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate subtle;

use rand::{thread_rng, Rng};

use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

use std::time::{Duration, Instant};

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError, Variable};
use curve25519_dalek::scalar::Scalar;

const MIMC_ROUNDS: usize = 90;

fn main() {
    for i in 0..5 {
          let mut blinding_rng = rand::thread_rng();

    let constants = [Scalar::random(&mut blinding_rng); MIMC_ROUNDS];

    let k = Scalar::random(&mut blinding_rng);
    let d = Scalar::random(&mut blinding_rng);

    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let seed_rs = Scalar::from_bytes_mod_order(seed);

    let (q, x,y, y_inv, z) = prog(seed_rs, k, d, &constants);

    let bp_gens = BulletproofGens::new(2048, 1);

    let items = vec![
        Scalar::from(1u64),
        Scalar::from(2u64),
        x,
        Scalar::from(100u64),
        Scalar::from(100u64),
        Scalar::from(100u64),
        Scalar::from(200u64), // 300, 400, 400, 500, 600, 700, 800, 900, 2000, 400, 1u64,
                              // 2, 10, 100, 100, 100, 200, 300, 400, 400, 500, 600, 700, 800, 900, 2000, 400, 1u64, 2, 10,
                              // 100, 100, 100, 200, 300, 400, 400, 500, 600, 700, 800, 900, 2000, 400, 1u64, 2, 10, 100,
                              // 100, 100, 200, 300, 400, 400, 500, 600, 700, 800, 900, 2000, 400, 0, 0, 0, 0, 0, 0, 0, 0,
                              // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    let toggle = [
        0u64, 0, 1, 0, 0, 0,
        0, // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           // 0, 0, 0, 0, 0, 0, 0u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0u64, 0, 0, 0, 0,
           // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let mut total_proving = Duration::new(0, 0);
    let now = Instant::now();

    println!(
        "{:#?}",
        proof_gadget_roundtrip_helper(
            bp_gens, d, k, y, y_inv, q, z, seed_rs, constants, items, &toggle
        )
    );

    let elapsed = now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1000_000_000.0);
    println!("Seconds: {}", sec);
    }
}

fn prog(
    seed: Scalar,
    k: Scalar,
    d: Scalar,
    constants: &[Scalar],
) -> (Scalar, Scalar, Scalar, Scalar,Scalar) {
    let m = mimc_hash(&k, &Scalar::from(0 as u8), constants);

    let x = mimc_hash(&d, &m, constants);

    let y = mimc_hash(&seed, &x, constants);

    let z = mimc_hash(&seed, &m, constants);

    let y_inv = y.invert();
    let q = d * y_inv;

    (q, x,y, y_inv, z)
}

fn proof_gadget<CS: ConstraintSystem>(
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

fn mimc_hash(left: &Scalar, right: &Scalar, constants: &[Scalar]) -> Scalar {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    let mut x = left.clone();
    let key = right.clone();

    for i in 0..MIMC_ROUNDS {
        let a: Scalar = x + key + constants[i];
        let a_2 = a * a;
        let a_3 = a_2 * a;
        let a_4 = a_2 * a_2;
        x = a_3 * a_4;
    }
    x + key
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

fn proof_gadget_roundtrip_helper(
    bp_gens: BulletproofGens,
    d: Scalar,
    k: Scalar,
    y: Scalar,
    y_inv: Scalar,
    q: Scalar,
    z_img: Scalar,
    seed: Scalar,
    constants: [Scalar; MIMC_ROUNDS],
    list: Vec<Scalar>,
    toggle: &[u64],
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();

    // Prover's scope
    let (proof, commitments, t_c) = {
        let mut transcript = Transcript::new(b"BlindBidProofGadget");

        // 1. Create a prover
        let mut prover = Prover::new(&bp_gens, &pc_gens, &mut transcript);

        // 2. Commit high-level variables
        let mut blinding_rng = rand::thread_rng();

        let (commitments, mut vars): (Vec<_>, Vec<_>) = [d, k, y, y_inv]
            .into_iter()
            .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
            .unzip();

        // // Secret toggle list
        let (t_c, t_v): (Vec<_>, Vec<_>) = toggle
            .into_iter()
            .map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng())))
            .unzip();

        // public list of numbers
        let l_v: Vec<LinearCombination> = list.iter().map(|&x| x.into()).collect::<Vec<_>>();

        // 3. Build a CS
        proof_gadget(
            &mut prover,
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
            q.into(),
            z_img.into(),
            seed.into(),
            constants.clone(),
            t_v,
            l_v,
        );

        // 4. Make a proof
        let proof = prover.prove()?;

        (proof, commitments, t_c)
    };

    let mut total_proving = Duration::new(0, 0);
    let now = Instant::now();

    // Verifier logic

    let mut transcript = Transcript::new(b"BlindBidProofGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let mut vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    let t_c_v: Vec<Variable> = t_c.iter().map(|V| verifier.commit(*V).into()).collect();

    // public list of numbers
    let l_v: Vec<LinearCombination> = list
        .iter()
        .map(|&x| Scalar::from(x).into())
        .collect::<Vec<_>>();

    // 3. Build a CS
    proof_gadget(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        q.into(),
        z_img.into(),
        seed.into(),
        constants.clone(),
        t_c_v,
        l_v,
    );

    // 4. Verify the proof
    verifier
        .verify(&proof)
        .map_err(|_| R1CSError::VerificationError)
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
