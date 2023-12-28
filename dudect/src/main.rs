use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
//use dudect_bencher::rand::{Rng, RngCore};
use ml_dsa_rs::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use ml_dsa_rs::ml_dsa_44::PrivateKey;
use ml_dsa_rs::traits::Signer;

fn sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 100;
    const ITERATIONS_INNER: usize = 10;

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (_pk1, sk1) = ml_dsa_44::try_keygen_vt().unwrap();  // Generate both public and secret keys
    let (_pk2, sk2) = ml_dsa_44::try_keygen_vt().unwrap();  // Generate both public and secret keys

    let mut inputs: Vec<PrivateKey> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(sk1.clone());
        classes.push(Class::Left);
    }

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(sk2.clone());
        classes.push(Class::Right);
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            for _ in 0..ITERATIONS_INNER {
                let _ = input.try_sign_ct(&message);
            }
        })
    }
}

ctbench_main!(sign);

/*
See https://docs.rs/dudect-bencher/latest/dudect_bencher/


running 1 benchmark continuously
bench sign seeded with 0x60428e9d4e18c9a8
...
bench sign ... : n == +0.010M, max t = -1.51648, max tau = -0.01544, (5/tau)^2 = 104839
bench sign ... : n == +0.021M, max t = -1.89577, max tau = -0.01319, (5/tau)^2 = 143637
bench sign ... : n == +0.021M, max t = -1.78355, max tau = -0.01236, (5/tau)^2 = 163775
bench sign ... : n == +0.030M, max t = -1.96031, max tau = -0.01141, (5/tau)^2 = 191974
bench sign ... : n == +0.040M, max t = -2.05464, max tau = -0.01034, (5/tau)^2 = 233960
bench sign ... : n == +0.050M, max t = -2.18394, max tau = -0.00980, (5/tau)^2 = 260158
bench sign ... : n == +0.060M, max t = -1.95796, max tau = -0.00802, (5/tau)^2 = 388668
bench sign ... : n == +0.070M, max t = -1.98743, max tau = -0.00753, (5/tau)^2 = 440910
bench sign ... : n == +0.081M, max t = -1.74250, max tau = -0.00611, (5/tau)^2 = 669133

 */