use criterion::{criterion_group, criterion_main, Criterion};
use ml_dsa_rs::traits::{PreGen, Signer, Verifier};
use ml_dsa_rs::{ml_dsa_44, ml_dsa_65, ml_dsa_87};


pub fn criterion_benchmark(c: &mut Criterion) {
    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (pk44, sk44) = ml_dsa_44::try_keygen_vt().unwrap();
    let precom44 = sk44.gen_precompute();
    let sig44 = sk44.try_sign_ct(&message).unwrap();

    let (pk65, sk65) = ml_dsa_65::try_keygen_vt().unwrap();
    let precom65 = sk65.gen_precompute();
    let sig65 = sk65.try_sign_ct(&message).unwrap();

    let (pk87, sk87) = ml_dsa_87::try_keygen_vt().unwrap();
    let precom87 = sk87.gen_precompute();
    let sig87 = sk87.try_sign_ct(&message).unwrap();


    c.bench_function("ml_dsa_44 keygen", |b| b.iter(|| ml_dsa_44::try_keygen_vt()));
    c.bench_function("ml_dsa_44 sign", |b| b.iter(|| sk44.try_sign_ct(&message)));
    c.bench_function("ml_dsa_44 precom sign", |b| b.iter(|| precom44.try_sign_ct(&message)));
    c.bench_function("ml_dsa 44 verify", |b| b.iter(|| pk44.try_verify_vt(&message, &sig44)));

    c.bench_function("ml_dsa_65 keygen", |b| b.iter(|| ml_dsa_65::try_keygen_vt()));
    c.bench_function("ml_dsa_65 sign", |b| b.iter(|| sk65.try_sign_ct(&message)));
    c.bench_function("ml_dsa_65 precom sign", |b| b.iter(|| precom65.try_sign_ct(&message)));
    c.bench_function("ml_dsa 65 verify", |b| b.iter(|| pk65.try_verify_vt(&message, &sig65)));

    c.bench_function("ml_dsa_87 keygen", |b| b.iter(|| ml_dsa_87::try_keygen_vt()));
    c.bench_function("ml_dsa_87 sign", |b| b.iter(|| sk87.try_sign_ct(&message)));
    c.bench_function("ml_dsa_87 precom sign", |b| b.iter(|| precom87.try_sign_ct(&message)));
    c.bench_function("ml_dsa 87 verify", |b| b.iter(|| pk87.try_verify_vt(&message, &sig87)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);


// Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

// Prior to any optimization
//    ml_dsa_44 keygen        time:   [158.58 µs 158.62 µs 158.66 µs]
//    ml_dsa_65 keygen        time:   [270.23 µs 270.49 µs 270.97 µs]
//    ml_dsa_87 keygen        time:   [388.72 µs 388.85 µs 389.02 µs]
//
//    ml_dsa_44 sign          time:   [1.0791 ms 1.1022 ms 1.1259 ms]
//    ml_dsa_65 sign          time:   [1.7349 ms 1.7702 ms 1.8063 ms]
//    ml_dsa_87 sign          time:   [1.9371 ms 1.9865 ms 2.0369 ms]
//
//    ml_dsa 44 verify        time:   [259.54 µs 260.31 µs 261.33 µs]
//    ml_dsa 65 verify        time:   [436.95 µs 437.18 µs 437.46 µs]
//    ml_dsa 87 verify        time:   [695.26 µs 697.27 µs 701.48 µs]

// As of 12-29-23
//   ml_dsa_44 keygen        time:   [102.44 µs 102.49 µs 102.55 µs]
//   ml_dsa_65 keygen        time:   [191.07 µs 191.10 µs 191.14 µs]
//   ml_dsa_87 keygen        time:   [280.13 µs 280.36 µs 280.65 µs]
//
//   ml_dsa_44 sign          time:   [504.60 µs 512.72 µs 520.84 µs]
//   ml_dsa_65 sign          time:   [854.72 µs 866.98 µs 879.45 µs]
//   ml_dsa_87 sign          time:   [996.97 µs 1.0136 ms 1.0304 ms]
//
//   ml_dsa 44 verify        time:   [164.13 µs 164.18 µs 164.23 µs]
//   ml_dsa 65 verify        time:   [304.44 µs 304.64 µs 304.87 µs]
//   ml_dsa 87 verify        time:   [515.77 µs 516.12 µs 516.52 µs]
