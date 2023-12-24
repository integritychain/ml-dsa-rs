use ml_dsa_rs::traits::{KeyGen, Signer, Verifier};
use ml_dsa_rs::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use rand_chacha::rand_core::SeedableRng;

#[test]
fn test_44_rounds() {
    let mut msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    for i in 0..256 {
        msg[0] = i as u8;
        let (pk, sk) = ml_dsa_44::KG::try_keygen_with_rng(&mut rng).unwrap();
        let sig = sk.try_sign(&msg).unwrap();
        let ver = pk.try_verify(&msg, &sig);
        assert!(ver.unwrap())
    }
}

#[test]
fn test_65_rounds() {
    let mut msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(456);
    for i in 0..256 {
        msg[0] = i as u8;
        let (pk, sk) = ml_dsa_65::KG::try_keygen_with_rng(&mut rng).unwrap();
        let sig = sk.try_sign(&msg).unwrap();
        let ver = pk.try_verify(&msg, &sig);
        assert!(ver.unwrap())
    }
}

#[test]
fn test_87_rounds() {
    let mut msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(789);
    for i in 0..256 {
        msg[0] = i as u8;
        let (pk, sk) = ml_dsa_87::KG::try_keygen_with_rng(&mut rng).unwrap();
        let sig = sk.try_sign(&msg).unwrap();
        let ver = pk.try_verify(&msg, &sig);
        assert!(ver.unwrap())
    }
}
