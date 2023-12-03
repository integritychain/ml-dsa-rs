mod algs;
mod conversion;
mod encodings;
mod hashing;
mod helpers;
mod high_low;
mod ml_dsa;
mod smoke_test;
mod types;

// const Q: u32 = 8380417;
const QU: u32 = 2u32.pow(23) - 2u32.pow(13) + 1;
const QI: i32 = 2i32.pow(23) - 2i32.pow(13) + 1;
const ZETA: i32 = 1753; // See line 906 et al
const D: u32 = 13;

// This common functionality is injected into each parameter set module
macro_rules! functionality {
    () => {
        use crate::ml_dsa;
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};


        /// Correctly sized private/secret key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct PrivateKey([u8; SK_LEN]);

        /// Correctly sized public key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct PublicKey([u8; PK_LEN]);

        impl PublicKey {
            pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<bool, &'static str> {
                ml_dsa::verify::<BETA, GAMMA1, GAMMA2, K, L, LAMBDA, OMEGA, PK_LEN, SIG_LEN, TAU>(
                    &self.0, &message, &sig.0,
                )
            }
        }

        /// Correctly sized public key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct Signature([u8; SIG_LEN]);

        impl PrivateKey {
            pub fn sign(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Signature, &'static str> {
                let sig = ml_dsa::sign::<
                    BETA,
                    ETA,
                    GAMMA1,
                    GAMMA2,
                    K,
                    L,
                    LAMBDA,
                    OMEGA,
                    SIG_LEN,
                    SK_LEN,
                    TAU,
                >(rng, &self.0, message)?;
                Ok(Signature(sig))
            }
        }

        #[must_use]
        pub fn key_gen(rng: &mut impl CryptoRngCore) -> (PublicKey, PrivateKey) {
            let (pk, sk) = ml_dsa::key_gen::<ETA, K, L, PK_LEN, SK_LEN>(rng);
            (PublicKey(pk), PrivateKey(sk))
        }
    };
}

// Regarding private key sizes, see https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/EKoI0u_PuOw/m/b02zPvomBAAJ

pub mod ml_dsa_44 {
    use super::QU;
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: usize = 2u32.pow(17) as usize;
    const GAMMA2: usize = (QU as usize - 1) / 88;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const BETA: u32 = (TAU * ETA) as u32;
    const OMEGA: usize = 80;
    const SK_LEN: usize = 2560;
    const PK_LEN: usize = 1312;
    const SIG_LEN: usize = 2420;

    functionality!();
}


pub mod ml_dsa_65 {
    use super::QU;
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: usize = 2u32.pow(19) as usize;
    const GAMMA2: usize = (QU as usize - 1) / 32;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const BETA: u32 = (TAU * ETA) as u32;
    const OMEGA: usize = 55;
    const SK_LEN: usize = 4032;
    const PK_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;

    functionality!();
}

pub mod ml_dsa_87 {
    use super::QU;
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: usize = 2u32.pow(19) as usize;
    const GAMMA2: usize = (QU as usize - 1) / 32;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const BETA: u32 = (TAU * ETA) as u32;
    const OMEGA: usize = 75;
    const SK_LEN: usize = 4896;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;

    functionality!();
}
