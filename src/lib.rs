//#![cfg_attr(not(test), no_std)]
#![deny(clippy::pedantic)]
#![deny(warnings)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

// To remove...need to drastically rework element+math
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

mod algs;
mod conversion;
mod encodings;
mod hashing;
mod helpers;
mod high_low;
mod ml_dsa;
mod smoke_test;
mod test_vectors;
mod types;

/// Trait documentation here
pub mod traits;

const QI: i32 = 8_380_417; // 2i32.pow(23) - 2i32.pow(13) + 1;
const QU: u32 = QI as u32; // 2u32.pow(23) - 2u32.pow(13) + 1;
const ZETA: i32 = 1753; // See line 906 et al
const D: u32 = 13;


// This common functionality is injected into each parameter set module
macro_rules! functionality {
    () => {
        use crate::ml_dsa;
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use rand_core::CryptoRngCore;
        #[cfg(feature = "default-rng")]
        use rand_core::OsRng;
        use zeroize::{Zeroize, ZeroizeOnDrop};


        // ----- DATA TYPES -----

        /// Correctly sized private/secret key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct PrivateKey([u8; SK_LEN]);


        /// Correctly sized public key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct PublicKey([u8; PK_LEN]);


        /// Correctly sized public key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct Signature([u8; SIG_LEN]);


        /// Empty struct to implement `KeyGen` trait
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct KG(); // Arguable how useful an empty struct+trait is...


        // ----- PRIMARY FUNCTIONS ---

        /// Generates public and private (secret) key pair
        /// Returns an error when the random number generator fails
        /// # Errors
        /// Returns an error when random number generator fails
        pub fn key_gen() -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::key_gen_with_rng(&mut OsRng)
        }


        impl KeyGen for KG {
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;

            /// Docstring here!?!?
            /// # Errors
            /// Returns an error when random number generator fails
            fn key_gen_with_rng(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(PublicKey, PrivateKey), &'static str> {
                let (pk, sk) = ml_dsa::key_gen::<ETA, K, L, PK_LEN, SK_LEN>(rng)?;
                Ok((PublicKey(pk), PrivateKey(sk)))
            }
        }


        impl Signer for PrivateKey {
            type Signature = Signature;

            fn try_sign_with_rng(
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


        impl Verifier for PublicKey {
            type Signature = Signature;

            fn verify(&self, message: &[u8], sig: &Signature) -> Result<bool, &'static str> {
                ml_dsa::verify::<BETA, GAMMA1, GAMMA2, K, L, LAMBDA, OMEGA, PK_LEN, SIG_LEN, TAU>(
                    &self.0, &message, &sig.0,
                )
            }
        }


        // ----- SERIALIZATION AND DESERIALIZATION ---

        impl SerDes for Signature {
            type ByteArray = [u8; SIG_LEN];

            fn try_from_bytes(sig: Self::ByteArray) -> Result<Self, &'static str> {
                if sig[0] == sig[1] {
                    return Err("Signature deserialization failed"); // Placeholder for validation
                }
                Ok(Signature(sig))
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }


        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];

            fn try_from_bytes(pk: Self::ByteArray) -> Result<Self, &'static str> {
                if pk[0] == pk[1] {
                    return Err("PublicKey deserialization failed"); // Placeholder for validation
                }
                Ok(PublicKey(pk))
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }


        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];

            fn try_from_bytes(sk: Self::ByteArray) -> Result<Self, &'static str> {
                if sk[0] == sk[1] {
                    return Err("PrivateKey deserialization failed"); // Placeholder for validation
                }
                Ok(PrivateKey(sk))
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }
    };
}


// Regarding private key sizes, see https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/EKoI0u_PuOw/m/b02zPvomBAAJ

/// ML-DSA-44 documentation here
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

/// ML-DSA-65 documentation here
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


/// ML-DSA-87 documentation here
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
