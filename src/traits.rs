// TODO: Review Error scheme
// TODO: Add trait for precompute sk material

use rand_core::CryptoRngCore;
#[cfg(feature = "default-rng")]
use rand_core::OsRng;
//use crate::ml_dsa_44::PrivateKey;


/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// A public key specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PublicKey;
    /// A private (secret) key specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PrivateKey;

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator and operates in variable time.
    /// # Errors
    /// Returns an error when random number generator fails.
    #[cfg(feature = "default-rng")]
    fn try_keygen_vt() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng_vt(&mut OsRng)
    }

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes a supplied random number generator and operates in variable time.
    /// # Errors
    /// Returns an error when random number generator fails.
    fn try_keygen_with_rng_vt(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
}

/// under dev
pub trait PreGen: Signer + SerDes {
    /// stand-in for secret key signer
    type PreCompute;

    /// wogga
    fn gen_precompute(&self) -> Self::PreCompute;
}


/// The Signer trait is implemented for the `PrivateKey` struct on each of the security parameter sets
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type Signature;

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong. This function utilizes the default OS RNG and
    /// operates in constant time with respect to the `PrivateKey` (only; work in progress).
    ///
    /// # Errors
    /// Returns an error when random number generator fails
    #[cfg(feature = "default-rng")]
    fn try_sign_ct(&self, message: &[u8]) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng_ct(&mut OsRng, message)
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong. This function utilizes a supplied RNG and
    /// operates in constant time with respect to the `PrivateKey` (only; work in progress).
    ///
    /// # Errors
    /// Returns an error when random number generator fails
    fn try_sign_with_rng_ct(
        &self, rng: &mut impl CryptoRngCore, message: &[u8],
    ) -> Result<Self::Signature, &'static str>;
}


/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type Signature;

    /// Doc for verify function. This function operates in variable time.
    ///
    /// # Errors
    /// Returns an error on malformed or illegal input
    fn try_verify_vt(
        &self, message: &[u8], signature: &Self::Signature,
    ) -> Result<bool, &'static str>;
}

/// The `SerDes` trait provides for validated serialization and deserialization of fixed size elements
pub trait SerDes {
    /// The fixed-size byte array to be serialized or deserialized
    type ByteArray;

    /// Produces a byte array of fixed-size specific to the struct being serialized.
    #[allow(clippy::wrong_self_convention)]
    fn into_bytes(&self) -> Self::ByteArray;

    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    /// # Errors
    /// Returns an error when random number generator fails
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
