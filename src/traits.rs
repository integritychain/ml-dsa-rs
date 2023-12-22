// TODO: Review Error scheme
// TODO: Add trait for precompute sk material

use rand_core::CryptoRngCore;
#[cfg(feature = "default-rng")]
use rand_core::OsRng;


/// The `KeyGen` trait doc...
pub trait KeyGen {
    /// A public key specific to the chosen security parameter set, e.g., ml-dsa-44
    type PublicKey;
    /// A private (secret) key specific to the chosen security parameter set, e.g., ml-dsa-44m ml-dsa-65 or ml-dsa-87
    type PrivateKey;

    /// Get the verifying key which can verify signatures produced by the
    /// signing key portion of this keypair.
    /// # Errors
    /// Returns an error when random number generator fails
    fn key_gen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
}


/// The Signer trait is implemented for `PrivateKey` on each of the security parameter sets
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44m ml-dsa-65 or ml-dsa-87
    type Signature;

    /// Sign the given message and return a digital signature
    #[cfg(feature = "default-rng")]
    #[must_use]
    fn sign(&self, message: &[u8]) -> Self::Signature {
        self.try_sign(message).expect("signature operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    /// # Errors
    /// Returns an error when random number generator fails
    #[cfg(feature = "default-rng")]
    fn try_sign(&self, message: &[u8]) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut OsRng, message)
    }

    /// Sign the given message and return a digital signature
    #[must_use]
    fn sign_with_rng(&self, rng: &mut impl CryptoRngCore, message: &[u8]) -> Self::Signature {
        self.try_sign_with_rng(rng, message)
            .expect("signature operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    /// # Errors
    /// Returns an error when random number generator fails
    fn try_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, message: &[u8],
    ) -> Result<Self::Signature, &'static str>;
}


/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44m ml-dsa-65 or ml-dsa-87
    type Signature;

    /// Doc for verify function
    /// # Errors
    /// Returns an error when random number generator fails
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<bool, &'static str>;
}

/// The `SerDes` trait provides for validated serialization and deserialization of fixed size elements
pub trait SerDes {
    /// The fixed-size byte array to be serialized or deserialized
    type ByteArray;

    /// Produces a byte array of fixed-size specific to the struct being serialized.
    fn into_bytes(self) -> Self::ByteArray;
    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    /// # Errors
    /// Returns an error when random number generator fails
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
