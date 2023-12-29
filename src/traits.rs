use rand_core::CryptoRngCore;
#[cfg(feature = "default-rng")]
use rand_core::OsRng;


/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// A public key specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PublicKey;
    /// A private (secret) key specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PrivateKey;

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator, and makes no (constant)
    /// timing assurances.
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, SerDes, Signer, Verifier};
    ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_44::KG::try_keygen_vt()?; // Generate both public and secret keys
    /// let sig = sk.try_sign_ct(&message)?; // Use the secret key to generate a message signature
    /// # Ok(())}
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_keygen_vt() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng_vt(&mut OsRng)
    }

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes a supplied random number generator, and makes no (constant)
    /// timing assurances..
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_44::KG::try_keygen_with_rng_vt(&mut rng)?;  // Generate both public and secret keys
    /// let sig = sk.try_sign_ct(&message)?;  // Use the secret key to generate a message signature
    /// # Ok(())}
    /// ```
    fn try_keygen_with_rng_vt(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
}

/// The `PreGen` trait is defined to allow pre-computation of private key material to speed signing.
pub trait PreGen: Signer + SerDes {
    /// A private (secret) precompute specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PreCompute;

    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    /// ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_44::KG::try_keygen_vt()?; // Generate both public and secret keys
    /// let pre = sk.gen_precompute();
    /// let sig = pre.try_sign_ct(&message)?; // Use the secret key to generate a message signature
    /// # Ok(())}
    /// ```
    fn gen_precompute(&self) -> Self::PreCompute;
}


/// The Signer trait is implemented for the `PrivateKey` struct on each of the security parameter sets
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type Signature;

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the default OS RNG and operates in constant time
    /// with respect to the `PrivateKey` only (not including rejection loop; work in progress).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_65; // Could also be ml_dsa_44 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_65::KG::try_keygen_vt()?; // Generate both public and secret keys
    /// let sig = sk.try_sign_ct(&message)?; // Use the secret key to generate a message signature
    /// # Ok(())}
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_sign_ct(&self, message: &[u8]) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng_ct(&mut OsRng, message)
    }

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes a supplied RNG and operates in constant time
    /// with respect to the `PrivateKey` only (not including rejection loop; work in progress).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_65; // Could also be ml_dsa_44 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_65::KG::try_keygen_with_rng_vt(&mut rng)?;  // Generate both public and secret keys
    /// let sig = sk.try_sign_with_rng_ct(&mut rng, &message)?;  // Use the secret key to generate a message signature
    /// # Ok(())}
    /// ```
    fn try_sign_with_rng_ct(
        &self, rng: &mut impl CryptoRngCore, message: &[u8],
    ) -> Result<Self::Signature, &'static str>;
}


/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65
    /// or ml-dsa-87
    type Signature;

    /// Verifies a digital signature with respect to a `PublicKey`. This function operates in
    /// variable time.
    ///
    /// # Errors
    /// Returns an error on a malformed signature; propagates internal errors.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_65; // Could also be ml_dsa_44 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_65::KG::try_keygen_vt()?; // Generate both public and secret keys
    /// let sig = sk.try_sign_ct(&message)?; // Use the secret key to generate a message signature
    /// let v = pk.try_verify_vt(&message, &sig)?; // Use the public to verify message signature
    /// # Ok(())}
    /// ```
    fn try_verify_vt(
        &self, message: &[u8], signature: &Self::Signature,
    ) -> Result<bool, &'static str>;
}

/// The `SerDes` trait provides for validated serialization and deserialization of fixed size elements
pub trait SerDes {
    /// The fixed-size byte array to be serialized or deserialized
    type ByteArray;

    /// Produces a byte array of fixed-size specific to the struct being serialized.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_65; // Could also be ml_dsa_44 or ml_dsa_87.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    ///
    /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_65::KG::try_keygen_vt()?; // Generate both public and secret keys
    /// let sig = sk.try_sign_ct(&message)?; // Use the secret key to generate a message signature
    /// let pk_bytes = pk.into_bytes(); // Serialize the public key
    /// let sk_bytes = sk.into_bytes(); // Serialize the private key
    /// let sig_bytes = sig.into_bytes(); // Serialize the signature
    /// # Ok(())}
    /// ```
    fn into_bytes(self) -> Self::ByteArray;

    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    /// # Errors
    /// Returns an error on malformed input.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use ml_dsa_rs::ml_dsa_87; // Could also be ml_dsa_44 or ml_dsa_65.
    /// use ml_dsa_rs::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
    ///
    /// // Generate key pair and signature
    /// let (pk, sk) = ml_dsa_87::try_keygen_vt()?; // Generate both public and secret keys
    /// let pk_bytes = pk.into_bytes(); // Serialize the public key
    /// let sk_bytes = sk.into_bytes(); // Serialize the private key
    /// let pk2 = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)?;
    /// let sk2 = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)?;
    /// # Ok(())}
    /// ```
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
