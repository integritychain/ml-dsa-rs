# [IntegrityChain]: FIPS 204 Module-Lattice-Based Digital Signature Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 204] (Initial Public Draft) Module-Lattice-Based Digital Signature Standard written in pure Rust for server, 
desktop, browser and embedded applications.

This crate implements the FIPS 204 **draft** standard in pure Rust with minimal and mainstream dependencies. All 
three security parameter sets are fully functional. The implementation does not require the standard library, e.g. 
`#[no_std]`, has no heap allocations, e.g. no `alloc` needed, and exposes the `RNG` so it is suitable for the full 
range of applications down to the bare-metal. The API is stabilized and the code is heavily biased towards safety 
and correctness; further performance optimizations will be implemented as the standard matures. This crate will 
quickly follow any changes to FIPS 204 as they become available.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf> for a full description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
// Use the desired target parameter set.
use ml_dsa_rs::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87. 
use ml_dsa_rs::traits::{SerDes, Signer, Verifier};
# use std::error::Error;
#
# fn main() -> Result<(), Box<dyn Error>> {

let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate key pair and signature
let (pk1, sk) = ml_dsa_44::try_keygen_vt()?;  // Generate both public and secret keys
let sig1 = sk.try_sign_ct(&message)?;  // Use the secret key to generate a message signature

// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig1.into_bytes());
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk_recv)?;
let sig2 = ml_dsa_44::Signature::try_from_bytes(sig_recv)?;
let v = pk2.try_verify_vt(&msg_recv, &sig2)?; // Use the public to verify message signature
assert!(v); 
# Ok(())
# }
~~~

The Rust [Documentation][docs-link] lives under each **Module** corresponding to the desired
[security parameter](#modules) below. 

## Notes

* This crate is fully functional and corresponds to the first initial public draft of FIPS 204.    
* Constant-time assurances target the source-code level only, and are a work in progress.
* Note that FIPS 204 places specific requirements on randomness per section 3.5.1, hence the exposed `RNG`.
* Requires Rust **1.72** or higher. The minimum supported Rust version may be changed in the future, but 
it will be done with a minor version bump.
* All on-by-default features of this library are covered by SemVer.
* This software is experimental and still under active development -- USE AT YOUR OWN RISK!

## License

Contents are licensed under either the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as 
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/ml-dsa-rs
[crate-link]: https://crates.io/crates/ml-dsa-rs
[docs-image]: https://docs.rs/ml-dsa-rs/badge.svg
[docs-link]: https://docs.rs/ml-dsa-rs/
[build-image]: https://github.com/integritychain/ml-dsa-rs/workflows/test/badge.svg
[build-link]: https://github.com/integritychain/ml-dsa-rs/actions?query=workflow%3Atest
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.72+-blue.svg

[//]: # (general links)

[IntegrityChain]: https://github.com/integritychain/
[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/ipd
