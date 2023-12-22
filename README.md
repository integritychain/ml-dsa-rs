# [IntegrityChain]: FIPS 204 Module-Lattice-Based Digital Signature Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 203] (Initial Public Draft) Module-Lattice-Based Digital Signature
Standard written in pure Rust for server, desktop, browser and embedded applications.

This library implements the FIPS 204 **draft** standard in pure Rust with minimal and
mainstream dependencies. All three security parameter sets are fully functional. The
code does not require the standard library, e.g. `#[no_std]`, has no heap allocations, 
and exposes the RNG so will be suitable for the full range of applications.
The API is being stabilized and significant performance optimizations are forthcoming.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf> for a full
description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
// Use the desired target parameter set.
use ml_dsa_rs::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87. 
use crate::ml_dsa_rs::traits::{SerDes, Signer, Verifier};

let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate key pair and signature
let (pk1, sk) = ml_dsa_44::key_gen().unwrap();  // Generate both public and secret keys
let sig1 = sk.sign(&message); // Use the secret key to generate message signature

// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig1.into_bytes());
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// Deserialize the public key and signature, then verify
let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk_recv).expect("public key deserialization failed");
let sig2 = ml_dsa_44::Signature::try_from_bytes(sig_recv).expect("signature deserialization failed");
let v = pk2.verify(&msg_recv, &sig2).unwrap(); // Use the public key to verify message signature
assert!(v);
~~~

Rust [Documentation][docs-link]

## Security Notes

This crate is functional and corresponds to the first initial public draft of FIPS 204.
This crate is still under construction/refinement -- USE AT YOUR OWN RISK!

## Supported Parameter Sets

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

## Minimum Supported Rust Version

Rust **1.72** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

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

[FIPS 203]: https://csrc.nist.gov/pubs/fips/204/ipd
