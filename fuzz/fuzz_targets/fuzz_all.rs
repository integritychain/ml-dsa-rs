#![no_main]
// rustup default nightly
// head -c 2560 </dev/urandom > seed1
// cargo fuzz run fuzz_all -j 4

use libfuzzer_sys::fuzz_target;
use ml_dsa_rs::ml_dsa_44;
use ml_dsa_rs::traits::{SerDes, Signer, Verifier};

fuzz_target!(|data: [u8; 2560]| {  // re-use the same data across deserializers below

    // Deserialize a 'fuzzy' secret key
    let sk = ml_dsa_44::PrivateKey::try_from_bytes(data);

    // Sign -- a decent (?) proportion of sk will deserialize OK
    if let Ok(sk) = sk {
        let _sig = sk.try_sign_ct(&[0u8, 1, 2, 3]);
    }


    // Deserialize a 'fuzzy' signature
    let sig = ml_dsa_44::Signature::try_from_bytes(data[0..2420].try_into().unwrap());

    // Signature -- a decent (?) proportion of sig will deserialize OK
    if let Ok(sig) = sig {
        let (pk, _) = ml_dsa_44::try_keygen_vt().unwrap();
        let _v = pk.try_verify_vt(&[0u8, 1, 2, 3], &sig);
    }


    // Deserialize a 'fuzzy' public key
    let pk = ml_dsa_44::PublicKey::try_from_bytes(data[0..1312].try_into().unwrap());

    // Verify -- a decent (?) proportion of pk will deserialize OK
    if let Ok(pk) = pk {
        let (_, sk) = ml_dsa_44::try_keygen_vt().unwrap();
        let sig2 = sk.try_sign_ct(&[0u8, 1, 2, 3]).unwrap();
        let _v = pk.try_verify_vt(&[0u8, 1, 2, 3], &sig2);
    }
});
