// This file implements a variety of top-level tests, including: official vectors, random
// round trips, and (soon) fails.

use hex::decode;
use ml_dsa_rs::traits::{KeyGen, SerDes, Signer, Verifier};
use ml_dsa_rs::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use rand_core::{CryptoRng, RngCore};
use regex::Regex;
use std::fs;


// ----- CUSTOM RNG TO REPLAY VALUES -----

struct MyRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for MyRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let x = self.data.pop().expect("test rng problem");
        out.copy_from_slice(&x)
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(self.fill_bytes(out))
    }
}

impl CryptoRng for MyRng {}

impl MyRng {
    fn new() -> Self { MyRng { data: Vec::new() } }

    fn push(&mut self, new_data: &[u8]) {
        let x = new_data.to_vec();
        self.data.push(x);
    }
}


// ----- EXTRACT I/O VALUES FROM OFFICIAL VECTORS -----

fn get_keygen_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let seed_regex = Regex::new(r"seed: ([0-9a-fA-F]+)").unwrap();
    let seed = decode(seed_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let pk_regex = Regex::new(r"pk: ([0-9a-fA-F]+)").unwrap();
    let pk_exp = decode(pk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let sk_regex = Regex::new(r"sk: ([0-9a-fA-F]+)").unwrap();
    let sk_exp = decode(sk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    (seed, pk_exp, sk_exp)
}

fn get_sign_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let msg_regex = Regex::new(r"message: ([0-9a-fA-F]+)").unwrap();
    let msg = decode(msg_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let sk_regex = Regex::new(r"sk: ([0-9a-fA-F]+)").unwrap();
    let sk = decode(sk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let rnd_regex = Regex::new(r"rnd: ([0-9a-fA-F]+)").unwrap();
    let rnd = decode(rnd_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let sig_regex = Regex::new(r"signature: ([0-9a-fA-F]+)").unwrap();
    let sig = decode(sig_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    (msg, sk, rnd, sig)
}

fn get_verify_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let msg_regex = Regex::new(r"message: ([0-9a-fA-F]+)").unwrap();
    let msg = decode(msg_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let pk_regex = Regex::new(r"pk: ([0-9a-fA-F]+)").unwrap();
    let pk = decode(pk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let sig_regex = Regex::new(r"signature: ([0-9a-fA-F]+)").unwrap();
    let sig = decode(sig_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    (pk, msg, sig)
}


// ----- TEST KEYGEN, SIGN AND VERIFY

#[test]
fn test_keygen() {
    let (seed, pk_exp, sk_exp) =
        get_keygen_vec("./tests/test_vectors/Key Generation -- ML-DSA-44.txt");
    let mut rnd = MyRng::new();
    rnd.push(&seed);
    let (pk_act, sk_act) = ml_dsa_44::KG::try_keygen_with_rng_vt(&mut rnd).unwrap();
    assert_eq!(pk_exp, pk_act.into_bytes());
    assert_eq!(sk_exp, sk_act.into_bytes());

    let (seed, pk_exp, sk_exp) =
        get_keygen_vec("./tests/test_vectors/Key Generation -- ML-DSA-65.txt");
    let mut rnd = MyRng::new();
    rnd.push(&seed);
    let (pk_act, sk_act) = ml_dsa_65::KG::try_keygen_with_rng_vt(&mut rnd).unwrap();
    assert_eq!(pk_exp, pk_act.into_bytes());
    assert_eq!(sk_exp, sk_act.into_bytes());

    let (seed, pk_exp, sk_exp) =
        get_keygen_vec("./tests/test_vectors/Key Generation -- ML-DSA-87.txt");
    let mut rnd = MyRng::new();
    rnd.push(&seed);
    let (pk_act, sk_act) = ml_dsa_87::KG::try_keygen_with_rng_vt(&mut rnd).unwrap();
    assert_eq!(pk_exp, pk_act.into_bytes());
    assert_eq!(sk_exp, sk_act.into_bytes());
}


#[test]
fn test_sign() {
    let (msg, sk, seed, sig_exp) =
        get_sign_vec("./tests/test_vectors/Signature Generation -- ML-DSA-44.txt");
    let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
    let mut rnd = MyRng::new();
    rnd.push(&seed);
    let sig_act = sk.try_sign_with_rng_ct(&mut rnd, &msg);
    assert_eq!(sig_exp, sig_act.unwrap().into_bytes());

    let (msg, sk, seed, sig_exp) =
        get_sign_vec("./tests/test_vectors/Signature Generation -- ML-DSA-65.txt");
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
    let mut rnd = MyRng::new();
    rnd.push(&seed);
    let sig_act = sk.try_sign_with_rng_ct(&mut rnd, &msg);
    assert_eq!(sig_exp, sig_act.unwrap().into_bytes());

    let (msg, sk, seed, sig_exp) =
        get_sign_vec("./tests/test_vectors/Signature Generation -- ML-DSA-87.txt");
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
    let mut rnd = MyRng::new();
    rnd.push(&seed);
    let sig_act = sk.try_sign_with_rng_ct(&mut rnd, &msg);
    assert_eq!(sig_exp, sig_act.unwrap().into_bytes());
}


#[test]
fn test_verify() {
    let (pk, msg, sig) =
        get_verify_vec("./tests/test_vectors/Signature Verification -- ML-DSA-44.txt");
    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk.try_into().unwrap()).unwrap();
    let sig = ml_dsa_44::Signature::try_from_bytes(sig.try_into().unwrap()).unwrap();
    let pass = pk.try_verify_vt(&msg, &sig);
    assert!(pass.unwrap());

    let (pk, message, sig) =
        get_verify_vec("./tests/test_vectors/Signature Verification -- ML-DSA-65.txt");
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk.try_into().unwrap()).unwrap();
    let sig = ml_dsa_65::Signature::try_from_bytes(sig.try_into().unwrap()).unwrap();
    let pass = pk.try_verify_vt(&message, &sig);
    assert!(pass.unwrap());

    let (pk, message, sig) =
        get_verify_vec("./tests/test_vectors/Signature Verification -- ML-DSA-87.txt");
    let pk = ml_dsa_87::PublicKey::try_from_bytes(pk.try_into().unwrap()).unwrap();
    let sig = ml_dsa_87::Signature::try_from_bytes(sig.try_into().unwrap()).unwrap();
    let pass = pk.try_verify_vt(&message, &sig);
    assert!(pass.unwrap());
}
