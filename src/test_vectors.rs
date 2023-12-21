#[cfg(test)]
mod tests {
    use crate::encodings::{pk_decode, pk_encode};
    use hex;
    use regex::Regex;
    use std::fs;

    use crate::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
    use rand_core::{CryptoRng, RngCore};

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

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            unimplemented!()
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

    fn get_keygen_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let data = fs::read_to_string(filename).expect("Unable to read file");

        let seed_regex = Regex::new(r"seed: ([0-9a-fA-F]+)").unwrap();
        let seed = hex::decode(
            seed_regex
                .captures(&data)
                .expect("expected seed")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();
        let pk_regex = Regex::new(r"pk: ([0-9a-fA-F]+)").unwrap();
        let pk_exp = hex::decode(
            pk_regex
                .captures(&data)
                .expect("expected pk")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();
        let sk_regex = Regex::new(r"sk: ([0-9a-fA-F]+)").unwrap();
        let sk_exp = hex::decode(
            sk_regex
                .captures(&data)
                .expect("expected sk")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();
        (seed, pk_exp, sk_exp)
    }

    #[test]
    fn test_keygen() {
        let (seed, pk_exp, sk_exp) =
            get_keygen_vec("./src/test_vectors/Key Generation -- ML-DSA-44.txt");
        let mut rnd = MyRng::new();
        rnd.push(&seed);
        let (pk_act, sk_act) = ml_dsa_44::key_gen(&mut rnd);
        assert_eq!(pk_exp, pk_act.to_bytes());
        assert_eq!(sk_exp, sk_act.to_bytes());

        let (seed, pk_exp, sk_exp) =
            get_keygen_vec("./src/test_vectors/Key Generation -- ML-DSA-65.txt");
        let mut rnd = MyRng::new();
        rnd.push(&seed);
        let (pk_act, sk_act) = ml_dsa_65::key_gen(&mut rnd);
        assert_eq!(pk_exp, pk_act.to_bytes());
        assert_eq!(sk_exp, sk_act.to_bytes());

        let (seed, pk_exp, sk_exp) =
            get_keygen_vec("./src/test_vectors/Key Generation -- ML-DSA-87.txt");
        let mut rnd = MyRng::new();
        rnd.push(&seed);
        let (pk_act, sk_act) = ml_dsa_87::key_gen(&mut rnd);
        assert_eq!(pk_exp, pk_act.to_bytes());
        assert_eq!(sk_exp, sk_act.to_bytes());
    }

    fn get_sign_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let data = fs::read_to_string(filename).expect("Unable to read file");

        let msg_regex = Regex::new(r"message: ([0-9a-fA-F]+)").unwrap();
        let msg = hex::decode(
            msg_regex
                .captures(&data)
                .expect("expected message")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();

        let sk_regex = Regex::new(r"sk: ([0-9a-fA-F]+)").unwrap();
        let sk = hex::decode(
            sk_regex
                .captures(&data)
                .expect("expected sk")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();


        let rnd_regex = Regex::new(r"rnd: ([0-9a-fA-F]+)").unwrap();
        let rnd = hex::decode(
            rnd_regex
                .captures(&data)
                .expect("expected rnd")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();

        let sig_regex = Regex::new(r"signature: ([0-9a-fA-F]+)").unwrap();
        let sig = hex::decode(
            sig_regex
                .captures(&data)
                .expect("expected sig")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();


        (msg, sk, rnd, sig)
    }

    #[test]
    fn test_sign() {
        let (message, sk, seed, sig_exp) =
            get_sign_vec("./src/test_vectors/Signature Generation -- ML-DSA-44.txt");
        let sk = ml_dsa_44::PrivateKey::from_bytes(&sk.try_into().unwrap());
        let mut rnd = MyRng::new();
        rnd.push(&seed);
        let sig_act = sk.sign(&mut rnd, &message);
        assert_eq!(sig_exp, sig_act.unwrap().to_bytes());

        let (message, sk, seed, sig_exp) =
            get_sign_vec("./src/test_vectors/Signature Generation -- ML-DSA-65.txt");
        let sk = ml_dsa_65::PrivateKey::from_bytes(&sk.try_into().unwrap());
        let mut rnd = MyRng::new();
        rnd.push(&seed);
        let sig_act = sk.sign(&mut rnd, &message);
        assert_eq!(sig_exp, sig_act.unwrap().to_bytes());

        let (message, sk, seed, sig_exp) =
            get_sign_vec("./src/test_vectors/Signature Generation -- ML-DSA-87.txt");
        let sk = ml_dsa_87::PrivateKey::from_bytes(&sk.try_into().unwrap());
        let mut rnd = MyRng::new();
        rnd.push(&seed);
        let sig_act = sk.sign(&mut rnd, &message);
        assert_eq!(sig_exp, sig_act.unwrap().to_bytes());
    }

    fn get_verify_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let data = fs::read_to_string(filename).expect("Unable to read file");

        let msg_regex = Regex::new(r"message: ([0-9a-fA-F]+)").unwrap();
        let msg = hex::decode(
            msg_regex
                .captures(&data)
                .expect("expected message")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();

        let pk_regex = Regex::new(r"pk: ([0-9a-fA-F]+)").unwrap();
        let pk = hex::decode(
            pk_regex
                .captures(&data)
                .expect("expected pk")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();

        let sig_regex = Regex::new(r"signature: ([0-9a-fA-F]+)").unwrap();
        let sig = hex::decode(
            sig_regex
                .captures(&data)
                .expect("expected sig")
                .get(1)
                .unwrap()
                .as_str(),
        )
        .unwrap();

        (pk, msg, sig)
    }


    #[test]
    fn test_verify() {
        let (pk, message, signature) =
            get_verify_vec("./src/test_vectors/Signature Verification -- ML-DSA-44.txt");
        let pk = ml_dsa_44::PublicKey::from_bytes(&pk.try_into().unwrap());
        let signature = ml_dsa_44::Signature::from_bytes(&signature.try_into().unwrap());
        let pass = pk.verify(&message, &signature);
        assert!(pass.unwrap());

        let (pk, message, signature) =
            get_verify_vec("./src/test_vectors/Signature Verification -- ML-DSA-65.txt");
        let pk = ml_dsa_65::PublicKey::from_bytes(&pk.try_into().unwrap());
        let signature = ml_dsa_65::Signature::from_bytes(&signature.try_into().unwrap());
        let pass = pk.verify(&message, &signature);
        assert!(pass.unwrap());

        let (pk, message, signature) =
            get_verify_vec("./src/test_vectors/Signature Verification -- ML-DSA-87.txt");
        let pk = ml_dsa_87::PublicKey::from_bytes(&pk.try_into().unwrap());
        let signature = ml_dsa_87::Signature::from_bytes(&signature.try_into().unwrap());
        let pass = pk.verify(&message, &signature);
        assert!(pass.unwrap());
    }
}
