#[cfg(test)]
mod tests {
    use crate::encodings::{pk_decode, pk_encode};
    use hex;
    use regex::Regex;
    use std::fs;

    use crate::ml_dsa_65;
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


    #[test]
    fn test_parse() {
        let data = fs::read_to_string("./src/test_vectors/Key Generation -- ML-DSA-65.txt")
            .expect("Unable to read file");

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

        println!("got {:?}", seed);
        //let xx = vec!(seed);
        let mut rnd = MyRng::new();
        rnd.push(&seed);


        let (pk_act, sk_act) = ml_dsa_65::key_gen(&mut rnd);

        assert_eq!(pk_exp, pk_act.to_bytes());
        assert_eq!(sk_exp, sk_act.to_bytes());

        assert_eq!(1, 2, "YAAAAAAAAAAAAAAAAAAAAAAAAY - MADE IT HERE!!!");

        // D=13 K=4 PK_LEN=1312
        let mut random_pk = [0u8; 1312];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 4];
        let (rho, t1) = pk_decode::<4, 1312>(&random_pk).unwrap();
        //let mut res = [0u8; 1312];
        let res = pk_encode::<4, 1312>(&rho, &t1);
        assert_eq!(&random_pk[..], res);
    }
}
