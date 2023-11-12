#[cfg(test)]
mod tests {
    use crate::ml_dsa_44;

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
    fn test1() {
        let mut rnd = MyRng::new();
        rnd.push(&[0u8; 32]);
        rnd.push(&[0u8; 32]);
        let (_pk, sk) = ml_dsa_44::key_gen(&mut rnd);
        let sig = sk.sign(&mut rnd, b"12345678");
    }
}
