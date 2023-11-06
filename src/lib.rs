use crate::algs::check;

mod algs;


// const Q: u32 = 8380417;
const Q: u32 = 2u32.pow(23) - 2u32.pow(13) + 1;
const D: u32 = 13;

pub mod ml_dsa_44 {
    use super::Q;
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: usize = 2u32.pow(17) as usize;
    const GAMMA2: usize = ((Q - 1) / 88) as usize;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const BETA: usize = TAU * ETA;
    const OMEGA: usize = 80;
}


pub mod ml_dsa_65 {
    use super::Q;
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: usize = 2u32.pow(19) as usize;
    const GAMMA2: usize = ((Q - 1) / 32) as usize;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const BETA: usize = TAU * ETA;
    const OMEGA: usize = 55;
}

pub mod ml_dsa_87 {
    use super::Q;
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: usize = 2u32.pow(19) as usize;
    const GAMMA2: usize = ((Q - 1) / 32) as usize;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const BETA: usize = TAU * ETA;
    const OMEGA: usize = 75;
}


pub fn add(left: usize, right: usize) -> usize {
    check();
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algs::check;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        check();
        assert_eq!(result, 4);
    }
}
