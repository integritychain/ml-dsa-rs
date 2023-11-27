// Note: R/T will soon be a struct tuple, and default will be implemented
pub(crate) trait Zero {
    fn zero() -> Self;
}

pub(crate) type Rq = i32;
pub(crate) type R = [Rq; 256];

impl Zero for R {
    fn zero() -> Self { [0i32; 256] }
}


pub(crate) type Tq = i32;
pub(crate) type T = [Tq; 256];

// impl Zero for T {
//     fn zero() -> Self {
//         [0i32; 256]
//     }
// }


pub(crate) type Zq = i32;
