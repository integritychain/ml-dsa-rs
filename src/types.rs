pub(crate) type Tq = i32;
pub(crate) type T = [Tq; 256];

pub(crate) type Rq = i32;
pub(crate) type R = [Rq; 256];
pub(crate) type Rk<const K: usize> = [R; K];
pub(crate) type Rl<const L: usize> = [R; L];
pub(crate) type Rkl<const K: usize, const L: usize> = [[R; K]; L];

pub(crate) type Zq = i32;
