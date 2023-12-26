use crate::types::{Zero, R};
use crate::{QI, QU, ZETA};

/// If the condition is not met, return an error message. Borrowed from the `anyhow` crate.
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($msg);
        }
    };
}
pub(crate) use ensure; // make available throughout crate


pub(crate) fn is_in_range(w: &R, lo: u32, hi: u32) -> bool {
    w.iter().all(|&e| (e >= -(lo as i32)) & (e <= (hi as i32)))
}

const M: i128 = 2i128.pow(64) / (QI as i128);

pub(crate) fn reduce_q(a: i64) -> i32 {
    let q = (a as i128 * M) >> 64;
    let res = (a - (q as i64) * (QI as i64)) as i32;
    if res >= QI {
        res - QI
    } else {
        res
    }
}

pub const fn bitlen(a: usize) -> usize { a.ilog2() as usize + 1 }

/// See definition on page 6
/// If α is a positive integer and m ∈ Z or m ∈ `Z_α` , then m mod± α denotes the unique
/// element m′ ∈ Z in the range −α/2 < m′ ≤ α/2 such that m and m′ are congruent
/// modulo α.
pub fn mod_pm(m: i32, a: u32) -> i32 {
    let t = m.rem_euclid(a as i32); // % a;
    let a = a as i32;
    let mp = if t <= (a / 2) { t } else { t - a };
    assert_eq!((mp + a) as u32 % (a as u32), t as u32);

    mp
}

/// HAC Algorithm 14.76 Right-to-left binary exponentiation mod Q.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn pow_mod_q(g: i32, e: u8) -> i32 {
    let g = g as i64;
    let mut result = 1;
    let mut s = g;
    let mut e = e;
    while e != 0 {
        if e & 1 != 0 {
            result = (result * s).rem_euclid(QI as i64);
        };
        e >>= 1;
        if e != 0 {
            s = (s * s).rem_euclid(QU as i64);
        };
    }
    result.rem_euclid(QI as i64) as i32
}


/// Matrix by vector multiplication; See top of page 10, first row: `w_hat` = `A_hat` mul `u_hat`
#[must_use]
pub(crate) fn mat_vec_mul<const K: usize, const L: usize>(
    a_hat: &[[[i32; 256]; L]; K], u_hat: &[[i32; 256]; L],
) -> [[i32; 256]; K] {
    let mut w_hat = [[0i32; 256]; K];
    #[allow(clippy::needless_range_loop)]
    for i in 0..K {
        #[allow(clippy::needless_range_loop)]
        for j in 0..L {
            //let tmp = multiply_ntts(&a_hat[i][j], &u_hat[j]);
            let mut tmp = [0i32; 256];
            tmp.iter_mut().enumerate().for_each(|(m, e)| {
                *e = reduce_q(a_hat[i][j][m] as i64 * u_hat[j][m] as i64) ; //.rem_euclid(QI as i64) as i32;
            });
            for k in 0..256 {
                w_hat[i][k] = (w_hat[i][k] + tmp[k]).rem_euclid(QI);
            }
        }
    }
    w_hat
}

/// Vector addition; See bottom of page 9, second row: `z_hat` = `u_hat` + `v_hat`
#[must_use]
pub(crate) fn vec_add<const K: usize>(vec_a: &[R; K], vec_b: &[R; K]) -> [R; K] {
    let mut result = [R::zero(); K];
    for i in 0..vec_a.len() {
        for j in 0..vec_a[i].len() {
            result[i][j] = (vec_a[i][j] + vec_b[i][j]).rem_euclid(QI);
        }
    }
    result
}


pub fn infinity_norm<const ROW: usize, const COL: usize>(w: &[[i32; COL]; ROW]) -> i32 {
    let mut result = 0;
    #[allow(clippy::needless_range_loop)]
    for i in 0..w.len() {
        let inner = w[i];
        #[allow(clippy::needless_range_loop)]
        for j in 0..inner.len() {
            let z_q = mod_pm(inner[j], QU).abs();
            result = if z_q > result { z_q } else { result };
        }
    }
    result
}



const fn gen_zeta_table() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut i = 0;
    while i < 256 {
        result[i] = pow_mod_q(ZETA, (i as u8).reverse_bits());
        i += 1;
    }
    result
}

pub(crate) static ZETA_TABLE: [i32; 256] = gen_zeta_table();