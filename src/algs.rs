//#![allow(dead_code)]

use crate::types::{Rq, Zero, R, T};
use crate::{QI, QU, ZETA}; // 8: return (r1, r0)

/// HAC Algorithm 14.76 Right-to-left binary exponentiation mod Q.
#[must_use]
pub(crate) fn pow_mod_q(g: i32, e: u8) -> i32 {
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


/// Algorithm 35 NTT(w) on page 36.
/// Computes the Number-Theoretic Transform.
pub(crate) fn ntt(w: &R) -> T {
    // Input: polynomial w(X) = ∑_{j=0}^{255} w_j X^j ∈ Rq
    // Output: w_hat = (w_hat[0], . . . , w_hat[255]) ∈ Tq
    let mut w_hat = R::zero(); // Note: this should be T ... will fix when impl struct

    // 1: for j from 0 to 255 do
    for j in 0..=255 {
        // 2: w_hat[j] ← w_j
        w_hat[j] = w[j];
    } // 3: end for
      // 4: k ← 0
    let mut k = 0;
    // 5: len ← 128
    let mut len = 128;
    // 6: while len ≥ 1 do
    while len >= 1 {
        // 7: start ← 0
        let mut start = 0;
        // 8: while start < 256 do
        while start < 256 {
            // 9: k ← k+1
            k += 1;
            // 10: zeta ← ζ^{brv(k)} mod q
            let zeta = pow_mod_q(ZETA, (k as u8).reverse_bits() >> 1) as i64;
            // 11: for j from start to start + len − 1 do
            for j in start..=(start + len - 1) {
                // 12: t ← zeta · w_hat[ j + len]
                let t = ((zeta * w_hat[j + len] as i64).rem_euclid(QU as i64)) as i32;
                // 13: w_hat[j + len] ← w_hat[j] − t
                w_hat[j + len] = (QU as i32 + w_hat[j] - t).rem_euclid(QI);
                // 14: w_hat[j] ← w_hat[j] + t
                w_hat[j] = (QU as i32 + w_hat[j] + t).rem_euclid(QI);
            } // 15: end for
              // 16: start ← start + 2 · len
            start = start + 2 * len;
        } // 17: end while
          // 18: len ← ⌊len/2⌋
        len = len / 2;
    } // 19: end while
    w_hat // 20: return ŵ
}


/// Algorithm 36 NTT−1 (w_hat) on page 37.
/// Computes the inverse of the Number-Theoretic Transform.
pub(crate) fn inv_ntt(w_hat: &T) -> R {
    // Input: w_hat = (w_hat[0], . . . , w_hat[255]) ∈ Tq
    // Output: polynomial w(X) = ∑_{j=0}^{255} w_j X^j ∈ Rq
    let mut w = R::zero();

    // 1: for j from 0 to 255 do
    for j in 0..=255 {
        // 2: w_j ← w_hat[j]
        w[j] = w_hat[j];
    } // 3: end for
      // 4: k ← 256
    let mut k = 256;
    // 5: len ← 1
    let mut len = 1;
    // 6: while len < 256 do
    while len < 256 {
        // 7: start ← 0
        let mut start = 0;
        // 8: while start < 256 do
        while start < 256 {
            // 9: k ← k−1
            k -= 1;
            // 10: zeta ← −ζ^{brv(k)} mod q
            let zeta = -1 * pow_mod_q(ZETA, (k as u8).reverse_bits()); // TODO: reconfirm interpretation of -1 precedence
                                                                       // 11: for j from start to start + len − 1 do
            for j in start..=(start + len - 1) {
                // 12: t ← w_j
                let t = w[j];
                // 13: w_j ← t + w_{j+len}
                w[j] = (t + w[j + len]).rem_euclid(QI);
                // 14: w_{j+len} ← t − w_{j+len}
                w[j + len] = (QI + t - w[j + len]).rem_euclid(QI);
                // 15: w_{j+len} ← zeta · w_{j+len}
                w[j + len] = ((zeta as i64 * w[j + len] as i64).rem_euclid(QI as i64)) as i32;
            } // 16: end for
              // 17: start ← start + 2 · len
            start += 2 * len;
        } // 18: end while
          // 19: len ← 2 · len
        len *= 2;
    } // 20: end while
      // 21: f ← 8347681          ▷ f = 256^{−1} mod q
    let f = 8347681 as i64; // TODO: recheck type size/boundaries
                            // 22: for j from 0 to 255 do
    for j in 0..=255 {
        // 23: wj ← f ·wj
        w[j] = ((f * w[j] as i64).rem_euclid(QI as i64)) as Rq;
    } // 24: end for
    w // 25: return w
}
