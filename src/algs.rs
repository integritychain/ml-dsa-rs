//#![allow(dead_code)]

use crate::types::{Rk, Rkl, Rl, Rq, Zq, R, T};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256; // 12: return c

//use sha3::digest::{ExtendableOutput, Update, XofReader};
use crate::{conversion, D, QI, QU, ZETA};
use sha3::Shake128;
//use sha3::digest::{ExtendableOutput, Update, XofReader};
//use crate::helpers::bitlen;
// 6: return A ˆ
// 7: return (s1, s2)
// 7: return s


/// Algorithm 29 Power2Round(r) on page 34.
/// Decomposes r into (r1, r0) such that r ≡ r1*2^d + r0 mod q.
pub(crate) fn power2round(r: Zq, r1: &mut Zq, r0: &mut Zq) {
    // Input: r ∈ Zq.
    // Output: Integers (r1, r0).
    // 1: r+ ← r mod q
    let rp = r.rem_euclid(QU as i32); // % (QU as i32);  // TODO euclid rem
                                      // 2: r0 ← r+ mod±2^d
    let x1 = rp & (2i32.pow(D) - 1);
    *r0 = if x1 < 2i32.pow(D - 1) {
        x1
    } else {
        (x1 - 2i32.pow(D - 1)).rem_euclid(QI) // % QI
    };
    // 3: return ((r+ − r0)/2^d, r0)
    *r1 = (rp - *r0) / 2_i32.pow(D);
}

/// Algorithm 30 Decompose(r) on page 34.
/// Decomposes r into (r1, r0) such that r ≡ r1(2γ2) + r0 mod q.
pub(crate) fn decompose<const GAMMA2: u32>(r: &Zq, r1: &mut Zq, r0: &mut Zq) {
    // Input: r ∈ Zq
    // Output: Integers (r1, r0).
    // 1: r+ ← r mod q
    let rp = r.rem_euclid(QI);
    // 2: r0 ← r+ mod±(2γ_2)
    let x1 = rp.rem_euclid(2 * GAMMA2 as i32);
    *r0 = if x1 <= (GAMMA2) as i32 {
        x1
    } else {
        2 * GAMMA2 as i32 - x1
    };
    // 3: if r+ − r0 = q − 1 then
    if (rp - *r0) == (QU as i32 - 1) {
        // 4: r1 ← 0
        *r1 = 0;
        // 5: r0 ← r0 − 1
        *r0 = *r0 - 1;
    } else {
        // 6: else r_1 ← (r+ − r0)/(2γ2)
        *r1 = (rp - *r0) / (2 * GAMMA2 as i32);
    } // 7: end if
} // 8: return (r1, r0)


/// Algorithm 31 HighBits(r) on page 34.
/// Returns r1 from the output of Decompose (r)
pub(crate) fn high_bits<const GAMMA2: u32>(r: &Zq) -> Zq {
    // Input: r ∈ Zq
    // Output: Integer r1.
    // 1: (r1, r0) ← Decompose(r)
    let (mut r1, mut r0) = (0, 0);
    decompose::<GAMMA2>(r, &mut r1, &mut r0);
    // 2: return r1
    r1
}


/// Algorithm 32 LowBits(r) on page 35
/// Returns r0 from the output of Decompose (r)
pub(crate) fn low_bits<const GAMMA2: u32>(r: Zq) -> Zq {
    // Input: r ∈ Zq
    // Output: Integer r0.
    // 1: (r1, r0) ← Decompose(r)
    let (mut r1, mut r0) = (0, 0);
    decompose::<GAMMA2>(&r, &mut r1, &mut r0);
    // 2: return r0
    r0
}

/// Algorithm 33 MakeHint(z, r) on page 35.
/// Compute hint bit indicating whether adding z to r alters the high bits of r.
pub(crate) fn make_hint<const GAMMA2: u32>(z: Zq, r: Zq) -> bool {
    // Input: z, r ∈ Zq
    // Output: Boolean
    // 1: r1 ← HighBits(r)
    let r1 = high_bits::<GAMMA2>(&r);
    // 2: v1 ← HighBits(r + z)
    let v1 = high_bits::<GAMMA2>(&(r + z));
    // 3: return [[r1 = v1]]
    r1 == v1
}


/// Algorithm 34 UseHint(h, r) on page 35.
/// Returns the high bits of r adjusted according to hint h
pub(crate) fn use_hit<const GAMMA2: u32>(h: bool, r: Zq) -> Zq {
    // Input:boolean h, r ∈ Zq
    // Output: r1 ∈ Z with 0 ≤ r1 ≤ (q − 1)/(2*γ_2)
    // 1: m ← (q− 1)/(2*γ_2)
    let m = (QU - 1) / (2 * GAMMA2);
    // 2: (r1, r0) ← Decompose(r)
    let (mut r1, mut r0) = (0, 0);
    decompose::<GAMMA2>(&r, &mut r1, &mut r0);
    // 3: if h = 1 and r0 > 0 return (r1 + 1) mod m
    if h & (r0 > 0) {
        return (r1 + 1).rem_euclid(m as i32);
    }
    // 4: if h = 1 and r0 ≤ 0 return (r1 − 1) mod m
    if h & (r0 <= 0) {
        return (r1 - 1).rem_euclid(m as i32);
    }
    // 5: return r1
    r1
}

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
pub(crate) fn ntt(w: &R, w_hat: &mut T) {
    // Input: polynomial w(X) = ∑_{j=0}^{255} w_j X^j ∈ Rq
    // Output: w_hat = (w_hat[0], . . . , w_hat[255]) ∈ Tq
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
} // 20: return ŵ


/// Algorithm 36 NTT−1 (w_hat) on page 37.
/// Computes the inverse of the Number-Theoretic Transform.
pub(crate) fn inv_ntt(w_hat: &T, w: &mut R) {
    // Input: w_hat = (w_hat[0], . . . , w_hat[255]) ∈ Tq
    // Output: polynomial w(X) = ∑_{j=0}^{255} w_j X^j ∈ Rq
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
} // 25: return w
