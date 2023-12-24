use crate::helpers::mod_pm;
use crate::types::Zq;
use crate::{D, QI, QU};


// This file implements functionality from FIPS 204 section 8.4 High Order / Low Order Bits and Hints


/// Algorithm 29 Power2Round(r) on page 34.
/// Decomposes r into (r1, r0) such that r ≡ r1*2^d + r0 mod q.
pub(crate) fn power2round(r: Zq) -> (Zq, Zq) {
    // Input: r ∈ Zq.
    // Output: Integers (r1, r0).

    // 1: r+ ← r mod q
    let rp = r.rem_euclid(QU as i32); // % (QU as i32);

    // 2: r0 ← r+ mod±2^d
    let r0 = mod_pm(rp, 2_u32.pow(D));
    //
    // 3: return ((r+ − r0)/2^d, r0)
    let r1 = (rp - r0) / 2_i32.pow(D);
    (r1, r0)
}


/// Algorithm 30 Decompose(r) on page 34.
/// Decomposes r into (r1, r0) such that r ≡ r1(2γ2) + r0 mod q.
pub(crate) fn decompose<const GAMMA2: usize>(r: Zq, r1: &mut Zq, r0: &mut Zq) {
    // Input: r ∈ Zq
    // Output: Integers (r1, r0).

    // 1: r+ ← r mod q
    let rp = r.rem_euclid(QI);

    // 2: r0 ← r+ mod±(2γ_2)
    *r0 = mod_pm(rp, 2 * GAMMA2 as u32);

    // 3: if r+ − r0 = q − 1 then
    if (rp - *r0) == (QU as i32 - 1) {
        // 4: r1 ← 0
        *r1 = 0;
        // 5: r0 ← r0 − 1
        *r0 -= 1;
    } else {
        // 6: else r_1 ← (r+ − r0)/(2γ2)
        *r1 = (rp - *r0) / (2 * GAMMA2 as i32);
    } // 7: end if
}


/// Algorithm 31 HighBits(r) on page 34.
/// Returns r1 from the output of Decompose (r)
pub(crate) fn high_bits<const GAMMA2: usize>(r: Zq) -> Zq {
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
pub(crate) fn low_bits<const GAMMA2: usize>(r: Zq) -> Zq {
    // Input: r ∈ Zq
    // Output: Integer r0.

    // 1: (r1, r0) ← Decompose(r)
    let (mut r1, mut r0) = (0, 0);
    decompose::<GAMMA2>(r, &mut r1, &mut r0);

    // 2: return r0
    r0
}


/// Algorithm 33 MakeHint(z, r) on page 35.
/// Compute hint bit indicating whether adding z to r alters the high bits of r.
pub(crate) fn make_hint<const GAMMA2: usize>(z: Zq, r: Zq) -> bool {
    // Input: z, r ∈ Zq
    // Output: Boolean

    // 1: r1 ← HighBits(r)
    let r1 = high_bits::<GAMMA2>(r);

    // 2: v1 ← HighBits(r + z)
    let v1 = high_bits::<GAMMA2>((r + z).rem_euclid(QI));

    // 3: return [[r1 != v1]]
    r1 != v1
}


/// Algorithm 34 UseHint(h, r) on page 35.
/// Returns the high bits of r adjusted according to hint h
pub(crate) fn use_hint<const GAMMA2: usize>(h: Zq, r: Zq) -> Zq {
    // Input:boolean h, r ∈ Zq
    // Output: r1 ∈ Z with 0 ≤ r1 ≤ (q − 1)/(2*γ_2)

    // 1: m ← (q− 1)/(2*γ_2)
    let m = (QU - 1) / (2 * GAMMA2 as u32);

    // 2: (r1, r0) ← Decompose(r)
    let (mut r1, mut r0) = (0, 0);
    decompose::<GAMMA2>(r, &mut r1, &mut r0);

    // 3: if h = 1 and r0 > 0 return (r1 + 1) mod m
    if (h == 1) & (r0 > 0) {
        return (r1 + 1).rem_euclid(m as i32);
    }

    // 4: if h = 1 and r0 ≤ 0 return (r1 − 1) mod m
    if (h == 1) & (r0 <= 0) {
        return (r1 - 1).rem_euclid(m as i32);
    }

    // 5: return r1
    r1
}
