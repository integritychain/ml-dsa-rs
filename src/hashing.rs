use crate::conversion;
use crate::helpers::bitlen;
use crate::types::{Zero, R, T};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

// This file implements functionality from FIPS 204 section 8.3 Hashing and Pseudorandom Sampling


/// Function H(v, d) of (8.1) on page 29.
pub(crate) fn h_xof(v: &[&[u8]]) -> impl XofReader {
    let mut hasher = Shake256::default();
    v.iter().for_each(|b| hasher.update(b));
    hasher.finalize_xof()
}


/// Function H_128(v, d) of (8.2) on page 29.
pub(crate) fn h128_xof(v: &[&[u8]]) -> impl XofReader {
    let mut hasher = Shake128::default();
    v.iter().for_each(|b| hasher.update(b));
    hasher.finalize_xof()
}


/// Algorithm 23 SampleInBall(ρ) on page 30.
/// Samples a polynomial c ∈ Rq with coefficients from {−1, 0, 1} and Hamming weight τ.
pub(crate) fn sample_in_ball<const TAU: usize>(rho: &[u8; 32]) -> R {
    // Input: A seed ρ ∈{0,1}^256
    // Output: A polynomial c in Rq.
    let mut c = R::zero();

    let mut xof = h_xof(&[rho]);
    let mut hpk8 = [0u8; 8];
    xof.read(&mut hpk8); // Save the first 8 bytes for step 9

    // 1: c ← 0
    c.iter_mut().for_each(|element| *element = 0);

    // 2: k ← 8
    let mut hpk = [0u8]; // k implicitly advances with each sample

    // 3: for i from 256 − τ to 255 do
    for i in (256 - TAU)..=255 {
        //
        // 4: while H(ρ)[[k]] > i do
        // 5: k ← k + 1
        // 6: end while
        // The above/below loop reads xof bytes until less than or equal to i
        loop {
            xof.read(&mut hpk); // Every 'read' effectively contains k = k + 1
            if hpk[0] <= i as u8 {
                break;
            }
        }

        // 7: j ← H(ρ)[[k]] ▷ j is a pseudorandom byte that is ≤ i
        let j = hpk[0];

        // 8: ci ← cj
        c[i] = c[j as usize];

        // 9: c_j ← (−1)^{H(ρ)[i+τ−256]
        let index = i + TAU - 256;
        let bite = hpk8[index / 8];
        let shifted = bite >> (index % 8);
        c[j as usize] = (-1i32).pow((shifted % 2 == 1) as u32);

        // 10: k ← k + 1   (implicit)
    } // 11: end for

    debug_assert!(c.iter().filter(|e| e.abs() == 1).count() == TAU);

    c // 12: return c
}


/// Algorithm 24 RejNTTPoly(ρ) on page 30.
/// Samples a polynomial ∈ Tq.
pub(crate) fn rej_ntt_poly(rhos: &[&[u8]], a_hat: &mut T) {
    // Input: A seed ρ ∈{0,1}^{272}.
    // Output: An element a_hat ∈ Tq.
    let mut xof = h128_xof(rhos);

    // 1: j ← 0
    let mut j = 0;

    // 2: c ← 0  (xof has implicit and advancing j)

    // 3: while j < 256 do
    while j < 256 {
        //
        // 4: a_hat[j] ← CoefFromThreeBytes(H128(ρ)[[c]], H128(ρ)[[c + 1]], H128(ρ)[[c + 2]])
        let mut h128pc = [0u8; 3];
        xof.read(&mut h128pc); // implicit c += 3
        let a_hat_j = conversion::coef_from_three_bytes(&h128pc);

        // 5: c ← c + 3  (implicit)

        // 6: if a_hat[j] != ⊥ then
        if a_hat_j == None {
            continue; // leave j alone and re-run
        }
        //
        a_hat[j] = a_hat_j.unwrap(); // Good result, save it and carry on

        // 7: j ← j + 1
        j += 1;

        // 8: end if
        //
    } // 9: end while
      //
} // 10: return a_hat


/// Algorithm 25 RejBoundedPoly(ρ) on page 31.
/// Samples an element a ∈ Rq with coeffcients in [−η, η] computed via rejection sampling from ρ.
pub(crate) fn rej_bounded_poly<const ETA: usize>(rhos: &[&[u8]], a: &mut R) {
    // Input: A seed ρ ∈{0,1}^528.
    // Output: A polynomial a ∈ Rq.
    let mut z = [0u8];
    let mut xof = h_xof(rhos);

    // 1: j ← 0
    let mut j = 0;

    // 2: c ← 0  c is implicit and advancing in xof

    // 3: while j < 256 do
    while j < 256 {
        //
        // 4: z ← H(ρ)[[c]]
        xof.read(&mut z);

        // 5: z0 ← CoefFromHalfByte(z mod 16, η)
        let z0 = conversion::coef_from_half_byte::<ETA>(z[0].rem_euclid(16));

        // 6: z1 ← CoefFromHalfByte(⌊z/16⌋, η)
        let z1 = conversion::coef_from_half_byte::<ETA>(z[0] / 16);

        // 7: if z0 != ⊥ then
        if z0.is_some() {
            //
            // 8: aj ← z0
            a[j] = z0.unwrap();

            // 9: j ← j + 1
            j += 1;
            //
        } // 10: end if
          //
          // 11: if z1 != ⊥ and j < 256 then
        if z1.is_some() & (j < 256) {
            //
            // 12: aj ← z1
            a[j] = z1.unwrap();

            // 13: j ← j + 1
            j += 1;
            //
        } // 14: end if
          //
          // 15: c ← c + 1  (implicit)
          //
    } // 16: end while
      //
} // 17: return a


/// Algorithm 26 ExpandA(ρ) on page 31.
/// Samples a k × ℓ matrix A_hat of elements of T_q.
pub(crate) fn expand_a<const K: usize, const L: usize>(rho: &[u8; 32]) -> [[R; L]; K] {
    // Input: ρ ∈{0,1}^256.
    // Output: Matrix A_hat
    let mut cap_a_hat = [[R::zero(); L]; K];

    // 1: for r from 0 to k − 1 do
    for r in 0..=(K - 1) {
        //
        // 2: for s from 0 to ℓ − 1 do
        for s in 0..=(L - 1) {
            //
            // 3: A_hat[r, s] ← RejNTTPoly(ρ||IntegerToBits(s, 8)||IntegerToBits(r, 8))
            rej_ntt_poly(&[&rho[..], &[s as u8], &[r as u8]], &mut cap_a_hat[r][s]);
            //
        } // 4: end for
          //
    } // 5: end for
    cap_a_hat
}


/// Algorithm 27 ExpandS(ρ) on page 32.
/// Samples vectors s1 ∈ R^ℓ_q and s2 ∈ R^k_q, each with coefficients in the interval [−η, η].
pub(crate) fn expand_s<const ETA: usize, const K: usize, const L: usize>(
    rho: &[u8; 64],
) -> ([R; L], [R; K]) {
    // Input: ρ ∈ {0,1}^512
    // Output: Vectors s1, s2 of polynomials in Rq.
    let (mut s1, mut s2) = ([R::zero(); L], [R::zero(); K]);

    // 1: for r from 0 to ℓ − 1 do
    for r in 0..=(L - 1) {
        //
        // 2: s1[r] ← RejBoundedPoly(ρ||IntegerToBits(r, 16))
        rej_bounded_poly::<ETA>(&[rho, &[0], &[r as u8]], &mut s1[r]);
        //
    } // 3: end for

    // 4: for r from 0 to k − 1 do
    for r in 0..=(K - 1) {
        //
        // 5: s2[r] ← RejBoundedPoly(ρ||IntegerToBits(r + ℓ, 16))
        debug_assert!((r + L) < 255);
        rej_bounded_poly::<ETA>(&[rho, &[0], &[(r + L) as u8]], &mut s2[r]);
        //
    } // 6: end for
      //
    debug_assert!(s1
        .iter()
        .all(|r| r.iter().all(|&c| (c >= -(ETA as i32)) & (c <= ETA as i32))));
    debug_assert!(s2
        .iter()
        .all(|r| r.iter().all(|&c| (c >= -(ETA as i32)) & (c <= ETA as i32))));
    (s1, s2) // 7: return (s_1 , s_2)
}


/// Algorithm 28 ExpandMask(ρ, µ) from page 32.
/// Samples a vector s ∈ R^ℓ_q such that each polynomial s_j has coeffcients between −γ1 + 1 and γ1.
pub(crate) fn expand_mask<const GAMMA1: usize, const L: usize>(
    rho: &[u8; 64], mu: u32
) -> [R; L] {
    // Input: A bit string ρ ∈{0,1}^512 and a nonnegative integer µ.
    // Output: Vector s ∈ R^ℓ_q.
    let mut s = [R::zero(); L];
    let mut v = [0u8; 32 * 20];

    // 1: c ← 1 + bitlen (γ1 − 1) ▷ γ1 is always a power of 2
    let c = 1 + bitlen(GAMMA1 - 1); // c will either be 18 or 20
    debug_assert!((c == 18) | (c == 20));

    // 2: for r from 0 to ℓ − 1 do
    for r in 0..=(L - 1) {
        //
        // 3: n ← IntegerToBits(µ + r, 16)
        debug_assert!((mu < 128) & (r < 128));
        let n = mu as u16 + r as u16;

        // 4: v ← (H(ρ||n)[[32rc]], H(ρ||n)[[32rc+1]], ... , H(ρ||n)[[32rc+32c − 1]])
        let mut xof = h_xof(&[rho, &n.to_be_bytes()]);
        xof.read(&mut v);

        // 5: s[r] ← BitUnpack(v, γ1 − 1, γ1)
        s[r] = conversion::bit_unpack(&v[0..32 * c], GAMMA1 as u32 - 1, GAMMA1 as u32).unwrap();

        debug_assert!(s.iter().all(|r| r
            .iter()
            .all(|&c| (c >= -(GAMMA1 as i32) + 1) & (c <= GAMMA1 as i32))));
    } // 6: end for

    // 7: return s
    s
}