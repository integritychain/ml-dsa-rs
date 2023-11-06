#![allow(dead_code)]

pub fn check() { println!("check!\n") }

const Q: u32 = 2u32.pow(23) - 2u32.pow(13) + 1;
type R = [i32; 100];
type Tq = [u32; 256];
type Zq = i32;

/// Algorithm 4 IntegerToBits(x, α) on page 20.
/// Computes the base-2 representation of x mod 2α (using in little-endian order).
pub(crate) fn integer_to_bits(xx: u32, alpha: usize, y_bits: &mut [bool]) {
    // Input: A nonnegative integer x and a positive integer α.
    // Output: A bit string y of length α.
    debug_assert_eq!(y_bits.len(), alpha.into());
    let mut x = xx;
    // 1: for i from 0 to α − 1 do
    for i in 0..alpha {
        // 2: y[i] ← x mod 2
        y_bits[i] = (x % 2) == 1;
        // 3: x ←⌊x/2⌋
        x >>= 1;
    } // 4: end for
} // 5: return y


/// Algorithm 5 BitsToInteger(y) on page 20.
/// Computes the integer value expressed by a bit string (using little-endian order).
pub(crate) fn bits_to_integer(y_bits: &[bool]) -> u32 {
    // Input: A bit string y of length α.
    // Output: A nonnegative integer x.
    // 1: x ← 0
    let mut x = 0;
    //2: for i from 1 to α do
    for i in 1..=y_bits.len() {
        // 3: x ← 2x + y[α − i]
        x = 2 * x + y_bits[y_bits.len() - i] as u32;
    } // 4: end for
      // 5: return x
    x
}


/// Algorithm 6 BitsToBytes(y) on page 21.
/// Converts a string of bits of length c into a string of bytes of length ⌈c/8⌉.
pub(crate) fn bits_to_bytes(y_bits: &[bool], z_bytes: &mut [u8]) {
    // Input: A bit string y of length c.
    // Output: A byte string z.
    debug_assert_eq!(y_bits.len() % 8, 0);
    debug_assert_eq!(y_bits.len(), z_bytes.len() * 8);
    //1: z ← 0⌈c/8⌉
    z_bytes.iter_mut().for_each(|b| *b = 0);
    // 2: for i from 0 to c − 1 do
    for i in 0..y_bits.len() {
        //3: z[⌊i/8⌋] ← z[⌊i/8⌋] + y[i] · 2
        z_bytes[i / 8] += y_bits[i] as u8 * 2u8.pow(i as u32 % 8);
    } // 4: end for
} // 5: return z


/// Algorithm 7 BytesToBits(z) on page 21.
/// Converts a byte string into a bit string.
pub(crate) fn bytes_to_bits(z_bytes: &[u8], y_bits: &mut [bool]) {
    // Input: A byte string z of length d.
    // Output: A bit string y.
    debug_assert_eq!(y_bits.len() % 8, 0);
    debug_assert_eq!(y_bits.len(), z_bytes.len() * 8);
    // 1: for i from 0 to d − 1 do
    for i in 0..z_bytes.len() {
        // 2: for j from 0 to 7 do
        let mut z_i = z_bytes[i];
        for j in 0..7 {
            // 3: y[8i + j] ← z[i] mod 2
            y_bits[8 * i + j] = (z_i % 2) == 1;
            // 4: z[i] ← ⌊z[i]/2⌋
            z_i >>= 1;
        } // 5: end for
    } // 6: end for
} // 7: return y


/// Algorithm 8 CoefFromThreeBytes(b0, b1, b2) on page 21.
/// Generates an element of {0, 1, 2, . . . , q − 1} ∪ {⊥}.
pub(crate) fn coef_from_three_bytes(bbb: [u8; 3]) -> Option<u32> {
    // Input: Bytes b0, b1, b2.
    // Output: An integer modulo q or ⊥.
    // 1: if b2 > 127 then  TODO: simple AND with 0x7F
    let b2 = if bbb[2] > 127 {
        // 2: b2 ← b2 − 128     ▷ Set the top bit of b2 to zero
        bbb[2] - 128
    } else {
        bbb[2]
    } as u32; // 3: end if
              // 4: z ← 2^16 · b_2 + 2^8 · b1 + b0
    let z = 2u32.pow(16) * b2 + 2u32.pow(8) * (bbb[1] as u32) + (bbb[0] as u32);
    // 5: if z < q then return z
    if z < Q {
        return Some(z);
    } else {
        // 6: 6: else return ⊥
        return None;
    } // 7: end if
}


/// Algorithm 9 CoefFromHalfByte(b) on page 22.
/// Generates an element of {−η,−η + 1, . . . , η} ∪ {⊥}.
pub(crate) fn coef_from_half_byte<const ETA: usize>(b: u8) -> Option<i32> {
    // Input: Integer b ∈{0, 1, . . . , 15}.
    // Output: An integer between −η and η, or ⊥.
    // 1: if η = 2 and b < 15 then return 2− (b mod 5)
    debug_assert!(b < 15);
    if (ETA == 2) & (b < 15) {
        return Some(2 - (b as i32 % 5));
    } else {
        // else
        // 3: if η = 4 and b < 9 then return 4 − b
        if (ETA == 4) & (b < 9) {
            return Some(4 - b as i32);
        } else {
            // 4: else return ⊥
            return None;
        } // 5: end if
    } // 6: end if
}


/// Algorithm 10 SimpleBitPack(w, b) on page 22
/// Encodes a polynomial w into a byte string.
pub(crate) fn simple_bit_pack(w: &R, b: u32, bytes: &mut [u8]) {
    // Input: b ∈ N and w ∈ R such that the coeffcients of w are all in [0, b].
    // Output: A byte string of length 32 · bitlen b.
    w.iter()
        .for_each(|element| debug_assert!(*element <= (b as i32)));
    debug_assert_eq!(bytes.len(), 32 * b as usize);
    let bitlen = (b.ilog2() + 1) as usize;
    // 1: z ← ()        ▷ set z to the empty string
    let mut z = vec![false; bitlen]; // TODO: global buffer?
                                     // 2: for i from 0 to 255 do
    for i in 0..256 {
        // 3: z ← z||IntegerToBits(wi, bitlen b)
        integer_to_bits(w[i] as u32, bitlen, &mut z[i * bitlen..(i + 1) * bitlen]);
    } // 4: end for
      // 5: return BitsToBytes(z)
    bits_to_bytes(&z, bytes);
}


/// Algorithm 11 BitPack(w, a, b) on page 22
/// Encodes a polynomial w into a byte string.
pub(crate) fn bit_pack(w: &[i32], a: u32, b: u32, bytes_out: &mut [u8]) {
    // Input: a, b ∈ N and w ∈ R such that the coeffcients of w are all in [−a, b].
    // Output: A byte string of length 32 · bitlen (a + b).
    debug_assert_eq!(w.len(), 256);
    w.iter()
        .for_each(|element| debug_assert!((-*element <= a as i32) & (*element <= b as i32)));
    let bitlen = ((a + b).ilog2() + 1) as usize;
    debug_assert_eq!(bytes_out.len(), 32 * bitlen);
    // 1: z ← () ▷ set z to the empty string
    let mut z = vec![false; w.len() * bitlen];
    // 2: for i from 0 to 255 do
    for i in 0..=255 {
        // 3: z ← z||IntegerToBits(b − wi, bitlen (a + b))
        integer_to_bits(b - w[i] as u32, bitlen, &mut z[i * bitlen..(i + 1) * bitlen]);
    } // 4: end for
      // 5: return BitsToBytes(z)
    bits_to_bytes(&z, bytes_out)
}


/// Algorithm 12 SimpleBitUnpack(v, b) on page 23.
///Reverses the procedure SimpleBitPack.
pub(crate) fn simple_bit_unpack(v: &[u8], b: u32, w: &mut R) {
    // Input: b ∈ N and a byte string v of length 32 · bitlen b.
    // Output: A polynomial w ∈ R, with coeffcients in [0, 2^c−1], where c = bitlen b.
    // When b + 1 is a power of 2, the coeffcients are in [0, b].
    debug_assert_eq!(v.len(), 32 * (b.ilog2() + 1) as usize);
    // 1: c ← bitlen b
    let c = (b.ilog2() + 1) as usize;
    // 2: z ← BytesToBits(v)
    let mut z = vec![false; 8 * v.len()];
    bytes_to_bits(v, &mut z);
    // 3: for i from 0 to 255 do
    for i in 0..=255 {
        // 4: wi ← BitsToInteger((z[ic], z[ic + 1], . . . z[ic + c − 1]), c)
        w[i] = bits_to_integer(&z[i * c..(i + 1) * c]) as i32;
    } // 5: end for
      // 6: return w
}


/// Algorithm 13 BitUnpack(v, a, b) on page 23.
/// Reverses the procedure BitPack.
pub(crate) fn bit_unpack(v: &[u8], a: u32, b: u32, w: &mut [i32]) {
    // Input: a, b ∈ N and a byte string v of length 32 · bitlen (a + b).
    // Output: A polynomial w ∈ R, with coeffcients in [b− 2c + 1, b], where c = bitlen (a + b).
    debug_assert_eq!(v.len(), 32 * ((a + b).ilog2() + 1) as usize);
    // When a + b + 1 is a power of 2, the coeffcients are in [−a, b].
    // 1: c ← bitlen (a + b)
    let c = ((a + b).ilog2() + 1) as usize;
    let mut z = vec![false; v.len() * 8];
    // 2: z ← BytesToBits(v)
    bytes_to_bits(&v, &mut z);
    // 3: for i from 0 to 255 do
    for i in 0..=255 {
        // 4: wi ← b − BitsToInteger((z[ic], z[ic + 1], . . . z[ic + c − 1]), c)
        w[i] = b as i32 - bits_to_integer(&z[i * c..i * (c + 1)]) as i32;
    } // 5: end for
      // 6: return w
}


/// Algorithm 14 HintBitPack(h) on page 24.
/// Encodes a polynomial vector h with binary coeffcients into a byte string.
pub(crate) fn hint_bit_pack<const OMEGA: usize>(h: &[bool], y_bytes: &mut [u8]) {
    // Input: A polynomial vector h ∈ R^k_2 such that at most ω of the coeffcients in h are equal to 1.
    // Output: A byte string y of length ω + k.
    debug_assert_eq!(y_bytes.len(), OMEGA + h.len());
    // 1: y ∈ Bω+k ← 0ω+k
    let k = h.len();
    // 2: Index ← 0
    let mut index = 0;
    // 3: for i from 0 to k − 1 do
    for i in 0..=(k - 1) {
        // 4: for j from 0 to 255 do
        for j in 0..=255 {
            // 5: if h[i] j = 0 then  // TODO: revisit h subscripts
            if h[i] == false {
                // TODO
                // 6: y[Index] ← j      ▷ Store the locations of the nonzero coeffcients in h[i]
                y_bytes[index] = j;
                // 7: Index ← Index + 1
                index += 1;
            } // 8: end if
        } // 9: end for
          // 10: y[ω + i] ← Index ▷ Store the value of Index after processing h[i]
        y_bytes[OMEGA + i] = index as u8;
    } // 11: end for
      // 12: return y
}


/// Algorithm 15 HintBitUnpack(y) on page 24.  TODO: DODGY ALL THE WAY
///Reverses the procedure HintBitPack.
pub(crate) fn hint_bit_unpack<const OMEGA: usize, const K: usize>(y_bytes: &[u8], h: &mut [u32]) {
    // Input: A byte string y of length ω + k.
    // Output: A polynomial vector h ∈ R^k_2 or ⊥.
    debug_assert_eq!(y_bytes.len(), OMEGA + K);
    debug_assert_eq!(h.len(), K);
    // 1: h Rk k ∈ ← 2 0
    //let mut h = vec![false; K];
    // 2: Index ← 0
    let mut index = 0;
    // 3: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 4: if y[ω + i] < Index or y[ω + i] > ω then return ⊥
        if (y_bytes[OMEGA + i] < index) | (y_bytes[OMEGA + i] > OMEGA as u8) {
            panic!()
        } // 5: end if
          // 6: while Index < y[ω + i] do
        while index < y_bytes[OMEGA + i] {
            // 7: h[i]y[Index] ← 1
            h[i] = 1; //TODO: broken
                      // 8: Index ← Index + 1
            index += 1;
        } // 9: end while
    } // 10: end for
      // 11: while Index < ω do
    while index < OMEGA as u8 {
        // 12: if y[Index] = 0 then return ⊥
        if y_bytes[index as usize] == 0 {
            panic!()
        } // 13: end if
          // 14: Index ← Index + 1
        index += 1;
    } // 15: end while
} // 16: return h


/// Algorithm 16 pkEncode(ρ, t1) on page 25
/// Encodes a public key for ML-DSA into a byte string.
pub(crate) fn pk_encode<const K: usize, const D: usize>(p: &[bool; 256], t1: &[R], pk: &mut [u8]) {
    // Input:ρ ∈ {0, 1}^256, t1 ∈ Rk with coefficients in [0, 2^{bitlen(q−1)−d}-1]).
    // Output: Public key pk ∈ B^{32+32k(bitlen (q−1)−d)}.
    debug_assert_ne!(pk.len(), 0); // TODO tighten!
    debug_assert_eq!(t1.len(), K);
    let bitlen = ((Q - 1).ilog2() + 1) as usize - D;
    // 1: pk ← BitsToBytes(ρ)
    bits_to_bytes(p, pk);
    // 2: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 3: pk ← pk || SimpleBitPack (t1[i], 2^{bitlen(q−1)−d}-1)
        simple_bit_pack(
            &t1[i],
            2u32.pow(bitlen as u32) - 1,
            &mut pk[32 + 32 * K * bitlen..32 + 32 * (K + 1) * bitlen],
        );
    } // 4: end for
} // 5: return pk


/// Algorithm 17 pkDecode(pk) on page 25.
/// Reverses the procedure pkEncode.
pub(crate) fn pk_decode<const K: usize, const D: usize>(
    pk: &[u8], rho: &mut [bool; 256], t1: &mut [R],
) {
    // Input: Public key pk ∈ B^{32+32k(bitlen(q−1)−d)}.
    // Output: ρ ∈ {0, 1}^256, t1 ∈ Rk with coeffcients in [0, 2^{bitlen(q−1)−d} − 1]).
    let bitlen = (Q - 1).ilog2() as usize + 1 - D;
    debug_assert_eq!(pk.len(), 32 + 32 * K * bitlen);
    debug_assert_eq!(t1.len(), K);
    debug_assert!(t1.iter().all(|rk| rk.len() == K)); // TODO: expand to coeff values
                                                      // 1: (y, z_0 , . . . , z_{k−1}) ∈ B^{32} × (B^{32(bitlen(q−1)−d))^k} ← pk
                                                      // TODO ?? skip above?
                                                      // 2: ρ ← BytesToBits(y)
    bytes_to_bits(&pk[0..32], rho);
    // 3: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 4: t1[i] ← SimpleBitUnpack(zi, 2^{bitlen(q−1)−d} − 1)) ▷ This is always in the correct range
        simple_bit_unpack(
            &pk[32 + i * bitlen..32 + (i + 1) * bitlen],
            2u32.pow(bitlen as u32) - 1,
            &mut t1[i],
        );
    } // 5: end for
} // 6: return (ρ, t1)


// Algorithm 18 skEncode(ρ, K,tr, s1, s2, t0) on page 26.
// Encodes a secret key for ML-DSA into a byte string.
pub fn sk_encode<const D: usize, const ETA: usize, const K: usize, const L: usize>(
    rho: &[bool; 256], k: &[bool; 256], tr: &[bool; 512], s1: &[R], s2: &[R], t0: &[R],
    sk: &mut [u8],
) {
    // Input: ρ ∈ {0,1}^256, K ∈ {0,1}^256, tr ∈ {0,1}^512,
    //        s1 ∈ R^l with coefficients in [−η, η],
    //        s2 ∈ R^k with coefficients in [−η η],
    //        t0 ∈ R^k with coefficients in [−2^{d-1} + 1, 2^{d-1}].
    // Output: Private key, sk ∈ B^{32+32+64+32·((k+ℓ)·bitlen (2η)+dk)}
    let (c_min, c_max) = (-1 * ETA as i32, ETA as i32);
    debug_assert_eq!(s1.len(), L);
    debug_assert!(s1
        .iter()
        .all(|r| r.iter().all(|coeff| (*coeff >= c_min) & (*coeff <= c_max))));
    debug_assert_eq!(s2.len(), K);
    debug_assert!(s2
        .iter()
        .all(|r| r.iter().all(|coeff| (*coeff >= c_min) & (*coeff <= c_max))));
    let (c_min, c_max) = (-1 * 2i32.pow(D as u32 - 1) + 1, 2i32.pow(D as u32 - 1));
    debug_assert_eq!(t0.len(), K);
    debug_assert!(t0
        .iter()
        .all(|r| r.iter().all(|coeff| (*coeff >= c_min) & (*coeff <= c_max))));
    // 1: sk ← BitsToBytes(ρ) || BitsToBytes(K) || BitsToBytes(tr)
    bits_to_bytes(rho, &mut sk[0..32]);
    bits_to_bytes(k, &mut sk[32..64]);
    bits_to_bytes(tr, &mut sk[64..128]);
    let start = 128;
    let step = 32 * ((K + L) * (2 * ETA).ilog2() as usize + 1 + D * K);
    // 2: for i from 0 to ℓ − 1 do
    for i in 0..=(L - 1) {
        // 3: sk ← sk || BitPack (s1[i], η, η)
        bit_pack(
            &s1[i],
            ETA as u32,
            ETA as u32,
            &mut sk[start + i * step..start + (i + 1) * step],
        );
    } // 4: end for
    let start = start + L * step;
    // 5: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 6: sk ← sk || BitPack (s2[i], η, η)
        bit_pack(
            &s2[i],
            ETA as u32,
            ETA as u32,
            &mut sk[start + i * step..start + (i + 1) * step],
        );
    } // 7: end for
    let start = start + K * step;
    // 8: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 9: sk ← sk || BitPack (t0[i], [−2^{d-1} + 1, 2^{d-1}] )
        bit_pack(
            &t0[i],
            2u32.pow(D as u32 - 1) + 1,
            2u32.pow(D as u32 - 1),
            &mut sk[start + i * step..start + (i + 1) * step],
        );
    } // 10: end for
} // 11: return sk


/// Algorithm 19 skDecode(sk) on page 27.
/// Reverses the procedure skEncode.
pub(crate) fn sk_decode<const D: usize, const ETA: usize, const K: usize, const L: usize>(
    sk: &[u8], rho: &mut [bool; 256], k: &mut [bool; 256], tr: &mut [bool; 512], s1: &mut [R],
    s2: &mut [R], t0: &mut [R],
) {
    // Input: Private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}
    // Output: ρ ∈ {0,1}^256, K ∈ ∈ {0,1}^256, tr ∈ ∈ {0,1}^512,
    // s1 ∈ R^ℓ, s2 ∈ R^k, t0 ∈ R^k with coefficients in [−2^{d−1} + 1, 2^{d−1}].
    debug_assert_eq!(
        sk.len(),
        32 + 32 + 64 + 32 * ((L + K) * (2 * ETA).ilog2() as usize + 1 + D * K)
    );
    debug_assert_eq!(s1.len(), L);
    // 1: (f, g, h, y_0, . . . , y_{ℓ−1}, z_0, . . . , z_{k−1}, w_0, . . . , w_{k−1)}) ∈
    //    B^32 × B^32 × B^64 × B^{32·bitlen(2η)}^l × B^{32·bitlen(2η)}^k × B^{32d}^k ← sk
    let bitlen = (2 * ETA).ilog2() as usize + 1;
    // 2: ρ ← BytesToBits( f )
    bytes_to_bits(&sk[0..32], rho);
    // 3: K ← BytesToBits(g)
    bytes_to_bits(&sk[32..64], k);
    // 4: tr ← BytesToBits(h)
    bytes_to_bits(&sk[64..128], tr);
    let start = 128;
    let step = 32 * bitlen;
    // 5: for i from 0 to ℓ − 1 do
    for i in 0..=(L - 1) {
        // 6: s1[i] ← BitUnpack(yi, η, η)   ▷ This may lie outside [−η, η], if input is malformed
        bit_unpack(
            &sk[start + i * step..start * (i + 1) * step],
            ETA as u32,
            ETA as u32,
            &mut s1[i],
        );
    } // 7: end for
    let start = start + L * step;
    // 8: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 9: s2[i] ← BitUnpack(zi, η, η) ▷ This may lie outside [−η, η], if input is malformed
        bit_unpack(
            &sk[start + i * step..start * (i + 1) * step],
            ETA as u32,
            ETA as u32,
            &mut s2[i],
        );
    } // 10: end for
    let start = start + K * bitlen;
    let step = 32 * D;
    // 11: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        // 12: t0[i] ← BitUnpack(wi, −2^{d−1} - 1, 2^{d−1})   ▷ This is always in the correct range
        bit_unpack(
            &sk[start + i * step..start * (i + 1) * step],
            2u32.pow(D as u32 - 1) + 1,
            2u32.pow(D as u32 - 1),
            &mut t0[i],
        );
    } // 13: end for
    let (c_min, c_max) = (-1 * 2i32.pow(D as u32 - 1) + 1, 2i32.pow(D as u32 - 1));
    debug_assert!([s1, s2, t0].iter().all(|var| var
        .iter()
        .all(|r| r.iter().all(|coeff| (*coeff >= c_min) & (*coeff <= c_max)))));
} // 14: return (ρ, K,tr, s1, s2, t0)


/// Algorithm 20 sigEncode(c_tilde, z, h) on page 28.
/// Encodes a signature into a byte string.
pub(crate) fn sig_encode<
    const GAMMA: usize,
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
>(
    c_tilde: &[bool], z: &[R], h: &[bool], sigma: &mut [u8],
) {
    // Input: c_tilde ∈ {0,1}^2λ, z ∈ R^ℓ with coeffcients in [−1*γ_1 + 1, γ_1], h ∈ R^k_2.
    // Output: Signature, σ ∈ B^{λ/4 +l*32*(1+bitlen(γ_1 - 1)+ω+k}
    debug_assert_eq!(c_tilde.len(), 2 * LAMBDA);
    // 1: σ ← BitsToBytes(c_tilde)
    bits_to_bytes(&c_tilde, &mut sigma[..2 * LAMBDA * 8]);
    let start = 2 * LAMBDA * 8;
    let step = L * 32 * ((LAMBDA - 1).ilog2() as usize + 1) + OMEGA + K;
    // 2: for i from 0 to ℓ − 1 do
    for i in 0..=(L - 1) {
        // 3: σ ← σ || BitPack (z[i], γ_1 − 1, γ_1)
        bit_pack(
            &z[i],
            GAMMA as u32 - 1,
            GAMMA as u32,
            &mut sigma[start + i * step..start + (i + 1) * step],
        );
    } // 4: end for
    hint_bit_pack::<OMEGA>(h, &mut sigma[start + L * step..]);
    // 5: σ ← σ || HintBitPack (h)
} // 6: return σ


/// Algorithm 21 sigDecode(σ) on page 28.
/// Reverses the procedure sigEncode.
pub(crate) fn sig_decode<
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
>(
    sigma: &[u8], c_tilde: &mut [bool], z: &mut [R], h: &mut R,
) {
    // Input: Signature, σ ∈ B^{λ/4+ℓ·32·(1+bitlen (γ_1-1))+ω+k
    // Output: c_tilde ∈ {0,1}^2λ, z ∈ R^ℓ_q with coefficients in [−γ_1 + 1, γ1], h ∈ R^k_2 or ⊥.

    // 1: (ω, x_0, ... , x_{ℓ−1}, y) ∈ B^{λ/4} × Bℓ·32·(1+bitlen(γ_1−1))+ω+k ← σ

    // 2: c_tilde ← BytesToBits(w)
    bytes_to_bits(&sigma[0..LAMBDA / 4], c_tilde);
    let start = LAMBDA / 4;
    let step = L * 32 * (1 + (OMEGA - 1).ilog2() + 1) as usize;
    // 3: for i from 0 to ℓ − 1 do
    for i in 0..=(L - 1) {
        // 4: z[i] ← BitUnpack(xi, γ1 − 1, γ1) ▷ This is always in the correct range, as γ1 is a power of 2
        bit_unpack(
            &sigma[start + i * step..start * (i + 1) * step],
            LAMBDA as u32 - 1,
            LAMBDA as u32,
            &mut z[i],
        );
    } // 5: end for
      // 6: h ← HintBitUnpack(y)
    hint_bit_unpack::<OMEGA, K>(&sigma[start + L * step..], &mut [h[0] as u32]);
    // TODO BLAHHH!
    // 7: return (c_tilde, z, h)
}

/// Algorithm 22 w1Encode(w1) on page 28.
/// Encodes a polynomial vector w1 into a bit string.
pub(crate) fn w1_encode<const K: usize, const GAMMA: usize>(w1: &[R], w1_tilde: &mut [bool]) {
    // Input: w1 ∈ R^k with coefficients in [0, (q − 1)/(2γ_2) − 1].
    // Output: A bit string representation, w1_tilde ∈ {0,1}^{32k*bitlen((q-1)/(2γ2)−1).
    // 1: w1_tilde ← ()
    let step = 32 * K * (((Q - 1) / (2 * GAMMA as u32 - 1)).ilog2() as usize + 1 - 1);
    // 2: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        let mut bytes = vec![0u8; 32 * (((Q - 1) / (2 * (GAMMA as u32)) - 1).ilog2() as usize + 1)];
        // 3: w1_tilde ← w1_tilde || BytesToBits (SimpleBitPack (w1[i], (q − 1)/(2γ2) − 1))
        simple_bit_pack(&w1[i], (Q - 1) / (2 * (GAMMA as u32)) - 1, &mut bytes);
        bytes_to_bits(&bytes, &mut w1_tilde[i * step..(i + 1) * step]);
    } // 4: end for
} // 5: return w˜1


use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
/// Function H(rho)[[k]] on page 29.
pub(crate) fn hpk_xof(v: &[u8]) -> impl XofReader {
    let mut hasher = Shake256::default();
    hasher.update(v);
    hasher.finalize_xof()
}


/// Algorithm 23 SampleInBall(ρ) on page 30.
/// Samples a polynomial c ∈ Rq with coefficients from {−1, 0, 1} and Hamming weight τ.
pub(crate) fn sample_in_ball<const TAU: usize>(rho: &[u8; 32], c: &mut R) {
    // Input: A seed ρ ∈{0,1}^256
    // Output: A polynomial c in Rq.
    let mut xof = hpk_xof(rho);
    let mut hpk8 = [0u8; 8];
    xof.read(&mut hpk8); // Save the first 8 bytes
                         // 1: c ← 0
    c.iter_mut().for_each(|element| *element = 0);
    // 2: k ← 8
    let mut hpk = [0u8];
    // 3: for i from 256 − τ to 255 do
    for i in (256 - TAU)..=255 {
        // 4: while H(ρ)[[k]] > i do
        // 5: k ← k + 1
        // 6: end while
        loop {
            xof.read(&mut hpk); // Every 'read' effectively contains k = k + 1
            if hpk[0] < i as u8 {
                break;
            }
        }
        // 7: j ← H(ρ)[[k]] ▷ j is a pseudorandom byte that is ≤ i
        let j = hpk[0];
        // 8: ci ← cj
        c[i] = c[j as usize];
        // 9: c_j ← (−1)^{H(ρ)[i+τ−256]
        c[j as usize] =
            (-1i32).pow(((hpk8[(i + TAU - 256) / 8] >> ((i + TAU - 256) % 8)) % 2 == 1) as u32);
        // 10: k ← k + 1
    } // 11: end for
} // 12: return c

//use sha3::digest::{ExtendableOutput, Update, XofReader};
use crate::D;
use sha3::Shake128;

/// Function H(rho)[[k]] on page 29.
pub(crate) fn h128pc_xof(v: &[u8; 34]) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(v);
    hasher.finalize_xof()
}


/// Algorithm 24 RejNTTPoly(ρ) on page 30.
/// Samples a polynomial ∈ Tq.
pub(crate) fn rej_ntt_poly(rho: &[u8; 34], a_hat: &mut Tq) {
    // Input: A seed ρ ∈{0,1}^{272}.
    // Output: An element a_hat ∈ Tq.
    let mut xof = h128pc_xof(rho);
    // 1: j ← 0
    let mut j = 0;
    // 2: c ← 0  (xof has implicit and advancing j)
    // 3: while j < 256 do
    while j < 256 {
        // 4: a_hat[ j] ← CoefFromThreeBytes(H128(ρ)[[c]], H128(ρ)[[c + 1]], H128(ρ)[[c + 2]])
        let mut h128pc = [0u8; 3];
        xof.read(&mut h128pc); // implicit c += 3
        let a_hat_j = coef_from_three_bytes(h128pc);
        // 5: c ← c + 3
        // 6: if aˆ[ j] != ⊥ then
        if a_hat_j == None {
            continue;
        } // leave j alone and re-run
        a_hat[j] = a_hat_j.unwrap(); // Good result, save it and carry on
                                     // 7: j ← j + 1
        j += 1;
        // 8: end if
    } // 9: end while
      // 10: return a_hat
}


/// Algorithm 25 RejBoundedPoly(ρ) on page 31.
/// Samples an element a ∈ Rq with coeffcients in [−η, η] computed via rejection sampling from ρ.
pub(crate) fn rej_bounded_poly<const ETA: usize>(rho: &[u8; 66], a: &mut R) {
    // Input: A seed ρ ∈{0,1}^528.
    // Output: A polynomial a ∈ Rq.
    let mut z = [0u8];
    let mut xof = hpk_xof(rho);
    // 1: j ← 0
    let mut j = 0;
    // 2: c ← 0  c is implicit and advancing in xof
    // 3: while j < 256 do
    while j < 256 {
        // 4: z ← H(ρ)JcK
        xof.read(&mut z);
        // 5: z0 ← CoefFromHalfByte(z mod 16, η)
        let z0 = coef_from_half_byte::<ETA>(z[0] % 16);
        // 6: z1 ← CoefFromHalfByte(⌊z/16⌋, η)
        let z1 = coef_from_half_byte::<ETA>(z[0] / 16);
        // 7: if z0 != ⊥ then
        if z0.is_some() {
            // 8: aj ← z0
            a[j] = z0.unwrap();
            // 9: j ← j + 1
            j += 1;
        } // 10: end if
          // 11: if z1 != ⊥ and j < 256 then
        if z1.is_some() & (j < 256) {
            // 12: aj ← z1
            a[j] = z1.unwrap();
            // 13: j ← j + 1
            j += 1;
        } // 14: end if
          // 15: c ← c + 1
    } // 16: end while
      // 17: return a
}


/// Algorithm 26 ExpandA(ρ) on page 31.
/// Samples a k × ℓ matrix A_hat of elements of T_q.
pub(crate) fn expand_a<const K: usize, const L: usize>(
    rho: &[u8; 32], cap_a_hat: &mut [[Tq; K]; L],
) {
    // Input: ρ ∈{0,1}^256.
    // Output: Matrix A_hat
    let mut big_rho = [0u8; 34];
    big_rho[0..32].copy_from_slice(rho);
    // 1: for r from 0 to k − 1 do
    for r in 0..=(K - 1) {
        // 2: for s from 0 to ℓ − 1 do
        for s in 0..=(L - 1) {
            // 3: Aˆ [r, s] ← RejNTTPoly(ρ||IntegerToBits(s, 8)||IntegerToBits(r, 8))
            big_rho[32] = s as u8;
            big_rho[33] = r as u8;
            rej_ntt_poly(&big_rho, &mut cap_a_hat[r][s]);
        } // 4: end for
    } // 5: end for
} // 6: return A ˆ


/// Algorithm 27 ExpandS(ρ) on page 32.
/// Samples vectors s1 ∈ R^ℓ_q and s2 ∈ R^k_q, each with coefficients in the interval [−η, η].
pub(crate) fn expand_s<const ETA: usize, const K: usize, const L: usize>(
    rho: &[u8; 64], s1: &mut [R; L], s2: &mut [R; K],
) {
    // Input: ρ ∈ {0,1}^512
    // Output: Vectors s1, s2 of polynomials in Rq.
    let mut big_rho = [0u8; 66];
    big_rho[0..64].copy_from_slice(rho); // note position 64 will be left as 0u8 below
                                         // 1: for r from 0 to ℓ − 1 do
    for r in 0..=(L - 1) {
        // 2: s1[r] ← RejBoundedPoly(ρ||IntegerToBits(r, 16))
        big_rho[65] = r as u8; // K,L never go above 8,7
        rej_bounded_poly::<ETA>(&big_rho, &mut s1[r]);
    } // 3: end for
      // 4: for r from 0 to k − 1 do
    for r in 0..=(K - 1) {
        // 5: s2[r] ← RejBoundedPoly(ρ||IntegerToBits(r + ℓ, 16))
        big_rho[65] = (r + L) as u8;
        rej_bounded_poly::<ETA>(&big_rho, &mut s2[r]);
    } // 6: end for
} // 7: return (s1, s2)


/// Algorithm 28 ExpandMask(ρ, µ) from page 32.
/// Samples a vector s ∈ Rℓq such that each polynomial sj has coeffcients between −γ1 + 1 and γ1.
pub(crate) fn expand_mask<const GAMMA1: usize, const L: usize>(
    rho: &[u8; 64], mu: u32, s: &mut [R; L],
) {
    // Input: A bit string ρ ∈{0,1}^512 and a nonnegative integer µ.
    // Output: Vector s ∈ R^ℓ_q.
    let mut v = [0u8; 32 * 19];
    // 1: c ← 1 + bitlen (γ1 − 1) ▷ γ1 is always a power of 2
    let c = 1 + (GAMMA1 - 1).ilog2() as usize + 1; // c will either be 17 or 19
                                                   // 2: for r from 0 to ℓ − 1 do
    for r in 0..=(L - 1) {
        // 3: n ← IntegerToBits(µ + r, 16)
        let mut n = [false; 16];
        integer_to_bits(mu + r as u32, 16, &mut n);
        let n = n.iter().fold(0u16, |acc, bit| (acc << 1) + (*bit as u16));
        // 4: v ← (H(ρ||n)[[32rc]], H(ρ||n)[[32rc+1]], ... , H(ρ||n)[[32rc+32c − 1]])
        let mut big_rho = [0u8; 66];
        big_rho[0..64].copy_from_slice(rho);
        big_rho[64..66].copy_from_slice(&n.to_be_bytes());
        let mut xof = hpk_xof(&big_rho);
        xof.read(&mut v);
        // 5: s[r] ← BitUnpack(v, γ1 − 1, γ1)
        bit_unpack(&v[0..(c - 1)], GAMMA1 as u32 - 1, GAMMA1 as u32, &mut s[r]);
    } // 6: end for
} // 7: return s


/// Algorithm 29 Power2Round(r) on page 34.
/// Decomposes r into (r1, r0) such that r ≡ r1*2^d + r0 mod q.
pub(crate) fn power2round(r: Zq, r1: &mut Zq, r0: &mut Zq) {
    // Input: r ∈ Zq.
    // Output: Integers (r1, r0).
    // 1: r+ ← r mod q
    let rp = r % (Q as i32);
    // 2: r0 ← r+ mod±2^d
    let x1 = rp & (2i32.pow(D) - 1);
    *r0 = if x1 < 2i32.pow(D - 1) {
        x1
    } else {
        2i32.pow(D - 1) - x1
    };
    // 3: return ((r+ − r0)/2^d, r0)
    *r1 = rp - *r0;
}

/// Algorithm 30 Decompose(r) on page 34.
/// Decomposes r into (r1, r0) such that r ≡ r1(2γ2) + r0 mod q.
pub(crate) fn decompose<const GAMMA2: u32>(r: &Zq, r1: &mut Zq, r0: &mut Zq) {
    // Input: r ∈ Zq
    // Output: Integers (r1, r0).
    // 1: r+ ← r mod q
    let rp = r % (Q as i32);
    // 2: r0 ← r+ mod±(2γ_2)
    let x1 = rp % (2 * GAMMA2 as i32);
    *r0 = if x1 <= GAMMA2 as i32 {
        x1
    } else {
        GAMMA2 as i32 - x1
    };
    // 3: if r+ − r0 = q − 1 then
    if (rp - *r0) == (Q as i32 - 1) {
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
    let m = (Q - 1)/(2*GAMMA2);
    // 2: (r1, r0) ← Decompose(r)
    let (mut r1, mut r0) = (0, 0);
    decompose::<GAMMA2>(&r, &mut r1, &mut r0);
    // 3: if h = 1 and r0 > 0 return (r1 + 1) mod m
    if h & (r0 > 0) {return (r1 + 1) % m as i32}
    // 4: if h = 1 and r0 ≤ 0 return (r1 − 1) mod m
    if h & (r0 <= 0) {return (r1 - 1) % m as i32}
    // 5: return r1
    r1
}
