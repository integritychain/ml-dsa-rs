use crate::helpers::bitlen;
use crate::types::R;
use crate::QI;

// This file implements functionality from FIPS 204 section 8.1 Conversion Between Data Types
// The functions involving individual bits are ripe for optimization...


/// Algorithm 4 IntegerToBits(x, alpha) on page 20.
/// Computes the base-2 representation of x mod 2^{alpha} (using in little-endian order).
/// This function will soon be optimized away.
//pub(crate) fn integer_to_bits(x: u32, alpha: usize, y_bits: &mut [bool]) {
pub(crate) fn integer_to_bits(x: i32, alpha: usize, y_bits: &mut [bool]) {
    // Input: A nonnegative integer x and a positive integer alpha.
    // Output: A bit string y of length alpha.
    debug_assert_eq!(y_bits.len(), alpha);
    let mut xx = x as u32;

    // 1: for i from 0 to alpha − 1 do
    for i in 0..=(alpha - 1) {
        //
        // 2: y[i] ← x mod 2
        y_bits[i] = (xx % 2) == 1;

        // 3: x ←⌊x/2⌋
        xx >>= 1;
        //
    } // 4: end for
} // 5: return y


/// Algorithm 5 BitsToInteger(y) on page 20.
/// Computes the integer value expressed by a bit string (using little-endian order).
/// This function will soon be optimized away.
pub(crate) fn bits_to_integer(y_bits: &[bool]) -> i32 {
    // Input: A bit string y of length alpha.
    // Output: A nonnegative integer x.
    debug_assert!(y_bits.len() <= 32);
    let alpha = y_bits.len();

    // 1: x ← 0
    let mut x = 0;

    //2: for i from 1 to alpha do
    for i in 1..=alpha {
        //
        // 3: x ← 2x + y[α − i]
        x = 2 * x + y_bits[alpha - i] as u32;
        //
    } // 4: end for

    x as i32 // 5: return x
}


/// Algorithm 6 BitsToBytes(y) on page 21.
/// Converts a string of bits of length c into a string of bytes of length ⌈c/8⌉.
/// This function will soon be optimized away.
pub(crate) fn bits_to_bytes(y_bits: &[bool], z_bytes: &mut [u8]) {
    // Input: A bit string y of length c.
    // Output: A byte string z.
    debug_assert_eq!(y_bits.len() % 8, 0);
    debug_assert_eq!(y_bits.len(), z_bytes.len() * 8);
    let c = y_bits.len();

    // 1: z ← 0⌈c/8⌉
    z_bytes.iter_mut().for_each(|b| *b = 0);

    // 2: for i from 0 to c − 1 do
    for i in 0..=(c - 1) {
        //
        //3: z[⌊i/8⌋] ← z[⌊i/8⌋] + y[i] · 2^{i mod 8}
        z_bytes[i / 8] += y_bits[i] as u8 * 2u8.pow((i % 8) as u32);
        //
    } // 4: end for
} // 5: return z


/// Algorithm 7 BytesToBits(z) on page 21.
/// Converts a byte string into a bit string.
/// This function will soon be optimized away.
pub(crate) fn bytes_to_bits(z_bytes: &[u8], y_bits: &mut [bool]) {
    // Input: A byte string z of length d.
    // Output: A bit string y.
    debug_assert_eq!(y_bits.len() % 8, 0);
    debug_assert_eq!(y_bits.len(), z_bytes.len() * 8);
    let d = z_bytes.len();

    // 1: for i from 0 to d − 1 do
    for i in 0..=(d - 1) {
        //
        // 2: for j from 0 to 7 do
        let mut z_i = z_bytes[i];
        for j in 0..=7 {
            //
            // 3: y[8i + j] ← z[i] mod 2
            y_bits[8 * i + j] = (z_i % 2) == 1;

            // 4: z[i] ← ⌊z[i]/2⌋
            z_i >>= 1;
            //
        } // 5: end for
    } // 6: end for
} // 7: return y


/// Algorithm 8 CoefFromThreeBytes(b0, b1, b2) on page 21.
/// Generates an element of {0, 1, 2, . . . , q − 1} ∪ {⊥}.
pub(crate) fn coef_from_three_bytes(bbb: &[u8; 3]) -> Option<i32> {
    // Input: Bytes b0, b1, b2.
    // Output: An integer modulo q or ⊥.

    // 1: if b2 > 127 then
    // 2: b2 ← b2 − 128     ▷ Set the top bit of b2 to zero
    // 3: end if
    let bbb2 = (bbb[2] & 0x7F) as i32;

    // 4: z ← 2^16 · b_2 + 2^8 · b1 + b0
    let z = 2i32.pow(16) * bbb2 + 2i32.pow(8) * (bbb[1] as i32) + (bbb[0] as i32);

    // 5: if z < q then return z
    return if z < QI {
        Some(z)
    } else {
        // 6: else return ⊥
        None
    }; // 7: end if
}


/// Algorithm 9 CoefFromHalfByte(b) on page 22.
/// Generates an element of {−η,−η + 1, . . . , η} ∪ {⊥}.
pub(crate) fn coef_from_half_byte<const ETA: usize>(b: u8) -> Option<i32> {
    // Input: Integer b ∈{0, 1, ... , 15}.
    // Output: An integer between −η and η, or ⊥.
    debug_assert!(b <= 15);

    // 1: if η = 2 and b < 15 then return 2 − (b mod 5)
    if (ETA == 2) & (b < 15) {
        return Some(2 - (b % 5) as i32);
        //
    } else {
        // 2: else
        //
        // 3: if η = 4 and b < 9 then return 4 − b
        if (ETA == 4) & (b < 9) {
            return Some(4 - b as i32);
            //
        } else {
            // 4: else return ⊥
            return None;
            //
        } // 5: end if
    } // 6: end if
}


/// Algorithm 10 SimpleBitPack(w, b) on page 22
/// Encodes a polynomial w into a byte string.
/// This function has been optimized, but remains under test alongside the original logic.
pub(crate) fn simple_bit_pack(w: &R, b: u32, bytes_out: &mut [u8]) {
    // Input: b ∈ N and w ∈ R such that the coeffcients of w are all in [0, b].
    // Output: A byte string of length 32 · bitlen b.
    debug_assert!(w.iter().all(|e| (*e >= 0) & (*e <= (b as i32))));
    let bitlen = bitlen(b as usize);
    debug_assert_eq!(bytes_out.len(), 32 * bitlen);

    // 1: z ← ()        ▷ set z to the empty string
    let mut z = vec![false; 256 * bitlen];

    // 2: for i from 0 to 255 do
    for i in 0..=255 {
        //
        // 3: z ← z||IntegerToBits(wi, bitlen b)
        integer_to_bits(w[i], bitlen, &mut z[i * bitlen..(i + 1) * bitlen]);
        //
    } // 4: end for

    // 5: return BitsToBytes(z)
    bits_to_bytes(&z, bytes_out);

    // Test...
    let mut bytes_tst = vec![0u8; bytes_out.len()];
    bit_pack2(w, 0, b, &mut bytes_tst);
    assert_eq!(bytes_out, bytes_tst);
}


/// Algorithm 11 BitPack(w, a, b) on page 22
/// Encodes a polynomial w into a byte string.
/// This function has been optimized, but remains under test alongside the original logic.
pub(crate) fn bit_pack(w: &R, a: u32, b: u32, bytes_out: &mut [u8]) {
    // Input: a, b ∈ N and w ∈ R such that the coeffcients of w are all in [−a, b].
    // Output: A byte string of length 32 · bitlen (a + b).
    debug_assert!(w.iter().all(|e| (*e >= -(a as i32)) & (*e <= b as i32)));
    let bitlen = bitlen((a + b) as usize);
    debug_assert_eq!(bytes_out.len(), 32 * bitlen);

    // 1: z ← () ▷ set z to the empty string
    let mut z = vec![false; w.len() * bitlen];

    // 2: for i from 0 to 255 do
    for i in 0..=255 {
        //
        // 3: z ← z||IntegerToBits(b − wi, bitlen (a + b))
        integer_to_bits(b as i32 - w[i], bitlen, &mut z[i * bitlen..(i + 1) * bitlen]);
        //
    } // 4: end for

    bits_to_bytes(&z, bytes_out); // 5: return BitsToBytes(z)

    // Test...
    let mut bytes_tst = vec![0u8; bytes_out.len()];
    bit_pack2(w, a, b, &mut bytes_tst);
    assert_eq!(bytes_out, bytes_tst);
}


pub(crate) fn bit_pack2(w: &R, a: u32, b: u32, bytes_out: &mut [u8]) {
    debug_assert!((a < u32::MAX / 4) & (b < u32::MAX / 4) & (b >= a)); // Ensure some headroom
    let bitlen = bitlen((a + b) as usize); // Calculate element bit length
    debug_assert_eq!(w.len() * bitlen / 8, bytes_out.len()); // correct size
    debug_assert!((w.len() * bitlen) % 8 == 0); // none left over
    debug_assert!(w.iter().all(|e| ((-*e <= a as i32) & (*e <= b as i32)))); // Correct range
    let mut temp = 0u64;
    let mut byte_index = 0;
    let mut bit_index = 0;
    for e in w {
        if a > 0 {
            temp = temp | (((b as i64 - *e as i64) as u64) << bit_index);
        } else {
            temp = temp | ((*e as u64) << bit_index);
        }
        bit_index += bitlen;
        while bit_index > 7 {
            bytes_out[byte_index] = temp as u8;
            temp = temp >> 8;
            byte_index += 1;
            bit_index -= 8;
        }
    }
}


/// Algorithm 12 SimpleBitUnpack(v, b) on page 23.
/// Reverses the procedure SimpleBitPack.
/// This function has been optimized, but remains under test alongside the original logic.
pub(crate) fn simple_bit_unpack(v: &[u8], b: u32) -> Result<R, &'static str> {
    // Input: b ∈ N and a byte string v of length 32 · bitlen b.
    // Output: A polynomial w ∈ R, with coeffcients in [0, 2^c−1], where c = bitlen b.
    // When b + 1 is a power of 2, the coeffcients are in [0, b].
    let bitlen = (b.ilog2() + 1) as usize;
    debug_assert_eq!(v.len(), 32 * bitlen);
    let mut w_out = [0i32; 256];

    // 1: c ← bitlen b
    let c = bitlen;

    // 2: z ← BytesToBits(v)
    let mut z = vec![false; 8 * v.len()];
    bytes_to_bits(v, &mut z);

    // 3: for i from 0 to 255 do
    for i in 0..=255 {
        //
        // 4: wi ← BitsToInteger((z[ic], z[ic + 1], . . . z[ic + c − 1]), c)
        w_out[i] = bits_to_integer(&z[i * c..(i + 1) * c]);
        //
    } // 5: end for
    debug_assert!(w_out
        .iter()
        .all(|e| ((*e >= 0) & (*e <= 2i32.pow(c as u32) - 1)))); // Correct range

    // Test...
    let mut w_tst = [0i32; 256];
    bit_unpack2(v, 0, b, &mut w_tst);
    assert_eq!(w_out, w_tst);

    if w_out // 6: return w
        .iter()
        .all(|e| (*e >= 0) & (*e <= 2i32.pow(bitlen as u32) - 1))
    {
        return Ok(w_out);
    } else {
        return Err("Invalid simple_bit_unpack deserialization");
    }
}


/// Algorithm 13 BitUnpack(v, a, b) on page 23.
/// Reverses the procedure BitPack.
pub(crate) fn bit_unpack(v: &[u8], a: u32, b: u32) -> Result<R, &'static str> {
    // Input: a, b ∈ N and a byte string v of length 32 · bitlen (a + b).
    // Output: A polynomial w ∈ R, with coeffcients in [b − 2^c + 1, b], where c = bitlen (a + b).
    let bitlen = ((a + b).ilog2() + 1) as usize;
    debug_assert_eq!(v.len(), 32 * bitlen);
    let mut w_out = [0i32; 256];
    // When a + b + 1 is a power of 2, the coeffcients are in [−a, b].

    // 1: c ← bitlen (a + b)
    let c = bitlen;

    // 2: z ← BytesToBits(v)
    let mut z = vec![false; v.len() * 8];
    bytes_to_bits(&v, &mut z);

    // 3: for i from 0 to 255 do
    for i in 0..=255 {
        //
        // 4: wi ← b − BitsToInteger((z[ic], z[ic + 1], . . . z[ic + c − 1]), c)
        w_out[i] = b as i32 - bits_to_integer(&z[i * c..c * (i + 1)]);
        //
    } // 5: end for


    // Test...
    let mut w_tst = [0i32; 256];
    bit_unpack2(v, a, b, &mut w_tst);
    assert_eq!(w_out, w_tst);

    if w_out
        .iter()
        .all(|e| ((*e >= -(a as i32)) & (*e <= b as i32)))
    {
        return Ok(w_out);
    } else {
        return Err("Invalid bit_unpack deserialization");
    }
} // 6: return w


// TODO: revisit validation responsibilities (put into initial fn?)
pub(crate) fn bit_unpack2(v: &[u8], a: u32, b: u32, w_out: &mut R) {
    debug_assert!((a < u32::MAX / 4) & (b < u32::MAX / 4) & (b >= a)); // Ensure some headroom
    let bitlen = ((a + b).ilog2() + 1) as usize; // Calculate element bit length
    debug_assert_eq!(v.len() * 8, w_out.len() * bitlen); // correct size
    let mut temp = 0u64;
    let mut r_index = 0;
    let mut bit_index = 0;
    for byte in v.iter() {
        temp = temp | (*byte as u64) << bit_index;
        bit_index += 8;
        while bit_index >= bitlen {
            let tmask = temp & (2u64.pow(bitlen as u32) - 1);
            //let tmask = tmask as u32 % (a + b);
            w_out[r_index] = if a != 0 {
                b as i32 - tmask as i32
            } else {
                tmask as i32
            };
            bit_index -= bitlen;
            temp = temp >> bitlen;
            r_index += 1;
        }
    }
}


/// Algorithm 14 HintBitPack(h) on page 24.
/// Encodes a polynomial vector h with binary coeffcients into a byte string.
pub(crate) fn hint_bit_pack<const K: usize, const OMEGA: usize>(h: &[R; K], y_bytes: &mut [u8]) {
    // Input: A polynomial vector h ∈ R^k_2 such that at most ω of the coeffcients in h are equal to 1.
    // Output: A byte string y of length ω + k.
    let k = h.len();
    debug_assert_eq!(y_bytes.len(), OMEGA + k);
    debug_assert!(h
        .iter()
        .all(|&r| r.iter().filter(|&&e| e == 1).sum::<i32>() <= OMEGA as i32));

    // 1: y ∈ Bω+k ← 0ω+k
    y_bytes.iter_mut().for_each(|e| *e = 0);

    // 2: Index ← 0
    let mut index = 0;

    // 3: for i from 0 to k − 1 do
    for i in 0..=(k - 1) {
        //
        // 4: for j from 0 to 255 do
        for j in 0..=255 {
            //
            // 5: if h[i]_j != 0 then
            if h[i][j] != 0 {
                //
                // 6: y[Index] ← j      ▷ Store the locations of the nonzero coeffcients in h[i]
                y_bytes[index] = j as u8;

                // 7: Index ← Index + 1
                index += 1;
                //
            } // 8: end if
        } // 9: end for

        // 10: y[ω + i] ← Index ▷ Store the value of Index after processing h[i]
        y_bytes[OMEGA + i] = index as u8;
        //
    } // 11: end for
} // 12: return y


/// Algorithm 15 HintBitUnpack(y) on page 24.
///Reverses the procedure HintBitPack.
pub(crate) fn hint_bit_unpack<const K: usize, const OMEGA: usize>(
    y_bytes: &[u8], h: &mut Option<[R; K]>,
) {
    // Input: A byte string y of length ω + k.
    // Output: A polynomial vector h ∈ R^k_2 or ⊥.
    debug_assert_eq!(y_bytes.len(), OMEGA + K);

    // 1: h ∈ R^k_2 ∈ ← 0^k
    let mut hh = [[0i32; 256]; K];

    // 2: Index ← 0
    let mut index = 0;

    // 3: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        //
        // 4: if y[ω + i] < Index or y[ω + i] > ω then return ⊥
        if (y_bytes[OMEGA + i] < index) | (y_bytes[OMEGA + i] > OMEGA as u8) {
            *h = None;
            return;
            //
        } // 5: end if

        // 6: while Index < y[ω + i] do
        while index < y_bytes[OMEGA + i] {
            //
            // 7: h[i]y[Index] ← 1
            hh[i][y_bytes[index as usize] as usize] = 1;

            // 8: Index ← Index + 1
            index += 1;
            //
        } // 9: end while
    } // 10: end for

    // 11: while Index < ω do
    while index < OMEGA as u8 {
        //
        // 12: if y[Index] != 0 then return ⊥
        if y_bytes[index as usize] != 0 {
            *h = None;
            return;
            //
        } // 13: end if

        // 14: Index ← Index + 1
        index += 1;
        //
    } // 15: end while
    *h = Some(hh);
} // 16: return h


#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_integers_and_bits_roundtrip() {
        // Round trip for random u32
        let random_i32 = random::<i32>();
        let mut bits = [false; 32];
        integer_to_bits(random_i32, 32, &mut bits);
        let res = bits_to_integer(&bits);
        assert_eq!(random_i32, res);

        // Round trip for random 14 bits
        let random_bits = random::<[bool; 14]>();
        let int = bits_to_integer(&random_bits);
        let mut res = [false; 14];
        integer_to_bits(int, 14, &mut res);
        assert_eq!(random_bits, res);
    }

    #[test]
    #[should_panic]
    fn test_integers_to_bits_validation() {
        let mut bits = [false; 12];
        integer_to_bits(44, 32, &mut bits);
    }

    #[test]
    #[should_panic]
    fn test_bits_to_integer_validation() {
        let mut bits = [false; 33];
        bits_to_integer(&mut bits);
    }

    #[test]
    fn test_bits_and_bytes_roundtrip() {
        // Round trip for 10 random bytes
        let random_bytes = random::<[u8; 10]>();
        let mut bits = [false; 80];
        bytes_to_bits(&random_bytes, &mut bits);
        let mut res = [0u8; 10];
        bits_to_bytes(&bits, &mut res);
        assert_eq!(random_bytes, res);
    }

    #[test]
    #[should_panic]
    fn test_bits_to_bytes_validation1() {
        let bits = [false; 12];
        let mut bytes = [0];
        bits_to_bytes(&bits, &mut bytes);
    }

    #[test]
    #[should_panic]
    fn test_bits_to_bytes_validation2() {
        let bits = [false; 16];
        let mut bytes = [0];
        bits_to_bytes(&bits, &mut bytes);
    }

    #[test]
    #[should_panic]
    fn test_bytes_to_bits_validation1() {
        let mut bits = [false; 12];
        let bytes = [0];
        bytes_to_bits(&bytes, &mut bits);
    }

    #[test]
    #[should_panic]
    fn test_bytes_to_bits_validation2() {
        let mut bits = [false; 16];
        let bytes = [0];
        bytes_to_bits(&bytes, &mut bits);
    }

    #[test]
    fn test_coef_from_three_bytes1() {
        let bytes = [0x12u8, 0x34, 0x56];
        let res = coef_from_three_bytes(&bytes).unwrap();
        assert_eq!(res, 0x563412);
    }

    #[test]
    fn test_coef_from_three_bytes2() {
        let bytes = [0x12u8, 0x34, 0x80];
        let res = coef_from_three_bytes(&bytes).unwrap();
        assert_eq!(res, 0x003412);
    }

    #[test]
    fn test_coef_from_three_bytes3() {
        let bytes = [0x01u8, 0xe0, 0x80];
        let res = coef_from_three_bytes(&bytes).unwrap();
        assert_eq!(res, 0x00e001);
    }

    #[test]
    #[should_panic]
    fn test_coef_from_three_bytes4() {
        let bytes = [0x01u8, 0xe0, 0x7f];
        let res = coef_from_three_bytes(&bytes).unwrap();
        assert_eq!(res, 0x563412);
    }

    #[test]
    fn test_coef_from_half_byte1() {
        let inp = 3;
        let res = coef_from_half_byte::<2>(inp).unwrap();
        assert_eq!(-1, res);
    }

    #[test]
    fn test_coef_from_half_byte2() {
        let inp = 8;
        let res = coef_from_half_byte::<4>(inp).unwrap();
        assert_eq!(-4, res);
    }

    #[test]
    #[should_panic]
    fn test_coef_from_half_byte_validation1() {
        let inp = 22;
        let _res = coef_from_half_byte::<2>(inp);
    }

    #[test]
    #[should_panic]
    fn test_coef_from_half_byte_validation2() {
        let inp = 15;
        let _res = coef_from_half_byte::<2>(inp).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_coef_from_half_byte_validation3() {
        let inp = 10;
        let _res = coef_from_half_byte::<4>(inp).unwrap();
    }

    #[test]
    fn test_simple_bit_pack_roundtrip() {
        // Round trip for 32 * 6(bitlen) bytes
        let random_bytes: Vec<u8> = (0..32 * 6).map(|_| rand::random::<u8>()).collect();
        let r = simple_bit_unpack(&random_bytes, 2u32.pow(6) - 1).unwrap();
        let mut res = [0u8; 32 * 6];
        simple_bit_pack(&r, 2u32.pow(6) - 1, &mut res);
        assert_eq!(random_bytes, res);
    }

    #[test]
    #[should_panic]
    fn test_simple_bit_unpack_validation1() {
        // wrong size of bytes
        let random_bytes: Vec<u8> = (0..32 * 7).map(|_| rand::random::<u8>()).collect();
        let r = simple_bit_unpack(&random_bytes, 2u32.pow(6) - 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_bit_unpack_validation1() {
        // wrong size of bytes
        let random_bytes: Vec<u8> = (0..32 * 7).map(|_| rand::random::<u8>()).collect();
        let _r = bit_unpack(&random_bytes, 0, 2u32.pow(6) - 1);
    }

    #[test]
    #[should_panic]
    fn test_simple_bit_pack_validation1() {
        // wrong size of bytes
        let mut random_bytes: Vec<u8> = (0..32 * 7).map(|_| rand::random::<u8>()).collect();
        let r = [0i32; 256];
        simple_bit_pack(&r, 2u32.pow(6) - 1, &mut random_bytes);
    }

    #[test]
    #[should_panic]
    fn test_simple_bit_pack_validation2() {
        let mut random_bytes: Vec<u8> = (0..32 * 7).map(|_| rand::random::<u8>()).collect();
        // wrong size r coeff
        let r = [1024i32; 256];
        simple_bit_pack(&r, 2u32.pow(6) - 1, &mut random_bytes);
    }

    // TODO: reword to start with bit_pack..
    // #[test]
    // fn test_bit_pack_roundtrip() {
    //     // Round trip for 32 * 6(bitlen) bytes
    //     let random_bytes: Vec<u8> = (0..32 * 6).map(|_| rand::random::<u8>()).collect();
    //     let mut r = bit_unpack(&random_bytes, 2u32.pow(2), 2u32.pow(6) - 2u32.pow(2) - 1).unwrap();
    //     let mut res = [0u8; 32 * 6];
    //     bit_pack(&r, 2u32.pow(2), 2u32.pow(6) - 2u32.pow(2) - 1, &mut res);
    //     assert_eq!(random_bytes, res);
    // }

    // TODO test hint_bit_pack and hint_bit_unpack
}
