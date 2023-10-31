pub fn check() { println!("check!\n") }

const Q: u32 = 2u32.pow(23) - 2u32.pow(13) + 1;


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
pub(crate) fn coef_from_three_bytes(bbb: [u8; 3]) -> u32 {
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
    // 6: 6: else return ⊥
    // 7: end if
    assert!(z < Q);
    z
}


/// Algorithm 9 CoefFromHalfByte(b) on page 22.
/// Generates an element of {−η,−η + 1, . . . , η} ∪ {⊥}.
pub(crate) fn coef_from_half_byte<const ETA: usize>(b: u8) -> i8 {
    // Input: Integer b ∈{0, 1, . . . , 15}.
    // Output: An integer between −η and η, or ⊥.
    // 1: if η = 2 and b < 15 then return 2− (b mod 5)
    debug_assert!(b < 15);
    if (ETA == 2) & (b < 15) {
        return 2 - (b as i8 % 5);
    } else {
        // else
        // 3: if η = 4 and b < 9 then return 4 − b
        if (ETA == 4) & (b < 9) {
            return 4 - b as i8;
        } else {
            // 4: else return ⊥
            panic!()
        } // 5: end if
    } // 6: end if
}


/// Algorithm 10 SimpleBitPack(w, b) on page 22
/// Encodes a polynomial w into a byte string.
pub(crate) fn simple_bit_pack(w: &[u32; 256], b: u32, bytes: &mut [u8]) {
    // Input: b ∈ N and w ∈ R such that the coeffcients of w are all in [0, b].
    // Output: A byte string of length 32 · bitlen b.
    w.iter().for_each(|element| debug_assert!(*element <= b));
    debug_assert_eq!(bytes.len(), 32 * b as usize);
    let bitlen = (b.ilog2() + 1) as usize;
    // 1: z ← ()        ▷ set z to the empty string
    let mut z = vec![false; bitlen]; // TODO: global buffer?
                                     // 2: for i from 0 to 255 do
    for i in 0..256 {
        // 3: z ← z||IntegerToBits(wi, bitlen b)
        integer_to_bits(w[i], bitlen, &mut z[i * bitlen..(i + 1) * bitlen]);
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
        integer_to_bits((b - w[i] as u32), bitlen, &mut z[i * bitlen..(i + 1) * bitlen]);
    } // 4: end for
      // 5: return BitsToBytes(z)
    bits_to_bytes(&z, bytes_out)
}


/// Algorithm 12 SimpleBitUnpack(v, b) on page 23.
///Reverses the procedure SimpleBitPack.
pub(crate) fn simple_bit_unpack(v: &[u8], b: u32, w: &mut [u32; 256]) {
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
        w[i] = bits_to_integer(&z[i * c..(i + 1) * c]);
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
            if h[i] == false { // TODO
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
    let mut h = vec![false; K];
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
            h[i] = true; //[index] = 1;  TODO: broken
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
