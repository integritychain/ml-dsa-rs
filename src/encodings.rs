use crate::helpers::bitlen;
use crate::types::R;
use crate::{
    conversion::{
        bit_pack, bit_unpack, bytes_to_bits, hint_bit_pack, hint_bit_unpack, simple_bit_pack,
        simple_bit_unpack,
    },
    QU,
};

// This file implements functionality from FIPS 204 section 8.2 Encodings of ML-DSA Keys and Signatures


/// Algorithm 16 pkEncode(ρ, t1) on page 25
/// Encodes a public key for ML-DSA into a byte string.
pub(crate) fn pk_encode<const D: usize, const K: usize>(p: &[u8; 32], t1: &[R; K], pk: &mut [u8]) {
    // Input:ρ ∈ {0, 1}^256, t1 ∈ Rk with coefficients in [0, 2^{bitlen(q−1) − d} - 1]).
    // Output: Public key pk ∈ B^{32+32k(bitlen (q−1)−d)}.
    let bl = bitlen(QU as usize - 1) - D;
    debug_assert_eq!(pk.len(), 32 + 32 * K * bl);

    // 1: pk ← BitsToBytes(ρ)
    pk[0..32].copy_from_slice(p);

    // 2: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        //
        // 3: pk ← pk || SimpleBitPack (t1[i], 2^{bitlen(q−1)−d}-1)
        // simple_bit_pack(
        //     &t1[i],
        //     2u32.pow(bl as u32) - 1,
        //     &mut pk[32 + 32 * i * bl..32 + 32 * (i + 1) * bl],
        // );
        simple_bit_pack(
            &t1[i],
            2u32.pow(bl as u32) - 1,
            &mut pk[32 + 32 * i * bl..32 + 32 * (i + 1) * bl],
        );
    } // 4: end for
} // 5: return pk


/// Algorithm 17 pkDecode(pk) on page 25.
/// Reverses the procedure pkEncode.
pub(crate) fn pk_decode<const D: usize, const K: usize>(
    pk: &[u8], rho: &mut [u8; 32], t1: &mut [R; K],
) -> Result<(), &'static str> {
    // Input: Public key pk ∈ B^{32+32k(bitlen(q−1)−d)}.
    // Output: ρ ∈ {0, 1}^256, t1 ∈ R^k with coeffcients in [0, 2^{bitlen(q−1)−d} − 1]).
    let bl = bitlen(QU as usize - 1) - D;
    debug_assert_eq!(pk.len(), 32 + 32 * K * bl);

    // 1: (y, z_0 , . . . , z_{k−1}) ∈ B^{32} × (B^{32(bitlen(q−1)−d))^k} ← pk
    //    pull out these fields below

    // 2: ρ ← BytesToBits(y)
    rho.copy_from_slice(&pk[0..32]);

    // 3: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        //
        // 4: t1[i] ← SimpleBitUnpack(zi, 2^{bitlen(q−1)−d} − 1)) ▷ This is always in the correct range
        t1[i] = simple_bit_unpack(
            &pk[32 + 32 * i * bl..32 + 32 * (i + 1) * bl],
            2u32.pow(bl as u32) - 1,
        )?;
        //
    } // 5: end for
    debug_assert!(t1
        .iter()
        .all(|r| r.iter().all(|e| (*e >= 0) & (*e < 2i32.pow(bl as u32)))));
    Ok(()) // 6: return (ρ, t1 )
}


/// Algorithm 18 skEncode(ρ, K,tr, s1, s2, t0) on page 26.
/// Encodes a secret key for ML-DSA into a byte string.
pub fn sk_encode<const D: usize, const ETA: usize, const K: usize, const L: usize>(
    rho: &[u8; 32], k: &[u8; 32], tr: &[u8; 64], s1: &[R; L], s2: &[R; K], t0: &[R; K],
    sk: &mut [u8],
) {
    // Input: ρ ∈ {0,1}^256, K ∈ {0,1}^256, tr ∈ {0,1}^512,
    //        s1 ∈ R^l with coefficients in [−η, η],
    //        s2 ∈ R^k with coefficients in [−η η],
    //        t0 ∈ R^k with coefficients in [−2^{d-1} + 1, 2^{d-1}].
    // Output: Private key, sk ∈ B^{32+32+64+32·((k+ℓ)·bitlen(2η)+dk)}
    let (c_min, c_max) = (-1 * ETA as i32, ETA as i32);
    debug_assert!(s1
        .iter()
        .all(|r| r.iter().all(|c| (*c >= c_min) & (*c <= c_max))));
    debug_assert!(s2
        .iter()
        .all(|r| r.iter().all(|c| (*c >= c_min) & (*c <= c_max))));
    let (c_min, c_max) = (-1 * 2i32.pow(D as u32 - 1) + 1, 2i32.pow(D as u32 - 1));
    debug_assert!(t0
        .iter()
        .all(|r| r.iter().all(|c| (*c >= c_min) & (*c <= c_max))));
    debug_assert_eq!(sk.len(), 32 + 32 + 64 + 32 * ((K + L) * bitlen(2 * ETA) + D * K));

    // 1: sk ← BitsToBytes(ρ) || BitsToBytes(K) || BitsToBytes(tr)
    sk[0..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(k);
    sk[64..128].copy_from_slice(tr);

    // 2: for i from 0 to ℓ − 1 do
    let start = 128;
    let step = 32 * bitlen(2 * ETA);
    for i in 0..=(L - 1) {
        //
        // 3: sk ← sk || BitPack (s1[i], η, η)
        bit_pack(
            &s1[i],
            ETA as u32,
            ETA as u32,
            &mut sk[start + i * step..start + (i + 1) * step],
        );
        //
    } // 4: end for
      //
      // 5: for i from 0 to k − 1 do
    let start = start + L * step;
    for i in 0..=(K - 1) {
        //
        // 6: sk ← sk || BitPack (s2[i], η, η)
        bit_pack(
            &s2[i],
            ETA as u32,
            ETA as u32,
            &mut sk[start + i * step..start + (i + 1) * step],
        );
        //
    } // 7: end for

    // 8: for i from 0 to k − 1 do
    let start = start + K * step;
    let step = 32 * D; //((2u32.pow(D as u32 - 1)).ilog2() as usize + 1);
    for i in 0..=(K - 1) {
        //
        // 9: sk ← sk || BitPack (t0[i], [−2^{d-1} + 1, 2^{d-1}] )
        bit_pack(
            &t0[i],
            2u32.pow(D as u32 - 1) - 1, // orginally a negative# + 1; now positive # - 1
            2u32.pow(D as u32 - 1),
            &mut sk[start + i * step..start + (i + 1) * step],
        );
        //
    } // 10: end for
    debug_assert_eq!(start + K * step, sk.len());
}


/// Algorithm 19 skDecode(sk) on page 27.
/// Reverses the procedure skEncode.
pub(crate) fn sk_decode<const D: usize, const ETA: usize, const K: usize, const L: usize>(
    sk: &[u8], rho: &mut [u8; 32], k: &mut [u8; 32], tr: &mut [u8; 64], s1: &mut [R; L],
    s2: &mut [R; K], t0: &mut [R; K],
) -> Result<(), &'static str> {
    // Input: Private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}
    // Output: ρ ∈ {0,1}^256, K ∈ ∈ {0,1}^256, tr ∈ ∈ {0,1}^512,
    // s1 ∈ R^ℓ, s2 ∈ R^k, t0 ∈ R^k with coefficients in [−2^{d−1} + 1, 2^{d−1}].
    let bl = bitlen(2 * ETA);
    debug_assert_eq!(sk.len(), 32 + 32 + 64 + 32 * ((L + K) * bl + D * K));


    // 1: (f, g, h, y_0, . . . , y_{ℓ−1}, z_0, . . . , z_{k−1}, w_0, . . . , w_{k−1)}) ∈
    //    B^32 × B^32 × B^64 × B^{32·bitlen(2η)}^l × B^{32·bitlen(2η)}^k × B^{32d}^k ← sk
    //    pull out these fields below

    // 2: ρ ← BytesToBits( f )
    rho.copy_from_slice(&sk[0..32]);

    // 3: K ← BytesToBits(g)
    k.copy_from_slice(&sk[32..64]);

    // 4: tr ← BytesToBits(h)
    tr.copy_from_slice(&sk[64..128]);

    // 5: for i from 0 to ℓ − 1 do
    let start = 128;
    let step = 32 * bl;
    for i in 0..=(L - 1) {
        //
        // 6: s1[i] ← BitUnpack(yi, η, η)   ▷ This may lie outside [−η, η], if input is malformed
        s1[i] = bit_unpack(&sk[start + i * step..start + (i + 1) * step], ETA as u32, ETA as u32)?;
        //
    } // 7: end for

    // 8: for i from 0 to k − 1 do
    let start = start + L * step;
    for i in 0..=(K - 1) {
        //
        // 9: s2[i] ← BitUnpack(zi, η, η) ▷ This may lie outside [−η, η], if input is malformed
        s2[i] = bit_unpack(&sk[start + i * step..start + (i + 1) * step], ETA as u32, ETA as u32)?;
        //
    } // 10: end for

    // 11: for i from 0 to k − 1 do
    let start = start + K * step;
    let step = 32 * D;
    for i in 0..=(K - 1) {
        //
        // 12: t0[i] ← BitUnpack(wi, −2^{d−1} - 1, 2^{d−1})   ▷ This is always in the correct range
        t0[i] = bit_unpack(
            &sk[start + i * step..start + (i + 1) * step],
            2u32.pow(D as u32 - 1) - 1,
            2u32.pow(D as u32 - 1),
        )?;
        //
    } // 13: end for
    debug_assert_eq!(start + K * step, sk.len());

    // Note spec is not consistent on the range constraints for s1 and s2; this is tighter
    let (c_min, c_max) = (-1 * ETA as i32, ETA as i32);
    let s1_ok = s1
        .iter()
        .all(|r| r.iter().all(|c| (*c >= c_min) & (*c <= c_max)));
    let s2_ok = s2
        .iter()
        .all(|r| r.iter().all(|c| (*c >= c_min) & (*c <= c_max)));
    let (c_min, c_max) = (-1 * 2i32.pow(D as u32 - 1) + 1, 2i32.pow(D as u32 - 1));
    let t0_ok = t0
        .iter()
        .all(|r| r.iter().all(|c| (*c >= c_min) & (*c <= c_max)));
    if s1_ok & s2_ok & t0_ok {
        return Ok(());
    } else {
        return Err("Invalid sk_decode deserialization");
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pk_encode_decode_roundtrip1() {
        // D=13 K=4 PK_LEN=1312
        let random_pk: Vec<u8> = (0..1312).map(|_| rand::random::<u8>()).collect();
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 4];
        pk_decode::<13, 4>(&random_pk, &mut rho, &mut t1);
        let mut res = [0u8; 1312];
        pk_encode::<13, 4>(&rho, &t1, &mut res);
        assert_eq!(random_pk, res);
    }

    #[test]
    fn test_pk_encode_decode_roundtrip2() {
        // D=13 K=6 PK_LEN=1952
        let random_pk: Vec<u8> = (0..1952).map(|_| rand::random::<u8>()).collect();
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 6];
        pk_decode::<13, 6>(&random_pk, &mut rho, &mut t1);
        let mut res = [0u8; 1952];
        pk_encode::<13, 6>(&rho, &t1, &mut res);
        assert_eq!(random_pk, res);
    }

    #[test]
    fn test_pk_encode_decode_roundtrip3() {
        // D=13 K=8 PK_LEN=2592
        let random_pk: Vec<u8> = (0..2592).map(|_| rand::random::<u8>()).collect();
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 8];
        pk_decode::<13, 8>(&random_pk, &mut rho, &mut t1);
        let mut res = [0u8; 2592];
        pk_encode::<13, 8>(&rho, &t1, &mut res);
        assert_eq!(random_pk, res);
    }

    fn get_vec(max: u32) -> [i32; 256] {
        let mut rnd_r = [0i32; 256];
        rnd_r
            .iter_mut()
            .for_each(|e| *e = rand::random::<i32>().rem_euclid(max as i32));
        rnd_r
    }

    #[test]
    fn test_sk_encode_decode_roundtrip1() {
        // TODO: figure out how to best test this correctly
        //  - should the skDecode function return a result (probably)
        //  - double check the range of the input operands (most are +/- ETA, but last one is 2^d-1)
        //  - maybe need to rework one/two of the conversion functions in a similar fashion

        // D=13 ETA=2 K=4 L=4 SK_LEN=2560
        let (mut rho, mut k) = (rand::random::<[u8; 32]>(), rand::random::<[u8; 32]>());
        let mut tr = [0u8; 64];
        tr.iter_mut().for_each(|e| *e = rand::random::<u8>());
        let mut s1 = [get_vec(2), get_vec(2), get_vec(2), get_vec(2)];
        let mut s2 = [get_vec(2), get_vec(2), get_vec(2), get_vec(2)];
        let mut t0 = [
            get_vec(2u32.pow(11)),
            get_vec(2u32.pow(11)),
            get_vec(2u32.pow(11)),
            get_vec(2u32.pow(11)),
        ];
        let mut sk = [0u8; 2560];
        sk_encode::<13, 2, 4, 4>(&rho, &k, &tr, &s1, &s2, &t0, &mut sk);
        let (mut rho_test, mut k_test, mut tr_test) = ([0u8; 32], [0u8; 32], [0u8; 64]);
        let mut tr_test = [0u8; 64];
        let mut s1_test = [[0i32; 256]; 4];
        let mut s2_test = [[0i32; 256]; 4];
        let mut t0_test = [[0i32; 256]; 4];
        let res = sk_decode::<13, 2, 4, 4>(
            &sk,
            &mut rho_test,
            &mut k_test,
            &mut tr_test,
            &mut s1_test,
            &mut s2_test,
            &mut t0_test,
        );
        assert!(res.is_ok());
        assert!(
            (rho == rho_test)
                & (k == k_test)
                & (tr == tr_test)
                & (s1 == s1_test)
                & (s2 == s2_test)
                & (t0 == t0_test)
        );
    }

    #[test]
    fn test_sig_roundtrip() {
        // GAMMA1=2^17 K=4 L=4 LAMBDA=128 OMEGA=80
        let c_tilde: Vec<u8> = (0..2 * 128 / 8).map(|_| rand::random::<u8>()).collect();
        let z = [get_vec(2), get_vec(2), get_vec(2), get_vec(2)];
        let h = [get_vec(1), get_vec(1), get_vec(1), get_vec(1)];
        let mut sigma = [0u8; 2420];
        sig_encode::<{ 2usize.pow(17) }, 4, 4, 128, 80>(&c_tilde, &z, &h, &mut sigma);
        let mut c_test = [0u8; 2 * 128 / 8];
        let mut z_test = [[0i32; 256]; 4];
        let mut h_test = [[0i32; 256]; 4];
        let res = sig_decode::<{ 2usize.pow(17) }, 4, 4, 128, 80>(
            &sigma,
            &mut c_test,
            &mut z_test,
            &mut h_test,
        );
        assert!(res.is_ok());
        assert_eq!(c_tilde, c_test);
        assert_eq!(z, z_test);
        assert_eq!(h, h_test);
    }
}


/// Algorithm 20 sigEncode(c_tilde, z, h) on page 28.
/// Encodes a signature into a byte string.
pub(crate) fn sig_encode<
    const GAMMA1: usize,
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
>(
    c_tilde: &[u8], z: &[R; L], h: &[R; K], sigma: &mut [u8],
) {
    // Input: c_tilde ∈ {0,1}^2λ, z ∈ R^ℓ with coeffcients in [−1*γ_1 + 1, γ_1], h ∈ R^k_2.
    // Output: Signature, σ ∈ B^{λ/4 +l*32*(1+bitlen(γ_1 - 1)+ω+k}
    debug_assert_eq!(c_tilde.len(), 2 * LAMBDA / 8);
    let bl = bitlen(GAMMA1 - 1);
    debug_assert_eq!(sigma.len(), LAMBDA / 4 + L * 32 * (1 + bl) + OMEGA + K);

    // 1: σ ← BitsToBytes(c_tilde)
    //bits_to_bytes(&c_tilde, &mut sigma[..2 * LAMBDA * 8]);
    sigma[..2 * LAMBDA / 8].copy_from_slice(c_tilde);

    // 2: for i from 0 to ℓ − 1 do
    let start = 2 * LAMBDA / 8;
    let step = 32 * (1 + bl);
    for i in 0..=(L - 1) {
        //
        // 3: σ ← σ || BitPack (z[i], γ_1 − 1, γ_1)
        bit_pack(
            &z[i],
            GAMMA1 as u32 - 1,
            GAMMA1 as u32,
            &mut sigma[start + i * step..start + (i + 1) * step],
        );
        //
    } // 4: end for

    hint_bit_pack::<K, OMEGA>(h, &mut sigma[start + L * step..]);
    // 5: σ ← σ || HintBitPack (h)
}


/// Algorithm 21 sigDecode(σ) on page 28.
/// Reverses the procedure sigEncode.
pub(crate) fn sig_decode<
    const GAMMA1: usize,
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
>(
    sigma: &[u8], c_tilde: &mut [u8], z: &mut [R; L], h: &mut [R; K],
) -> Result<(), &'static str> {
    // Input: Signature, σ ∈ B^{λ/4+ℓ·32·(1+bitlen (γ_1-1))+ω+k
    // Output: c_tilde ∈ {0,1}^2λ, z ∈ R^ℓ_q with coefficients in [−γ_1 + 1, γ1], h ∈ R^k_2 or ⊥.
    let bl = bitlen(GAMMA1 - 1);

    // 1: (ω, x_0, ... , x_{ℓ−1}, y) ∈ B^{λ/4} × Bℓ·32·(1+bitlen(γ_1−1))+ω+k ← σ

    // 2: c_tilde ← BytesToBits(w)
    c_tilde.copy_from_slice(&sigma[0..LAMBDA / 4]);

    // 3: for i from 0 to ℓ − 1 do
    let start = LAMBDA / 4;
    let step = 32 * (bl + 1);
    for i in 0..=(L - 1) {
        //
        // 4: z[i] ← BitUnpack(xi, γ1 − 1, γ1) ▷ This is always in the correct range, as γ1 is a power of 2
        z[i] = bit_unpack(
            &sigma[start + i * step..start + (i + 1) * step],
            GAMMA1 as u32 - 1,
            GAMMA1 as u32,
        )?;
        //
    } // 5: end for

    // 6: h ← HintBitUnpack(y)
    let mut hh = Some([[0i32; 256]; K]);
    hint_bit_unpack::<K, OMEGA>(&sigma[start + L * step..], &mut hh);
    if hh.is_none() {
        return Err("Invalid hint_bit_unpack deserialization");
    }
    *h = hh.unwrap();

    // 7: return (c_tilde, z, h)
    Ok(())
}


/// Algorithm 22 w1Encode(w1) on page 28.
/// Encodes a polynomial vector w1 into a bit string.
pub(crate) fn w1_encode<const K: usize, const GAMMA2: u32>(w1: &[R; K], w1_tilde: &mut [u8]) {
    // Input: w1 ∈ R^k with coefficients in [0, (q − 1)/(2γ_2) − 1].
    // Output: A bit string representation, w1_tilde ∈ {0,1}^{32k*bitlen((q-1)/(2γ2)−1).

    // 1: w1_tilde ← ()
    let step = 32 * K * (((QU - 1) / (2 * GAMMA2 - 1)).ilog2() as usize + 1 - 1);
    // 2: for i from 0 to k − 1 do
    for i in 0..=(K - 1) {
        let mut bytes = vec![0u8; 4 * 8 * (((QU - 1) / (2 * (GAMMA2)) - 1).ilog2() as usize + 1)];
        // 3: w1_tilde ← w1_tilde || BytesToBits (SimpleBitPack (w1[i], (q − 1)/(2γ2) − 1))
        simple_bit_pack(&w1[i], ((QU - 1) / (2 * GAMMA2)) - 1, &mut bytes);
        //bytes_to_bits(&bytes, &mut w1_tilde[i * step..(i + 1) * step]);
        w1_tilde[i * bytes.len()..(i + 1) * bytes.len()].copy_from_slice(&bytes[..]);
    } // 4: end for
}
