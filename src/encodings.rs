use crate::helpers::bitlen;
use crate::types::{Zero, R};
use crate::{
    conversion::{
        bit_pack, bit_unpack, hint_bit_pack, hint_bit_unpack, simple_bit_pack, simple_bit_unpack,
    },
    D, QU,
};

// This file implements functionality from FIPS 204 section 8.2 Encodings of ML-DSA Keys and Signatures


/// Algorithm 16 pkEncode(ρ, t1) on page 25
/// Encodes a public key for ML-DSA into a byte string.
pub(crate) fn pk_encode<const K: usize, const PK_LEN: usize>(
    p: &[u8; 32], t1: &[R; K],
) -> [u8; PK_LEN] {
    // Input:ρ ∈ {0, 1}^256, t1 ∈ Rk with coefficients in [0, 2^{bitlen(q−1) − d} - 1]).
    // Output: Public key pk ∈ B^{32+32k(bitlen (q−1)−d)}.
    let bl = bitlen(QU as usize - 1) - D as usize;
    let mut pk = [0u8; PK_LEN];

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
    pk // 5: return pk
}


/// Algorithm 17 pkDecode(pk) on page 25.
/// Reverses the procedure pkEncode.
pub(crate) fn pk_decode<const K: usize, const PK_LEN: usize>(
    pk: &[u8; PK_LEN],
) -> Result<([u8; 32], [R; K]), &'static str> {
    // Input: Public key pk ∈ B^{32+32k(bitlen(q−1)−d)}.
    // Output: ρ ∈ {0, 1}^256, t1 ∈ R^k with coeffcients in [0, 2^{bitlen(q−1)−d} − 1]).
    let bl = bitlen(QU as usize - 1) - D as usize;
    debug_assert_eq!(pk.len(), 32 + 32 * K * bl);
    let (mut rho, mut t1): ([u8; 32], [R; K]) = ([0u8; 32], [R::zero(); K]);

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
    Ok((rho, t1)) // 6: return (ρ, t1 )
}


/// Algorithm 18 skEncode(ρ, K,tr, s1, s2, t0) on page 26.
/// Encodes a secret key for ML-DSA into a byte string.
pub fn sk_encode<
    const D: usize,
    const ETA: usize,
    const K: usize,
    const L: usize,
    const SK_LEN: usize,
>(
    rho: &[u8; 32], k: &[u8; 32], tr: &[u8; 64], s1: &[R; L], s2: &[R; K], t0: &[R; K],
) -> [u8; SK_LEN] {
    // Input: ρ ∈ {0,1}^256, K ∈ {0,1}^256, tr ∈ {0,1}^512,
    //        s1 ∈ R^l with coefficients in [−η, η],
    //        s2 ∈ R^k with coefficients in [−η η],
    //        t0 ∈ R^k with coefficients in [−2^{d-1} + 1, 2^{d-1}].
    // Output: Private key, sk ∈ B^{32+32+64+32·((k+ℓ)·bitlen(2η)+dk)}
    let mut sk = [0u8; SK_LEN];

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
    sk
}


/// Algorithm 19 skDecode(sk) on page 27.
/// Reverses the procedure skEncode.
pub(crate) fn sk_decode<
    const D: usize,
    const ETA: usize,
    const K: usize,
    const L: usize,
    const SK_LEN: usize,
>(
    sk: &[u8; SK_LEN],
) -> Result<([u8; 32], [u8; 32], [u8; 64], [R; L], [R; K], [R; K]), &'static str> {
    // Input: Private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}
    // Output: ρ ∈ {0,1}^256, K ∈ ∈ {0,1}^256, tr ∈ ∈ {0,1}^512,
    // s1 ∈ R^ℓ, s2 ∈ R^k, t0 ∈ R^k with coefficients in [−2^{d−1} + 1, 2^{d−1}].
    let bl = bitlen(2 * ETA);
    //debug_assert_eq!(sk.len(), 32 + 32 + 64 + 32 * ((L + K) * bl + D * K));
    let (mut rho, mut k, mut tr) = ([0u8; 32], [0u8; 32], [0u8; 64]);
    let (mut s1, mut s2, mut t0) = ([R::zero(); L], [R::zero(); K], [R::zero(); K]);

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
        return Ok((rho, k, tr, s1, s2, t0));
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
        let mut random_pk = [0u8; 1312];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 4];
        let (rho, t1) = pk_decode::<4, 1312>(&random_pk).unwrap();
        //let mut res = [0u8; 1312];
        let res = pk_encode::<4, 1312>(&rho, &t1);
        assert_eq!(&random_pk[..], res);
    }

    #[test]
    fn test_pk_encode_decode_roundtrip2() {
        // D=13 K=6 PK_LEN=1952
        let mut random_pk = [0u8; 1952];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 6];
        let (rho, t1) = pk_decode::<6, 1952>(&random_pk.try_into().unwrap()).unwrap();
        //let mut res = [0u8; 1952];
        let res = pk_encode::<6, 1952>(&rho, &t1);
        assert_eq!(random_pk, res);
    }

    #[test]
    fn test_pk_encode_decode_roundtrip3() {
        // D=13 K=8 PK_LEN=2592
        let mut random_pk = [0u8; 2592];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        let mut rho = [0u8; 32];
        let mut t1 = [[0i32; 256]; 8];
        let (rho, t1) = pk_decode::<8, 2592>(&random_pk.try_into().unwrap()).unwrap();
        //let mut res = [0u8; 2592];
        let res = pk_encode::<8, 2592>(&rho, &t1);
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
        let sk = sk_encode::<13, 2, 4, 4, 2560>(&rho, &k, &tr, &s1, &s2, &t0);
        let res = sk_decode::<13, 2, 4, 4, 2560>(&sk);
        assert!(res.is_ok());
        let (rho_test, k_test, tr_test, s1_test, s2_test, t0_test) = res.unwrap();

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
        sigma = sig_encode::<{ 2usize.pow(17) }, 4, 4, 128, 80, 2420>(&c_tilde, &z, &h);
        let mut c_test = [0u8; 2 * 128 / 8];
        let mut z_test = [[0i32; 256]; 4];
        let mut h_test = [[0i32; 256]; 4];
        let (c_test, z_test, h_test) =
            sig_decode::<{ 2usize.pow(17) }, 4, 4, 128, 80>(&sigma).unwrap();
        //        assert!(res.is_ok());
        assert_eq!(c_tilde[0..8], c_test[0..8]);
        assert_eq!(z, z_test);
        assert_eq!(h, h_test.unwrap());
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
    const SIG_LEN: usize,
>(
    c_tilde: &[u8], z: &[R; L], h: &[R; K],
) -> [u8; SIG_LEN] {
    // Input: c_tilde ∈ {0,1}^2λ, z ∈ R^ℓ with coeffcients in [−1*γ_1 + 1, γ_1], h ∈ R^k_2.
    // Output: Signature, σ ∈ B^{λ/4 +l*32*(1+bitlen(γ_1 - 1)+ω+k}
    let mut sigma = [0u8; SIG_LEN];
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
    sigma
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
    sigma: &[u8],
) -> Result<([u8; 32], [R; L], Option<[R; K]>), &'static str> {
    // Input: Signature, σ ∈ B^{λ/4+ℓ·32·(1+bitlen (γ_1-1))+ω+k
    // Output: c_tilde ∈ {0,1}^2λ, z ∈ R^ℓ_q with coefficients in [−γ_1 + 1, γ1], h ∈ R^k_2 or ⊥.
    // Note: c_tilde is hardcoded to 256bits since the remainder is 'soon' discarded
    let bl = bitlen(GAMMA1 - 1);
    let (mut c_tilde, mut z, mut h): ([u8; 32], [R; L], Option<[R; K]>) =
        ([0u8; 32], [R::zero(); L], None::<[R; K]>);

    // 1: (ω, x_0, ... , x_{ℓ−1}, y) ∈ B^{λ/4} × Bℓ·32·(1+bitlen(γ_1−1))+ω+k ← σ

    // 2: c_tilde ← BytesToBits(w)
    c_tilde.copy_from_slice(&sigma[0..32]); //LAMBDA / 4]);

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
    hint_bit_unpack::<K, OMEGA>(&sigma[start + L * step..], &mut h);

    // 7: return (c_tilde, z, h)
    Ok((c_tilde, z, h))
}


/// Algorithm 22 w1Encode(w1) on page 28.
/// Encodes a polynomial vector w1 into a bit string.
pub(crate) fn w1_encode<const K: usize, const GAMMA2: usize>(w1: &[R; K], w1_tilde: &mut [u8]) {
    // Input: w1 ∈ R^k with coefficients in [0, (q − 1)/(2γ_2) − 1].
    // Output: A bit string representation, w1_tilde ∈ {0,1}^{32k*bitlen((q-1)/(2γ2)−1).
    let qm12gm1 = (QU - 1) / (2 * GAMMA2 as u32) - 1;
    let bl = bitlen(qm12gm1 as usize);
    debug_assert!(w1
        .iter()
        .all(|r| r.iter().all(|&c| (c >= 0) & (c <= qm12gm1 as i32))));

    // 1: w1_tilde ← ()

    // 2: for i from 0 to k − 1 do
    let step = 32 * bl;
    for i in 0..=(K - 1) {
        //
        // 3: w1_tilde ← w1_tilde || BytesToBits (SimpleBitPack (w1[i], (q − 1)/(2γ2) − 1))
        simple_bit_pack(&w1[i], qm12gm1, &mut w1_tilde[i * step..(i + 1) * step]);
        //
    } // 4: end for
      //
} // 5: return w^tilde_1
