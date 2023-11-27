use crate::algs::{inv_ntt, ntt, pow_mod_q};
//use crate::conversion::{bits_to_bytes, bytes_to_bits};
use crate::encodings::{pk_encode, sig_encode, sk_decode, sk_encode, w1_encode};
use crate::hashing::{expand_a, expand_mask, expand_s, h_xof, sample_in_ball};
use crate::helpers::bitlen;
use crate::high_low::{high_bits, low_bits, make_hint, power2round};
use crate::types::{R, T};
use crate::{D, QI, QU, ZETA};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;


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
            let tmp = multiply_ntts(&a_hat[i][j], &u_hat[j]);
            for k in 0..256 {
                w_hat[i][k] = (w_hat[i][k] + tmp[k]).rem_euclid(QI);
            }
        }
    }
    w_hat
}

/// Algorithm 10 `MultiplyNTTs(f, g)` on page 24 of FIPS 203.
/// Computes the product (in the ring Tq ) of two NTT representations.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn multiply_ntts(f_hat: &[i32; 256], g_hat: &[i32; 256]) -> [i32; 256] {
    // Input: Two arrays f_hat ∈ Z^{256}_q and g_hat ∈ Z^{256}_q        ▷ the coeffcients of two NTT representations
    // Output: An array h_hat ∈ Z^{256}_q                               ▷ the coeffcients of the product of the inputs
    let mut h_hat: [i32; 256] = [0; 256];

    // for (i ← 0; i < 128; i ++)
    for i in 0..128 {
        //
        // 2: (h_hat[2i], h_hat[2i + 1]) ← BaseCaseMultiply( f_hat[2i], f_hat[2i + 1], g_hat[2i], g_hat[2i + 1], ζ^{2BitRev7(i) + 1})
        let (h_hat_2i, h_hat_2ip1) = base_case_multiply(
            f_hat[2 * i],
            f_hat[2 * i + 1],
            g_hat[2 * i],
            g_hat[2 * i + 1],
            pow_mod_q(ZETA, 2 * ((i as u8).reverse_bits() >> 1) + 1),
        );
        h_hat[2 * i] = h_hat_2i;
        h_hat[2 * i + 1] = h_hat_2ip1;
    } // 3: end for

    h_hat // 4: return h_hat
}

/// Algorithm 11 `BaseCaseMultiply(a0, a1, b0, b1, gamma)` on page 24 of FIPS 203.
/// Computes the product of two degree-one polynomials with respect to a quadratic modulus.
#[must_use]
pub fn base_case_multiply(a0: i32, a1: i32, b0: i32, b1: i32, gamma: i32) -> (i32, i32) {
    let (a0, a1, b0, b1, gamma) = (a0 as i64, a1 as i64, b0 as i64, b1 as i64, gamma as i64);
    // Input: a0 , a1 , b0 , b1 ∈ Z_q               ▷ the coefficients of a0 + a1 X and b0 + b1 X
    // Input: γ ∈ Z_q                               ▷ the modulus is X^2 − γ
    // Output: c0 , c1 ∈ Z_q                        ▷ the coeffcients of the product of the two polynomials
    // 1: c0 ← a0 · b0 + a1 · b1 · γ                ▷ steps 1-2 done modulo q
    let c0 = (a0 * b0 + (a1 * b1).rem_euclid(QI as i64) * gamma).rem_euclid(QI as i64);

    // 2: 2: c1 ← a0 · b1 + a1 · b0
    let c1 = (a0 * b1 + a1 * b0).rem_euclid(QI as i64);

    // 3: return c0 , c1
    (c0 as i32, c1 as i32)
}


/// Algorithm 1 ML-DSA.KeyGen() on page 15.
/// Generates a public-private key pair.
pub(crate) fn key_gen<
    const ETA: usize,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    rng: &mut impl CryptoRngCore,
) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    // Output: Public key, pk ∈ B^{32+32k(bitlen(q−1)−d)},
    // and private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}

    // 1: ξ ← {0,1}^{256}               ▷ Choose random seed
    let mut xi = [0u8; 32];
    rng.fill_bytes(&mut xi);

    // 2: (ρ, ρ′, K) ∈ {0,1}^{256} × {0,1}^{512} × {0,1}^{256} ← H(ξ, 1024)     ▷ Expand seed
    let mut xof = h_xof(&[&xi]);
    let mut rho = [0u8; 32];
    xof.read(&mut rho);
    let mut rho_prime = [0u8; 64];
    xof.read(&mut rho_prime);
    let mut k = [0u8; 32];
    xof.read(&mut k);

    // 3: cap_a_hat ← ExpandA(ρ)        ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat = expand_a::<K, L>(&rho.try_into().unwrap());

    // 4: (s_1, s_2 ) ← ExpandS(ρ′)
    let (s_1, s_2) = expand_s::<ETA, K, L>(&rho_prime);

    // 5: t ← NTT−1 (cap_a_hat ◦ NTT(s_1)) + s_2        ▷ Compute t = As1 + s2
    let mut ntt_s_1 = [[0i32; 256] as T; L];
    for i in 0..L {
        ntt_s_1[i] = ntt(&(s_1[i] as R));
    }
    let ntt_p1 = mat_vec_mul(&cap_a_hat, &ntt_s_1);
    let mut t = [[0i32; 256]; L];
    for l in 0..L {
        t[l] = inv_ntt(&ntt_p1[l]);
    }

    // 6: (t_1 , t_0 ) ← Power2Round(t, d)              ▷ Compress t
    let mut t_1 = [[0i32; 256]; K];
    let mut t_0 = [[0i32; 256]; K];
    for l in 0..L {
        for m in 0..256 {
            (t_1[l][m], t_0[l][m]) = power2round(t[l][m]);
        }
    }

    // 7: pk ← pkEncode(ρ, t_1)
    let pk = pk_encode::<{ D as usize }, K, PK_LEN>(&rho, &t_1);

    // 8: tr ← H(BytesToBits(pk), 512)
    let mut tr = [0u8; 64];
    let mut h = h_xof(&[&pk]);
    h.read(&mut tr);

    // 9: sk ← skEncode(ρ, K, tr, s_1 , s_2 , t_0 )     ▷ K and tr are for use in signing
    let sk = sk_encode::<{ D as usize }, ETA, K, L, SK_LEN>(&rho, &k, &tr, &s_1, &s_2, &t_0);

    // 10: return (pk, sk)
    (pk, sk)
}


/// Algorithm 2 ML-DSA.Sign(sk, M) on page 17
/// Generates a signature for a message M.
pub(crate) fn sign<
    const BETA: u32,
    const ETA: usize,
    const GAMMA1: usize,
    const GAMMA2: u32,
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
    const SK_LEN: usize,
    const TAU: usize,
>(
    rng: &mut impl CryptoRngCore, sk: &[u8; SK_LEN], message: &[u8], sig: &mut [u8],
) -> Result<(), &'static str> {
    // Input: Private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)} and the message M ∈ {0,1}^∗
    // Output: Signature, σ ∈ B^{32+ℓ·32·(1+bitlen(gamma_1 −1))+ω+k}
    debug_assert_eq!(sig.len(), 32 + L * 32 * (1 + bitlen((GAMMA1 - 1) as usize)) + OMEGA + K + 16); // c_tilde correction is trailing 16

    // 1:  (ρ, K, tr, s_1 , s_2 , t_0 ) ← skDecode(sk)
    let (rho, cap_k, tr, s_1, s_2, t_0) = sk_decode::<{ D as usize }, ETA, K, L, SK_LEN>(sk)?;

    // 2:  s_hat_1 ← NTT(s_1)
    let mut s_hat_1 = [[0i32; 256] as T; L];
    for i in 0..L {
        s_hat_1[i] = ntt(&s_1[i]);
    }

    // 3:  s_hat_2 ← NTT(s_2)
    let mut s_hat_2 = [[0i32; 256] as T; K];
    for i in 0..K {
        s_hat_2[i] = ntt(&s_2[i]);
    }

    // 4:  t_hat_0 ← NTT(t_0)
    let mut t_hat_0 = [[0i32; 256]; K];
    for i in 0..K {
        t_hat_0[i] = ntt(&t_0[i]);
    }

    // 5:  cap_a_hat ← ExpandA(ρ)        ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[R; L]; K] = expand_a(&rho);

    // 6:  µ ← H(tr||M, 512)             ▷ Compute message representative µ
    let mut xof = h_xof(&[&tr, &message]);
    let mut mu = [0u8; 64];
    xof.read(&mut mu);

    // 7:  rnd ← {0,1}^256               ▷ For the optional deterministic variant, substitute rnd ← {0}256
    let mut rnd = [0u8; 32];
    rng.fill_bytes(&mut rnd);

    // 8:  ρ′ ← H(K||rnd||µ, 512)        ▷ Compute private random seed
    let mut xof = h_xof(&[&cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    xof.read(&mut rho_prime);

    // 9:  κ ← 0                         ▷ Initialize counter κ
    let mut k = 0;

    // 10: (z, h) ← ⊥
    let (mut z, mut h) = (None::<[[i32; 256]; L]>, None::<[[i32; 256]; K]>); // TODO: wrong None type
    let mut c_tilde = vec![0u8; 2 * LAMBDA / 8]; // TODO: check; LAMBDA is in bits not bytes  TODO: c_tilde should be 384 bits per section 1.3.2 (for 65&87)

    // 11: while (z, h) = ⊥ do          ▷ Rejection sampling loop
    while z.is_none() & h.is_none() {
        //
        // 12: y ← ExpandMask(ρ′ , κ)
        let y = expand_mask::<GAMMA1, L>(&rho_prime, k);

        // 13: w ← NTT−1 (cap_a_hat ◦ NTT(y))
        let mut ntt_y = [[0i32; 256] as T; L];
        for i in 0..L {
            ntt_y[i] = ntt(&(y[i] as R));
        }
        let ntt_p1 = mat_vec_mul(&cap_a_hat, &ntt_y);
        let mut w = [[0i32; 256]; K];
        for l in 0..K {
            w[l] = inv_ntt(&ntt_p1[l]);
        }

        // 14: w_1 ← HighBits(w)            ▷ Signer’s commitment
        let mut w_1 = [[0i32; 256]; K];
        for i in 0..256 {
            for j in 0..K {
                w_1[j][i] = high_bits::<GAMMA2>(&w[j][i]);
            }
        }

        // 15: c_tilde ∈ {0,1}^{2Lambda} ← H(µ || w1Encode(w_1), 2Lambda)     ▷ Commitment hash
        let bitlen_step = 4 * bitlen((QU - 1) as usize / (2 * GAMMA2) as usize - 1);
        let mut w1_tilde = vec![0u8; 2 * 4 * K * bitlen_step];
        w1_encode::<K, GAMMA2>(&w_1, &mut w1_tilde[..]);
        let mut xof = h_xof(&[&mu, &w1_tilde]);
        xof.read(&mut c_tilde);

        // 16: (c_tilde_1 , c_tilde_2) ∈ {0,1}^256 × {0,1}^{2Lambda-256} ← c_tilde      ▷ First 256 bits of commitment hash
        let mut c_tilde_1 = [0u8; 32];
        c_tilde_1.copy_from_slice(&c_tilde[0..32]);
        let mut c_tilde_2 = vec![0u8; 256 - 32]; //(2*LAMBDA-256)/8];
                                                 //c_tilde_2.copy_from_slice(&c_tilde[32..]);

        // 17: c ← SampleInBall(c_tilde_1)          ▷ Verifer’s challenge
        let c = sample_in_ball::<TAU>(&c_tilde_1);

        // 18: c_hat ← NTT(c)
        let c_hat = ntt(&c);

        // 19: ⟨⟨c_s_1 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_1)
        let mut x = [[0i32; 256]; L];
        for i in 0..256 {
            for k in 0..L {
                x[k][i] = (c_hat[i] as i64 * s_hat_1[k][i] as i64).rem_euclid(QI as i64) as i32;
            }
        }
        let mut c_s_1 = [[0i32; 256]; L];
        for i in 0..L {
            c_s_1[i] = inv_ntt(&x[i]);
        }

        // 20: ⟨⟨c_s_2 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_2)
        let mut x = [[0i32; 256]; K];
        for i in 0..256 {
            for k in 0..K {
                x[k][i] = (c_hat[i] as i64 * s_hat_2[k][i] as i64).rem_euclid(QI as i64) as i32;
            }
        }
        let mut c_s_2 = [[0i32; 256]; K];
        for i in 0..L {
            c_s_2[i] = inv_ntt(&x[i]);
        }

        // 21: z ← y + ⟨⟨c_s_1⟩⟩                    ▷ Signer’s response
        let mut zz = [[0i32; 256]; L];
        for i in 0..256 {
            for k in 0..L {
                zz[k][i] = (y[k][i] + c_s_1[k][i]).rem_euclid(QI);
            }
        }
        z = Some(zz);

        // 22: r0 ← LowBits(w − ⟨⟨c_s_2⟩⟩)
        let mut r0 = [[0i32; 256]; L];
        for i in 0..256 {
            for k in 0..L {
                r0[k][i] = low_bits::<GAMMA2>((QI + w[k][i] - c_s_2[k][i]).rem_euclid(QI));
            }
        }

        // 23: if ||z||∞ ≥ Gamma1 − β or ||r0||∞ ≥ Gamma2 − β then (z, h) ← ⊥       ▷ Validity checks
        if ((infinity_norm(&z.unwrap()) >= (GAMMA1 as i32 - BETA as i32))
            | (infinity_norm(&r0) >= (GAMMA2 as i32 - BETA as i32)))
            & false
        {
            //(z, h) = (None, None);
        } else {
            // 24: else
            // 25: ⟨⟨c_t_0 ⟩⟩ ← NTT−1 (c_hat ◦ t_hat_0)
            let mut x = [[0i32; 256]; K];
            for i in 0..256 {
                for k in 0..K {
                    x[k][i] = (c_hat[i] as i64 * t_hat_0[k][i] as i64).rem_euclid(QI as i64) as i32;
                }
            }
            let mut c_t_0 = [[0i32; 256]; K];
            for i in 0..L {
                c_t_0[i] = inv_ntt(&x[i]);
            }
            // 26: h ← MakeHint(−⟨⟨c_t_0⟩⟩, w − ⟨⟨c_s_2⟩⟩ + ⟨⟨c_t_0⟩⟩)                  ▷ Signer’s hint
            let mut hh = [[0i32; 256]; K];
            for i in 0..256 {
                for k in 0..K {
                    hh[k][i] = make_hint::<GAMMA2>(
                        -1 * z.unwrap()[k][i],
                        w[k][i] - c_s_2[k][i] + c_t_0[k][i],
                    ) as i32;
                }
            }
            h = Some(hh);
            // 27: if ||⟨⟨c_t_0⟩⟩||∞ ≥ Gamma2 or the number of 1’s in h is greater than ω, then (z, h) ← ⊥
            if (infinity_norm(&c_t_0) >= GAMMA2 as i32)
                | (h.unwrap()
                    .iter()
                    .flatten()
                    .filter(|i| **i == 1)
                    .collect::<Vec<_>>()
                    .len()
                    > OMEGA)
            {
                //(z, h) = (None::<[[i32; 256]; L]>, None::<[[bool; 256]; K]>);
            } // 28: end if
        } // 29: end if
          // 30: κ ← κ +ℓ                     ▷ Increment counter
        k += L as u32;
        break;
    } // 31: end while
      // 32: σ ← sigEncode(c_tilde, z mod± q, h)
    sig_encode::<GAMMA1, K, L, LAMBDA, OMEGA>(&c_tilde, &z.unwrap(), &h.unwrap(), sig);
    // TODO h [1] is wrong
    Ok(())
} // 33: return σ

fn infinity_norm<const ROW: usize, const COL: usize>(w: &[[i32; COL]; ROW]) -> i32 {
    let mut result = 0;
    for i in 0..w.len() {
        let inner = w[i];
        for j in 0..inner.len() {
            result = if inner[j].abs() > result {
                inner[j].abs()
            } else {
                result
            };
        }
    }
    result
}
