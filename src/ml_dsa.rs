use crate::encodings::{
    pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, sk_encode, w1_encode,
};
use crate::hashing::{expand_a, expand_mask, expand_s, h_xof, sample_in_ball};
use crate::helpers::{bitlen, mod_pm};
use crate::high_low::{high_bits, low_bits, make_hint, power2round, use_hint};
use crate::ntt::{inv_ntt, ntt};
use crate::types::{Zero, R, T};
use crate::{helpers, D, QI, QU};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;


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
) -> Result<([u8; PK_LEN], [u8; SK_LEN]), &'static str> {
    // Output: Public key, pk ∈ B^{32+32k(bitlen(q−1)−d)},
    // and private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}

    // 1: ξ ← {0,1}^{256}    ▷ Choose random seed
    let mut xi = [0u8; 32];
    rng.try_fill_bytes(&mut xi).map_err(|_| "Random number generator failed")?;

    // 2: (ρ, ρ′, K) ∈ {0,1}^{256} × {0,1}^{512} × {0,1}^{256} ← H(ξ, 1024)    ▷ Expand seed
    let mut h = h_xof(&[&xi]);
    let mut rho = [0u8; 32];
    h.read(&mut rho);
    let mut rho_prime = [0u8; 64];
    h.read(&mut rho_prime);
    let mut cap_k = [0u8; 32];
    h.read(&mut cap_k);

    // 3: cap_a_hat ← ExpandA(ρ)        ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a::<K, L>(&rho);

    // 4: (s_1, s_2 ) ← ExpandS(ρ′)
    let (s_1, s_2): ([R; L], [R; K]) = expand_s::<ETA, K, L>(&rho_prime);

    // 5: t ← NTT−1 (cap_a_hat ◦ NTT(s_1)) + s_2        ▷ Compute t = As1 + s2
    let mut s_1_hat: [T; L] = [T::zero(); L];
    for i in 0..L {
        s_1_hat[i] = ntt(&s_1[i]);
    }
    let ntt_p1: [T; K] = helpers::mat_vec_mul(&cap_a_hat, &s_1_hat);
    let mut t: [R; K] = [R::zero(); K];
    for l in 0..K {
        t[l] = inv_ntt(&ntt_p1[l]);
    }
    t = helpers::vec_add(&t, &s_2);

    // 6: (t_1 , t_0 ) ← Power2Round(t, d)              ▷ Compress t
    let mut t_1: [R; K] = [R::zero(); K];
    let mut t_0: [R; K] = [R::zero(); K];
    for l in 0..K {
        for m in 0..256 {
            (t_1[l][m], t_0[l][m]) = power2round(t[l][m]);
        }
    }

    // 7: pk ← pkEncode(ρ, t_1)
    let pk: [u8; PK_LEN] = pk_encode::<K, PK_LEN>(&rho, &t_1);

    // 8: tr ← H(BytesToBits(pk), 512)
    let mut tr = [0u8; 64];
    let mut h = h_xof(&[&pk]);
    h.read(&mut tr);

    // 9: sk ← skEncode(ρ, K, tr, s_1 , s_2 , t_0 )     ▷ K and tr are for use in signing
    let sk: [u8; SK_LEN] =
        sk_encode::<{ D as usize }, ETA, K, L, SK_LEN>(&rho, &cap_k, &tr, &s_1, &s_2, &t_0);

    // 10: return (pk, sk)
    Ok((pk, sk))
}


/// Algorithm 2 ML-DSA.Sign(sk, M) on page 17
/// Generates a signature for a message M.
#[allow(clippy::similar_names)]
#[allow(clippy::many_single_char_names)]
#[allow(clippy::too_many_lines)]
pub(crate) fn sign<
    const BETA: u32,
    const ETA: usize,
    const GAMMA1: usize,
    const GAMMA2: usize,
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
    const SIG_LEN: usize,
    const SK_LEN: usize,
    const TAU: usize,
>(
    rand_gen: &mut impl CryptoRngCore, sk: &[u8; SK_LEN], message: &[u8],
) -> Result<[u8; SIG_LEN], &'static str> {
    // Input: Private key, sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)} and the message M ∈ {0,1}^∗
    // Output: Signature, σ ∈ B^{32+ℓ·32·(1+bitlen(gamma_1 −1))+ω+k}
    //let mut sig = [0u8; SIG_LEN];

    // 1:  (ρ, K, tr, s_1 , s_2 , t_0 ) ← skDecode(sk)
    #[allow(clippy::type_complexity)]
    let (rho, cap_k, tr, s_1, s_2, t_0): (
        [u8; 32],
        [u8; 32],
        [u8; 64],
        [R; L],
        [R; K],
        [R; K],
    ) = sk_decode::<{ D as usize }, ETA, K, L, SK_LEN>(sk)?;

    // 2:  s_hat_1 ← NTT(s_1)
    let mut s_hat_1: [T; L] = [T::zero(); L];
    for i in 0..L {
        s_hat_1[i] = ntt(&s_1[i]);
    }

    // 3:  s_hat_2 ← NTT(s_2)
    let mut s_hat_2: [T; K] = [T::zero(); K];
    for i in 0..K {
        s_hat_2[i] = ntt(&s_2[i]);
    }

    // 4:  t_hat_0 ← NTT(t_0)
    let mut t_hat_0: [T; K] = [T::zero(); K];
    for i in 0..K {
        t_hat_0[i] = ntt(&t_0[i]);
    }

    // 5:  cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    // 6:  µ ← H(tr||M, 512)    ▷ Compute message representative µ
    let mut h = h_xof(&[&tr, &message]);
    let mut mu = [0u8; 64];
    h.read(&mut mu);

    // 7:  rnd ← {0,1}^256    ▷ For the optional deterministic variant, substitute rnd ← {0}256
    let mut rnd = [0u8; 32];
    rand_gen.fill_bytes(&mut rnd);

    // 8:  ρ′ ← H(K||rnd||µ, 512)    ▷ Compute private random seed
    let mut h = h_xof(&[&cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    h.read(&mut rho_prime);

    // 9:  κ ← 0    ▷ Initialize counter κ
    let mut k = 0;

    // 10: (z, h) ← ⊥
    let (mut z, mut h) = (None::<[R; L]>, None::<[R; K]>);
    let mut c_tilde = [0u8; 2 * 256 / 8]; //[0u8; 2 * LAMBDA / 8];
                                          // 11: while (z, h) = ⊥ do          ▷ Rejection sampling loop
    while z.is_none() & h.is_none() {
        //
        // 12: y ← ExpandMask(ρ′ , κ)
        let y: [R; L] = expand_mask::<GAMMA1, L>(&rho_prime, k);

        // 13: w ← NTT−1 (cap_a_hat ◦ NTT(y))
        let mut ntt_y: [T; L] = [T::zero(); L];
        for i in 0..L {
            ntt_y[i] = ntt(&y[i]);
        }
        let ntt_p1: [T; K] = helpers::mat_vec_mul(&cap_a_hat, &ntt_y);
        let mut w: [R; K] = [R::zero(); K];
        for l in 0..K {
            w[l] = inv_ntt(&ntt_p1[l]);
        }

        // 14: w_1 ← HighBits(w)            ▷ Signer’s commitment
        let mut w_1: [R; K] = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                w_1[i][j] = high_bits::<GAMMA2>(w[i][j]);
            }
        }

        // 15: c_tilde ∈ {0,1}^{2Lambda} ← H(µ || w1Encode(w_1), 2Lambda)     ▷ Commitment hash
        let w1e_len = 32 * K * bitlen(((QU - 1) / (2 * GAMMA2 as u32) - 1) as usize);
        //assert_eq!(w1e_len, 768);
        let mut w1_tilde = [0u8; 1024];
        w1_encode::<K, GAMMA2>(&w_1, &mut w1_tilde[0..w1e_len]);
        let mut h99 = h_xof(&[&mu, &w1_tilde[0..w1e_len]]);
        h99.read(&mut c_tilde); // Ok, to read a bit too much

        // 16: (c_tilde_1 , c_tilde_2) ∈ {0,1}^256 × {0,1}^{2Lambda-256} ← c_tilde    ▷ First 256 bits of commitment hash
        let mut c_tilde_1 = [0u8; 32];
        c_tilde_1.copy_from_slice(&c_tilde[0..32]);
        // c_tilde_2 is never used!

        // 17: c ← SampleInBall(c_tilde_1)    ▷ Verifier’s challenge
        let c: R = sample_in_ball::<TAU>(&c_tilde_1);

        // 18: c_hat ← NTT(c)
        let c_hat: T = ntt(&c);

        // 19: ⟨⟨c_s_1 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_1)
        let mut x: [T; L] = [T::zero(); L];
        for i in 0..L {
            #[allow(clippy::needless_range_loop)]
            for j in 0..256 {
                x[i][j] = (c_hat[j] as i64 * s_hat_1[i][j] as i64).rem_euclid(QI as i64) as i32;
            }
        }
        let mut c_s_1: [R; L] = [R::zero(); L];
        for i in 0..L {
            c_s_1[i] = inv_ntt(&x[i]);
        }

        // 20: ⟨⟨c_s_2 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_2)
        let mut x: [T; K] = [T::zero(); K];
        for i in 0..K {
            #[allow(clippy::needless_range_loop)]
            for j in 0..256 {
                x[i][j] = (c_hat[j] as i64 * s_hat_2[i][j] as i64).rem_euclid(QI as i64) as i32;
            }
        }
        let mut c_s_2: [R; K] = [R::zero(); K];
        for i in 0..K {
            c_s_2[i] = inv_ntt(&x[i]);
        }

        // 21: z ← y + ⟨⟨c_s_1⟩⟩    ▷ Signer’s response
        let mut x: [R; L] = [R::zero(); L];
        for i in 0..L {
            for j in 0..256 {
                x[i][j] = (y[i][j] + c_s_1[i][j]).rem_euclid(QI);
            }
        }
        z = Some(x);

        // 22: r0 ← LowBits(w − ⟨⟨c_s_2⟩⟩)
        let mut r0: [R; K] = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                r0[i][j] = low_bits::<GAMMA2>((QI + w[i][j] - c_s_2[i][j]).rem_euclid(QI));
            }
        }

        // 23: if ||z||∞ ≥ Gamma1 − β or ||r0||∞ ≥ Gamma2 − β then (z, h) ← ⊥    ▷ Validity checks
        let z_norm = helpers::infinity_norm(&z.unwrap());
        let r0_norm = helpers::infinity_norm(&r0);
        if (z_norm >= (GAMMA1 as i32 - BETA as i32)) | (r0_norm >= (GAMMA2 as i32 - BETA as i32)) {
            (z, h) = (None, None);
            //
            // 24: else
        } else {
            //
            // 25: ⟨⟨c_t_0 ⟩⟩ ← NTT−1 (c_hat ◦ t_hat_0)
            let mut x: [T; K] = [T::zero(); K];
            for i in 0..K {
                #[allow(clippy::needless_range_loop)]
                for j in 0..256 {
                    x[i][j] = (c_hat[j] as i64 * t_hat_0[i][j] as i64).rem_euclid(QI as i64) as i32;
                }
            }
            let mut c_t_0 = [R::zero(); K];
            for i in 0..K {
                c_t_0[i] = inv_ntt(&x[i]);
            }

            // 26: h ← MakeHint(−⟨⟨c_t_0⟩⟩, w − ⟨⟨c_s_2⟩⟩ + ⟨⟨c_t_0⟩⟩)    ▷ Signer’s hint
            let mut mct0 = [R::zero(); K];
            let mut wcc = [R::zero(); K];
            let mut hh: [R; K] = [R::zero(); K]; // hh should be R_2
            for i in 0..K {
                for j in 0..256 {
                    mct0[i][j] = (QI - c_t_0[i][j]).rem_euclid(QI);
                    wcc[i][j] = (w[i][j] - c_s_2[i][j] + c_t_0[i][j]).rem_euclid(QI);
                    hh[i][j] = make_hint::<GAMMA2>(mct0[i][j], wcc[i][j]) as i32;
                }
            }
            h = Some(hh);

            // 27: if ||⟨⟨c_t_0⟩⟩||∞ ≥ Gamma2 or the number of 1’s in h is greater than ω, then (z, h) ← ⊥
            if (helpers::infinity_norm(&c_t_0) >= GAMMA2 as i32)
                | (h.unwrap().iter().flatten().filter(|i| (**i).abs() == 1).count() > OMEGA)
            {
                (z, h) = (None::<[R; L]>, None::<[R; K]>);
            } // 28: end if
              //
        } // 29: end if
          //
          // 30: κ ← κ + ℓ ▷ Increment counter
        k += L as u32;
    } // 31: end while
      //
      // 32: σ ← sigEncode(c_tilde, z mod± q, h)
    let mut zmq: [R; L] = [R::zero(); L];
    let zz = z.unwrap();
    for i in 0..L {
        for j in 0..256 {
            zmq[i][j] = mod_pm(zz[i][j], QU);
        }
    }

    let sig = sig_encode::<GAMMA1, K, L, LAMBDA, OMEGA, SIG_LEN>(
        &c_tilde[0..2 * LAMBDA / 8],
        &zmq,
        &h.unwrap(),
    );

    Ok(sig) // 33: return σ
}


/// Algorithm 3 ML-DSA.Verify(pk, M, σ) on page 19.
/// Verifies a signature σ for a message M.
pub(crate) fn verify<
    const BETA: u32,
    const GAMMA1: usize,
    const GAMMA2: usize,
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const OMEGA: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
    const TAU: usize,
>(
    pk: &[u8; PK_LEN], m: &[u8], sig: &[u8; SIG_LEN],
) -> Result<bool, &'static str> {
    // Input: Public key, pk ∈ B^{32 + 32*k*(bitlen(q−1) − d) and message M ∈ {0,1}∗.
    // Input: Signature, σ ∈ B^{32 + ℓ·32·(1 + bitlen(γ1−1)) + ω + k}.
    // Output: Boolean

    // 1: (ρ,t_1) ← pkDecode(pk)
    let (rho, t_1): ([u8; 32], [R; K]) = pk_decode::<K, PK_LEN>(pk)?;

    // 2: (c_tilde, z, h) ← sigDecode(σ)    ▷ Signer’s commitment hash c_tilde, response z and hint h
    let (c_tilde, z, h): (Vec<u8>, [R; L], Option<[R; K]>) =
        sig_decode::<GAMMA1, K, L, LAMBDA, OMEGA>(sig)?;

    // 3: if h = ⊥ then return false ▷ Hint was not properly encoded
    if h.is_none() {
        return Ok(false);
    };
    let i_norm = helpers::infinity_norm(&z);
    assert!(i_norm < GAMMA1 as i32);
    // 4: end if

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    // 6: tr ← H(BytesToBits(pk), 512)
    let mut hasher = h_xof(&[pk]);
    let mut tr = [0u8; 64];
    hasher.read(&mut tr);

    // 7: µ ← H(tr||M,512)    ▷ Compute message representative µ
    let mut hasher = h_xof(&[&tr, m]);
    let mut mu = [0u8; 64];
    hasher.read(&mut mu);

    // 8: (c_tilde_1, c_tilde_2) ∈ {0,1}^256 × {0,1}^{2λ-256} ← c_tilde   NOTE: c_tilde_2 is discarded
    let c_tilde_1 = c_tilde.clone(); // c_tilde_2 is just discarded...

    // 9: c ← SampleInBall(c_tilde_1)    ▷ Compute verifier’s challenge from c_tilde
    let c: R = sample_in_ball::<TAU>(&c_tilde_1[0..32].try_into().unwrap());

    // 10: w′_Approx ← invNTT(cap_A_hat ◦ NTT(z) - NTT(c) ◦ NTT(t_1 · 2^d)    ▷ w′_Approx = Az − ct1·2^d
    let mut ntt_z: [T; L] = [T::zero(); L];
    for i in 0..L {
        ntt_z[i] = ntt(&z[i]);
    }
    let ntt_a_z: [T; K] = helpers::mat_vec_mul(&cap_a_hat, &ntt_z);

    let mut ntt_t1: [T; K] = [T::zero(); K];
    for i in 0..K {
        ntt_t1[i] = ntt(&t_1[i]);
    }
    let mut ntt_t1_d2: [T; K] = [T::zero(); K];
    for i in 0..K {
        for j in 0..256 {
            ntt_t1_d2[i][j] =
                (ntt_t1[i][j] as i64 * 2i32.pow(D) as i64).rem_euclid(QI as i64) as i32;
        }
    }
    let ntt_c: T = ntt(&c);
    let mut ntt_ct: [T; K] = [T::zero(); K];
    for i in 0..K {
        #[allow(clippy::needless_range_loop)]
        for j in 0..256 {
            ntt_ct[i][j] = (ntt_c[j] as i64 * ntt_t1_d2[i][j] as i64).rem_euclid(QI as i64) as i32;
        }
    }

    let mut wp_approx: [R; K] = [R::zero(); K];
    for i in 0..K {
        let mut tmp = T::zero();
        (0..256).for_each(|j| tmp[j] = ntt_a_z[i][j] - ntt_ct[i][j]);
        wp_approx[i] = inv_ntt(&tmp);
    }

    // 11: w′_1 ← UseHint(h, w′_Approx)    ▷ Reconstruction of signer’s commitment
    let mut wp_1: [R; K] = [R::zero(); K];
    for i in 0..K {
        for j in 0..256 {
            wp_1[i][j] = use_hint::<GAMMA2>(h.unwrap()[i][j], wp_approx[i][j]);
        }
    }

    // 12: c_tilde_′ ← H(µ||w1Encode(w′_1), 2λ)     ▷ Hash it; this should match c_tilde
    let qm12gm1 = (QU - 1) / (2 * GAMMA2 as u32) - 1;
    let bl = bitlen(qm12gm1 as usize);
    let mut tmp = vec![0u8; 32 * K * bl];
    w1_encode::<K, GAMMA2>(&wp_1, &mut tmp[..]);
    let mut hasher = h_xof(&[&mu, &tmp[..]]);
    let mut c_tilde_p = vec![0u8; 2 * LAMBDA / 8];
    hasher.read(&mut c_tilde_p);

    // 13: return [[ ||z||∞ < γ1 −β]] and [[c_tilde = c_tilde_′]] and [[number of 1’s in h is ≤ ω]]
    let left = helpers::infinity_norm(&z) < ((GAMMA1 - BETA as usize) as i32);
    let center = c_tilde == c_tilde_p;
    let right = h // TODO: this checks #h per each R (rather than overall total)
        .unwrap()
        .iter()
        .all(|&r| r.iter().filter(|&&e| e == 1).sum::<i32>() <= OMEGA as i32);
    Ok(left & center & right)
}
