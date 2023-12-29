use crate::helpers;
use crate::helpers::reduce_q64;
use crate::types::{R, T};


/// Algorithm 35 NTT(w) on page 36.
/// Computes the Number-Theoretic Transform.
///
/// Input: polynomial `w(X) = ∑_{j=0}^{255} w_j X^j ∈ Rq` <br>
/// Output: `w_hat = (w_hat[0], . . . , w_hat[255]) ∈ Tq`
pub(crate) fn ntt<const X: usize>(w: &[R; X]) -> [T; X] {
    let mut w_res = *w;
    for w_hat in &mut w_res {
        // 1: for j from 0 to 255 do
        // 2: w_hat[j] ← w_j
        // 3: end for
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
                let zeta = helpers::ZETA_TABLE[k] as i64;
                // 11: for j from start to start + len − 1 do
                for j in start..(start + len) {
                    // 12: t ← zeta · w_hat[ j + len]
                    let t = reduce_q64(zeta * w_hat[j + len] as i64);
                    // 13: w_hat[j + len] ← w_hat[j] − t
                    w_hat[j + len] = w_hat[j] - t;
                    // 14: w_hat[j] ← w_hat[j] + t
                    w_hat[j] += t;
                    // 15: end for
                }
                // 16: start ← start + 2 · len
                start += 2 * len;
                // 17: end while
            }
            // 18: len ← ⌊len/2⌋
            len /= 2;
            // 19: end while
        }
        // 20: return ŵ
    }
    w_res
}


/// Algorithm 36 NTT−1 (`w_hat`) on page 37.
/// Computes the inverse of the Number-Theoretic Transform.
///
/// Input: `w_hat` = `(w_hat[0], . . . , w_hat[255]) ∈ Tq` <br>
/// Output: polynomial `w(X) = ∑_{j=0}^{255} w_j X^j ∈ Rq`
pub(crate) fn inv_ntt<const X: usize>(w_hat: &[T; X]) -> [R; X] {
    let mut w_top = *w_hat;
    for w in &mut w_top {
        // 1: for j from 0 to 255 do
        // 2: w_j ← w_hat[j]
        // 3: end for
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
                let zeta = -(helpers::ZETA_TABLE[k]);
                // 11: for j from start to start + len − 1 do
                for j in start..(start + len) {
                    // 12: t ← w_j
                    let t = w[j];
                    // 13: w_j ← t + w_{j+len}
                    w[j] = t + w[j + len];
                    // 14: w_{j+len} ← t − w_{j+len}
                    w[j + len] = t - w[j + len];
                    // 15: w_{j+len} ← zeta · w_{j+len}
                    w[j + len] = reduce_q64(zeta as i64 * w[j + len] as i64);
                    // 16: end for
                }
                // 17: start ← start + 2 · len
                start += 2 * len;
                // 18: end while
            }
            // 19: len ← 2 · len
            len *= 2;
            // 20: end while
        }
        // 21: f ← 8347681          ▷ f = 256^{−1} mod q
        let f = 8_347_681_i64;
        // 22: for j from 0 to 255 do
        // 23: wj ← f · wj
        for i in &mut *w {
            *i = reduce_q64(f * *i as i64);
        }
        // 24: end for
    }
    w_top // 25: return w
}
