pub const fn bitlen(a: usize) -> usize { a.ilog2() as usize + 1 }

/// See definition on page 6
/// If α is a positive integer and m ∈ Z or m ∈ Z_α , then m mod± α denotes the unique
/// element m′ ∈ Z in the range −α/2 < m′ ≤ α/2 such that m and m′ are congruent
/// modulo α.
pub fn mod_pm(m: i32, a: u32) -> i32 {
    let t = m.rem_euclid(a as i32); // % a;
    let a = a as i32;
    let mp = if t <= (a / 2) {
        t as i32
    } else {
        t as i32 - a as i32
    };
    //assert_eq!((mp + a as i32) as u32 % a, t);
    assert_eq!((mp + a) as u32 % (a as u32), t as u32);

    mp
}
