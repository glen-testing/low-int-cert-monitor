use crate::bigint::{b256, b384, b521};

#[inline]
pub fn inv_mod_2_64(a: u64) -> u64 {
    // Newton's method for the inverse mod 2^64, doubling correct bits each
    // round (3 -> 6 -> 12 -> 24 -> 48 -> 96 >= 64).
    let mut inv = a;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
    }
    inv
}

#[inline]
pub fn n0inv(p0: u64) -> u64 {
    inv_mod_2_64(p0).wrapping_neg()
}

macro_rules! mont_redc {
    ($fname:ident, $ops:ident, $n:expr) => {
        pub fn $fname(wide: &$ops::Wide, p: &$ops::Limb, n0inv: u64) -> $ops::Limb {
            // One extra headroom limb beyond the 2N-limb product: the final
            // round's carry-out can otherwise walk one limb past the end.
            let mut t = [0u64; 2 * $n + 1];
            t[..2 * $n].copy_from_slice(wide);
            for i in 0..$n {
                let m = t[i].wrapping_mul(n0inv);
                let mut carry: u128 = 0;
                for j in 0..$n {
                    let idx = i + j;
                    let prod = (m as u128) * (p[j] as u128) + t[idx] as u128 + carry;
                    t[idx] = prod as u64;
                    carry = prod >> 64;
                }
                let mut k = i + $n;
                let mut c = carry;
                while c != 0 {
                    let s = t[k] as u128 + c;
                    t[k] = s as u64;
                    c = s >> 64;
                    k += 1;
                }
            }
            debug_assert!(t[2 * $n] <= 1, "REDC headroom limb out of expected [0,1] range");
            let mut res = [0u64; $n];
            res.copy_from_slice(&t[$n..2 * $n]);
            // Headroom limb set means the true value is >= 2^(64N) > p, so
            // (same reasoning as add_mod) the wrapped subtraction is exactly
            // the answer -- no extra comparison needed in that case.
            if t[2 * $n] != 0 {
                $ops::sub(&res, p).0
            } else {
                $ops::cond_sub(&res, p)
            }
        }
    };
}

mont_redc!(redc256, b256, 4);
mont_redc!(redc384, b384, 6);
mont_redc!(redc521, b521, 9);
