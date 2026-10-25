use crate::bigint::b521;

// ---- P-256: p = 2^256 - 2^224 + 2^192 + 2^96 - 1 ----
// Table[k-8][*] = (output 32-bit word position, coefficient) contributions
// of input word c_k (k = 8..15) after folding 2^256 = 2^224-2^192-2^96+1.
#[rustfmt::skip]
static P256_TABLE: [&[(usize, i64)]; 8] = [
    /* c8  */ &[(7, 1), (6, -1), (3, -1), (0, 1)],
    /* c9  */ &[(4, -1), (1, 1), (6, -1), (3, -1), (0, 1)],
    /* c10 */ &[(5, -1), (2, 1), (7, -1), (4, -1), (1, 1)],
    /* c11 */ &[(3, 2), (5, -1), (2, 1), (7, -1), (0, -1)],
    /* c12 */ &[(7, -1), (4, 2), (3, 2), (1, -1), (0, -1)],
    /* c13 */ &[(5, 2), (7, -1), (4, 2), (2, -1), (1, -1), (6, 1), (3, 1), (0, -1)],
    /* c14 */ &[(6, 3), (5, 2), (2, -1), (4, 1), (1, -1), (0, -1)],
    /* c15 */ &[(7, 3), (6, 2), (3, -1), (5, 1), (2, -1), (1, -1)],
];

// ---- P-384: p = 2^384 - 2^128 - 2^96 + 2^32 - 1 ----
#[rustfmt::skip]
static P384_TABLE: [&[(usize, i64)]; 12] = [
    /* c12 */ &[(4, 1), (3, 1), (1, -1), (0, 1)],
    /* c13 */ &[(5, 1), (4, 1), (2, -1), (1, 1)],
    /* c14 */ &[(6, 1), (5, 1), (3, -1), (2, 1)],
    /* c15 */ &[(7, 1), (6, 1), (4, -1), (3, 1)],
    /* c16 */ &[(8, 1), (7, 1), (5, -1), (4, 1)],
    /* c17 */ &[(9, 1), (8, 1), (6, -1), (5, 1)],
    /* c18 */ &[(10, 1), (9, 1), (7, -1), (6, 1)],
    /* c19 */ &[(11, 1), (10, 1), (8, -1), (7, 1)],
    /* c20 */ &[(11, 1), (9, -1), (8, 1), (4, 1), (3, 1), (1, -1), (0, 1)],
    /* c21 */ &[(10, -1), (9, 1), (5, 1), (4, 2), (2, -1), (3, 1), (0, 1)],
    /* c22 */ &[(11, -1), (10, 1), (6, 1), (5, 2), (3, -1), (4, 1), (1, 1)],
    /* c23 */ &[(11, 1), (7, 1), (6, 2), (4, -2), (3, -1), (5, 1), (2, 1), (1, 1), (0, -1)],
];

/// Add `mag * rmod` (mag small, >=0) into a 5-limb extended accumulator.
fn addmul_small_256(ext: &mut [u64; 5], rmod: &[u64; 4], mag: u64) {
    let mut carry: u128 = 0;
    for i in 0..4 {
        let s = ext[i] as u128 + (rmod[i] as u128) * (mag as u128) + carry;
        ext[i] = s as u64;
        carry = s >> 64;
    }
    let s = ext[4] as u128 + carry;
    ext[4] = s as u64; // no further carry expected: mag and rmod are bounded
}

fn submul_small_256(ext: &mut [u64; 5], rmod: &[u64; 4], mag: u64) {
    // delta = mag*rmod (<=4p, needs 5 limbs); bias ext up by 16*p first so the
    // subtraction cannot underflow, then normalize down at the call site.
    let mut delta = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let s = (rmod[i] as u128) * (mag as u128) + carry;
        delta[i] = s as u64;
        carry = s >> 64;
    }
    delta[4] = carry as u64;
    let mut borrow: i128 = 0;
    for i in 0..5 {
        let d = ext[i] as i128 - delta[i] as i128 - borrow;
        if d < 0 {
            ext[i] = (d + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            ext[i] = d as u64;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "bias insufficient in submul_small_256");
}

fn bias_add_p_256(ext: &mut [u64; 5], p: &[u64; 4], mult: u64) {
    let mut c: u128 = 0;
    for i in 0..4 {
        let s = ext[i] as u128 + (p[i] as u128) * (mult as u128) + c;
        ext[i] = s as u64;
        c = s >> 64;
    }
    let s = ext[4] as u128 + c;
    ext[4] = s as u64;
}

fn normalize_256(ext: &mut [u64; 5], p: &[u64; 4]) -> [u64; 4] {
    let p5 = [p[0], p[1], p[2], p[3], 0u64];
    for _ in 0..40 {
        let ge = {
            if ext[4] != p5[4] {
                ext[4] > p5[4]
            } else {
                let mut g = true;
                for i in (0..4).rev() {
                    if ext[i] != p[i] {
                        g = ext[i] > p[i];
                        break;
                    }
                    if i == 0 {
                        g = true;
                    }
                }
                g
            }
        };
        if !ge {
            break;
        }
        let mut borrow: i128 = 0;
        for i in 0..5 {
            let d = ext[i] as i128 - p5[i] as i128 - borrow;
            if d < 0 {
                ext[i] = (d + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                ext[i] = d as u64;
                borrow = 0;
            }
        }
    }
    [ext[0], ext[1], ext[2], ext[3]]
}

pub fn fast_reduce_p256(t: &[u64; 8], p: &[u64; 4], r_mod_p: &[u64; 4]) -> [u64; 4] {
    let mut cw = [0i64; 16];
    for i in 0..8 {
        cw[2 * i] = (t[i] & 0xFFFF_FFFF) as i64;
        cw[2 * i + 1] = (t[i] >> 32) as i64;
    }
    let mut out = [0i64; 8];
    for m in 0..8 {
        out[m] += cw[m];
    }
    for (idx, table) in P256_TABLE.iter().enumerate() {
        let ck = cw[8 + idx];
        if ck == 0 {
            continue;
        }
        for &(m, coef) in *table {
            out[m] += coef * ck;
        }
    }
    let mut acc = [0i128; 5];
    for i in 0..4 {
        acc[i] = out[2 * i] as i128 + ((out[2 * i + 1] as i128) << 32);
    }
    for i in 0..4 {
        let v = acc[i];
        let carry = v >> 64;
        acc[i] = v - (carry << 64);
        acc[i + 1] += carry;
    }
    let mut ext = [0u64; 5];
    for i in 0..4 {
        ext[i] = acc[i] as u64;
    }
    let k = acc[4];
    if k > 0 {
        addmul_small_256(&mut ext, r_mod_p, k as u64);
    } else if k < 0 {
        bias_add_p_256(&mut ext, p, 16);
        submul_small_256(&mut ext, r_mod_p, (-k) as u64);
    }
    normalize_256(&mut ext, p)
}

// ---------- P-384 (same scheme, N=6) ----------

fn addmul_small_384(ext: &mut [u64; 7], rmod: &[u64; 6], mag: u64) {
    let mut carry: u128 = 0;
    for i in 0..6 {
        let s = ext[i] as u128 + (rmod[i] as u128) * (mag as u128) + carry;
        ext[i] = s as u64;
        carry = s >> 64;
    }
    let s = ext[6] as u128 + carry;
    ext[6] = s as u64;
}

fn submul_small_384(ext: &mut [u64; 7], rmod: &[u64; 6], mag: u64) {
    let mut delta = [0u64; 7];
    let mut carry: u128 = 0;
    for i in 0..6 {
        let s = (rmod[i] as u128) * (mag as u128) + carry;
        delta[i] = s as u64;
        carry = s >> 64;
    }
    delta[6] = carry as u64;
    let mut borrow: i128 = 0;
    for i in 0..7 {
        let d = ext[i] as i128 - delta[i] as i128 - borrow;
        if d < 0 {
            ext[i] = (d + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            ext[i] = d as u64;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "bias insufficient in submul_small_384");
}

fn bias_add_p_384(ext: &mut [u64; 7], p: &[u64; 6], mult: u64) {
    let mut c: u128 = 0;
    for i in 0..6 {
        let s = ext[i] as u128 + (p[i] as u128) * (mult as u128) + c;
        ext[i] = s as u64;
        c = s >> 64;
    }
    let s = ext[6] as u128 + c;
    ext[6] = s as u64;
}

fn normalize_384(ext: &mut [u64; 7], p: &[u64; 6]) -> [u64; 6] {
    for _ in 0..40 {
        let ge = {
            if ext[6] != 0 {
                true
            } else {
                let mut g = true;
                for i in (0..6).rev() {
                    if ext[i] != p[i] {
                        g = ext[i] > p[i];
                        break;
                    }
                    if i == 0 {
                        g = true;
                    }
                }
                g
            }
        };
        if !ge {
            break;
        }
        let mut borrow: i128 = 0;
        for i in 0..6 {
            let d = ext[i] as i128 - p[i] as i128 - borrow;
            if d < 0 {
                ext[i] = (d + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                ext[i] = d as u64;
                borrow = 0;
            }
        }
        if borrow == 1 {
            ext[6] -= 1;
        }
    }
    [ext[0], ext[1], ext[2], ext[3], ext[4], ext[5]]
}

pub fn fast_reduce_p384(t: &[u64; 12], p: &[u64; 6], r_mod_p: &[u64; 6]) -> [u64; 6] {
    let mut cw = [0i64; 24];
    for i in 0..12 {
        cw[2 * i] = (t[i] & 0xFFFF_FFFF) as i64;
        cw[2 * i + 1] = (t[i] >> 32) as i64;
    }
    let mut out = [0i64; 12];
    for m in 0..12 {
        out[m] += cw[m];
    }
    for (idx, table) in P384_TABLE.iter().enumerate() {
        let ck = cw[12 + idx];
        if ck == 0 {
            continue;
        }
        for &(m, coef) in *table {
            out[m] += coef * ck;
        }
    }
    let mut acc = [0i128; 7];
    for i in 0..6 {
        acc[i] = out[2 * i] as i128 + ((out[2 * i + 1] as i128) << 32);
    }
    for i in 0..6 {
        let v = acc[i];
        let carry = v >> 64;
        acc[i] = v - (carry << 64);
        acc[i + 1] += carry;
    }
    let mut ext = [0u64; 7];
    for i in 0..6 {
        ext[i] = acc[i] as u64;
    }
    let k = acc[6];
    if k > 0 {
        addmul_small_384(&mut ext, r_mod_p, k as u64);
    } else if k < 0 {
        bias_add_p_384(&mut ext, p, 16);
        submul_small_384(&mut ext, r_mod_p, (-k) as u64);
    }
    normalize_384(&mut ext, p)
}

// ---------- P-521: Mersenne, p = 2^521 - 1 ----------

pub fn fast_reduce_p521(t: &[u64; 18], p: &[u64; 9]) -> [u64; 9] {
    let mut low = [0u64; 9];
    low.copy_from_slice(&t[0..9]);
    low[8] &= 0x1FF;
    let mut high = [0u64; 9];
    for i in 0..9 {
        let lo = if i + 8 < 18 { t[i + 8] >> 9 } else { 0 };
        let hi = if i + 9 < 18 { t[i + 9] << 55 } else { 0 };
        high[i] = lo | hi;
    }
    let (mut sum, _carry) = b521::add(&low, &high);
    for _ in 0..4 {
        if b521::ge(&sum, p) {
            sum = b521::sub(&sum, p).0;
        } else {
            break;
        }
    }
    sum
}
