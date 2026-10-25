macro_rules! bigint_ops {
    ($modname:ident, $n:expr, $n2:expr) => {
        pub mod $modname {
            pub const N: usize = $n;
            pub type Limb = [u64; $n];
            pub type Wide = [u64; $n2];

            #[inline]
            pub fn add(a: &Limb, b: &Limb) -> (Limb, u64) {
                let mut r = [0u64; $n];
                let mut carry: u128 = 0;
                for i in 0..$n {
                    let s = a[i] as u128 + b[i] as u128 + carry;
                    r[i] = s as u64;
                    carry = s >> 64;
                }
                (r, carry as u64)
            }

            #[inline]
            pub fn sub(a: &Limb, b: &Limb) -> (Limb, u64) {
                let mut r = [0u64; $n];
                let mut borrow: i128 = 0;
                for i in 0..$n {
                    let d = a[i] as i128 - b[i] as i128 - borrow;
                    if d < 0 {
                        r[i] = (d + (1i128 << 64)) as u64;
                        borrow = 1;
                    } else {
                        r[i] = d as u64;
                        borrow = 0;
                    }
                }
                (r, borrow as u64)
            }

            #[inline]
            pub fn is_zero(a: &Limb) -> bool {
                a.iter().all(|&x| x == 0)
            }

            #[inline]
            pub fn cmp(a: &Limb, b: &Limb) -> std::cmp::Ordering {
                for i in (0..$n).rev() {
                    if a[i] != b[i] {
                        return a[i].cmp(&b[i]);
                    }
                }
                std::cmp::Ordering::Equal
            }

            #[inline]
            pub fn ge(a: &Limb, b: &Limb) -> bool {
                cmp(a, b) != std::cmp::Ordering::Less
            }

            /// Assumes a < 2*m. Subtracts m once if a >= m.
            #[inline]
            pub fn cond_sub(a: &Limb, m: &Limb) -> Limb {
                if ge(a, m) { sub(a, m).0 } else { *a }
            }

            #[inline]
            pub fn mul_wide(a: &Limb, b: &Limb) -> Wide {
                let mut t = [0u64; $n2];
                for i in 0..$n {
                    let mut carry: u128 = 0;
                    let ai = a[i] as u128;
                    for j in 0..$n {
                        let idx = i + j;
                        let prod = ai * (b[j] as u128) + t[idx] as u128 + carry;
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
                t
            }

            pub fn hex_to_limbs(hex: &str) -> Limb {
                let mut limbs = [0u64; $n];
                let bytes = hex.as_bytes();
                let mut pos = bytes.len();
                let mut i = 0;
                while pos > 0 && i < $n {
                    let start = if pos >= 16 { pos - 16 } else { 0 };
                    let chunk = std::str::from_utf8(&bytes[start..pos]).unwrap();
                    limbs[i] = u64::from_str_radix(chunk, 16).unwrap();
                    pos = start;
                    i += 1;
                }
                limbs
            }

            pub fn limbs_to_hex(a: &Limb) -> String {
                let mut s = String::new();
                for i in (0..$n).rev() {
                    s.push_str(&format!("{:016x}", a[i]));
                }
                let trimmed = s.trim_start_matches('0');
                if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
            }

            /// Big-endian byte slice (as from SPKI point coords) -> limbs.
            pub fn from_bytes_be(bytes: &[u8]) -> Limb {
                let mut limbs = [0u64; $n];
                let mut idx = bytes.len();
                let mut i = 0;
                while idx > 0 && i < $n {
                    let start = if idx >= 8 { idx - 8 } else { 0 };
                    let chunk = &bytes[start..idx];
                    let mut v: u64 = 0;
                    for &b in chunk {
                        v = (v << 8) | b as u64;
                    }
                    limbs[i] = v;
                    idx = start;
                    i += 1;
                }
                limbs
            }

            /// (2*a) mod m, assuming a < m.
            #[inline]
            pub fn double_mod(a: &Limb, m: &Limb) -> Limb {
                let (s, carry) = add(a, a);
                if carry != 0 || ge(&s, m) { sub(&s, m).0 } else { s }
            }

            /// (a+b) mod m, assuming a < m and b < m.
            #[inline]
            pub fn add_mod(a: &Limb, b: &Limb, m: &Limb) -> Limb {
                let (s, carry) = add(a, b);
                let (d, borrow) = sub(&s, m);
                if carry != 0 || borrow == 0 { d } else { s }
            }

            /// (a-b) mod m, assuming a < m and b < m.
            #[inline]
            pub fn sub_mod(a: &Limb, b: &Limb, m: &Limb) -> Limb {
                let (d, borrow) = sub(a, b);
                if borrow == 1 { add(&d, m).0 } else { d }
            }

            /// -a mod m, assuming a < m.
            #[inline]
            pub fn neg_mod(a: &Limb, m: &Limb) -> Limb {
                if is_zero(a) { *a } else { sub(m, a).0 }
            }

            /// 2^k mod m via repeated doubling from 1. Startup-only; not perf critical.
            pub fn pow2_mod(k: u32, m: &Limb) -> Limb {
                let mut x = [0u64; $n];
                x[0] = 1;
                for _ in 0..k {
                    x = double_mod(&x, m);
                }
                x
            }
        }
    };
}

bigint_ops!(b256, 4, 8);
bigint_ops!(b384, 6, 12);
bigint_ops!(b521, 9, 18);
