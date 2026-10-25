use crate::bigint::{b256, b384, b521};
use crate::fastreduce;
use crate::montgomery;

pub trait FieldCtx {
    type Elem: Copy + Clone + PartialEq + Eq + std::hash::Hash + std::fmt::Debug;
    fn zero(&self) -> Self::Elem;
    fn one(&self) -> Self::Elem;
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn neg(&self, a: &Self::Elem) -> Self::Elem;
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn square(&self, a: &Self::Elem) -> Self::Elem {
        self.mul(a, a)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool;
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem;
    fn invert(&self, a: &Self::Elem) -> Self::Elem;
}

/// a^exp via left-to-right square-and-multiply, generic over any FieldCtx.
pub fn pow_mod<C: FieldCtx>(ctx: &C, base: &C::Elem, exp_limbs: &[u64]) -> C::Elem {
    let mut result = ctx.one();
    let nbits = exp_limbs.len() * 64;
    let mut started = false;
    for bitpos in (0..nbits).rev() {
        let limb_idx = bitpos / 64;
        let bit_idx = bitpos % 64;
        let bit = (exp_limbs[limb_idx] >> bit_idx) & 1;
        if !started {
            if bit == 0 {
                continue;
            }
            started = true;
        }
        result = ctx.mul(&result, &result);
        if bit == 1 {
            result = ctx.mul(&result, base);
        }
    }
    result
}

macro_rules! two_and_pminus2 {
    ($ops:ident, $n:expr, $p:expr) => {{
        let mut two = [0u64; $n];
        two[0] = 2;
        $ops::sub(&$p, &two).0
    }};
}

// ---------------- P-256 ----------------

pub struct Mont256Ctx {
    pub p: [u64; 4],
    pub n0inv: u64,
    pub r2: [u64; 4],
    pub p_minus_2: [u64; 4],
}

impl Mont256Ctx {
    pub fn new(p_hex: &str) -> Self {
        let p = b256::hex_to_limbs(p_hex);
        let n0inv = montgomery::n0inv(p[0]);
        let r2 = b256::pow2_mod(512, &p);
        let p_minus_2 = two_and_pminus2!(b256, 4, p);
        Self { p, n0inv, r2, p_minus_2 }
    }
    pub fn to_mont(&self, std_val: &[u64; 4]) -> [u64; 4] {
        montgomery::redc256(&b256::mul_wide(std_val, &self.r2), &self.p, self.n0inv)
    }
    pub fn from_mont(&self, mont_val: &[u64; 4]) -> [u64; 4] {
        let mut wide = [0u64; 8];
        wide[0..4].copy_from_slice(mont_val);
        montgomery::redc256(&wide, &self.p, self.n0inv)
    }
}

impl FieldCtx for Mont256Ctx {
    type Elem = [u64; 4];
    fn zero(&self) -> Self::Elem {
        [0; 4]
    }
    fn one(&self) -> Self::Elem {
        let mut v = [0u64; 4];
        v[0] = 1;
        self.to_mont(&v)
    }
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b256::add_mod(a, b, &self.p)
    }
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b256::sub_mod(a, b, &self.p)
    }
    fn neg(&self, a: &Self::Elem) -> Self::Elem {
        b256::neg_mod(a, &self.p)
    }
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        montgomery::redc256(&b256::mul_wide(a, b), &self.p, self.n0inv)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool {
        b256::is_zero(a)
    }
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem {
        self.to_mont(&b256::from_bytes_be(b))
    }
    fn invert(&self, a: &Self::Elem) -> Self::Elem {
        pow_mod(self, a, &self.p_minus_2)
    }
}

pub struct Fast256Ctx {
    pub p: [u64; 4],
    pub r_mod_p: [u64; 4],
    pub p_minus_2: [u64; 4],
}

impl Fast256Ctx {
    pub fn new(p_hex: &str) -> Self {
        let p = b256::hex_to_limbs(p_hex);
        let r_mod_p = b256::pow2_mod(256, &p);
        let p_minus_2 = two_and_pminus2!(b256, 4, p);
        Self { p, r_mod_p, p_minus_2 }
    }
}

impl FieldCtx for Fast256Ctx {
    type Elem = [u64; 4];
    fn zero(&self) -> Self::Elem {
        [0; 4]
    }
    fn one(&self) -> Self::Elem {
        let mut v = [0u64; 4];
        v[0] = 1;
        v
    }
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b256::add_mod(a, b, &self.p)
    }
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b256::sub_mod(a, b, &self.p)
    }
    fn neg(&self, a: &Self::Elem) -> Self::Elem {
        b256::neg_mod(a, &self.p)
    }
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        fastreduce::fast_reduce_p256(&b256::mul_wide(a, b), &self.p, &self.r_mod_p)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool {
        b256::is_zero(a)
    }
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem {
        b256::from_bytes_be(b)
    }
    fn invert(&self, a: &Self::Elem) -> Self::Elem {
        pow_mod(self, a, &self.p_minus_2)
    }
}

// ---------------- P-384 ----------------

pub struct Mont384Ctx {
    pub p: [u64; 6],
    pub n0inv: u64,
    pub r2: [u64; 6],
    pub p_minus_2: [u64; 6],
}

impl Mont384Ctx {
    pub fn new(p_hex: &str) -> Self {
        let p = b384::hex_to_limbs(p_hex);
        let n0inv = montgomery::n0inv(p[0]);
        let r2 = b384::pow2_mod(768, &p);
        let p_minus_2 = two_and_pminus2!(b384, 6, p);
        Self { p, n0inv, r2, p_minus_2 }
    }
    pub fn to_mont(&self, std_val: &[u64; 6]) -> [u64; 6] {
        montgomery::redc384(&b384::mul_wide(std_val, &self.r2), &self.p, self.n0inv)
    }
}

impl FieldCtx for Mont384Ctx {
    type Elem = [u64; 6];
    fn zero(&self) -> Self::Elem {
        [0; 6]
    }
    fn one(&self) -> Self::Elem {
        let mut v = [0u64; 6];
        v[0] = 1;
        self.to_mont(&v)
    }
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b384::add_mod(a, b, &self.p)
    }
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b384::sub_mod(a, b, &self.p)
    }
    fn neg(&self, a: &Self::Elem) -> Self::Elem {
        b384::neg_mod(a, &self.p)
    }
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        montgomery::redc384(&b384::mul_wide(a, b), &self.p, self.n0inv)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool {
        b384::is_zero(a)
    }
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem {
        self.to_mont(&b384::from_bytes_be(b))
    }
    fn invert(&self, a: &Self::Elem) -> Self::Elem {
        pow_mod(self, a, &self.p_minus_2)
    }
}

pub struct Fast384Ctx {
    pub p: [u64; 6],
    pub r_mod_p: [u64; 6],
    pub p_minus_2: [u64; 6],
}

impl Fast384Ctx {
    pub fn new(p_hex: &str) -> Self {
        let p = b384::hex_to_limbs(p_hex);
        let r_mod_p = b384::pow2_mod(384, &p);
        let p_minus_2 = two_and_pminus2!(b384, 6, p);
        Self { p, r_mod_p, p_minus_2 }
    }
}

impl FieldCtx for Fast384Ctx {
    type Elem = [u64; 6];
    fn zero(&self) -> Self::Elem {
        [0; 6]
    }
    fn one(&self) -> Self::Elem {
        let mut v = [0u64; 6];
        v[0] = 1;
        v
    }
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b384::add_mod(a, b, &self.p)
    }
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b384::sub_mod(a, b, &self.p)
    }
    fn neg(&self, a: &Self::Elem) -> Self::Elem {
        b384::neg_mod(a, &self.p)
    }
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        fastreduce::fast_reduce_p384(&b384::mul_wide(a, b), &self.p, &self.r_mod_p)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool {
        b384::is_zero(a)
    }
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem {
        b384::from_bytes_be(b)
    }
    fn invert(&self, a: &Self::Elem) -> Self::Elem {
        pow_mod(self, a, &self.p_minus_2)
    }
}

// ---------------- P-521 ----------------

pub struct Mont521Ctx {
    pub p: [u64; 9],
    pub n0inv: u64,
    pub r2: [u64; 9],
    pub p_minus_2: [u64; 9],
}

impl Mont521Ctx {
    pub fn new(p_hex: &str) -> Self {
        let p = b521::hex_to_limbs(p_hex);
        let n0inv = montgomery::n0inv(p[0]);
        let r2 = b521::pow2_mod(1152, &p);
        let p_minus_2 = two_and_pminus2!(b521, 9, p);
        Self { p, n0inv, r2, p_minus_2 }
    }
    pub fn to_mont(&self, std_val: &[u64; 9]) -> [u64; 9] {
        montgomery::redc521(&b521::mul_wide(std_val, &self.r2), &self.p, self.n0inv)
    }
}

impl FieldCtx for Mont521Ctx {
    type Elem = [u64; 9];
    fn zero(&self) -> Self::Elem {
        [0; 9]
    }
    fn one(&self) -> Self::Elem {
        let mut v = [0u64; 9];
        v[0] = 1;
        self.to_mont(&v)
    }
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b521::add_mod(a, b, &self.p)
    }
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b521::sub_mod(a, b, &self.p)
    }
    fn neg(&self, a: &Self::Elem) -> Self::Elem {
        b521::neg_mod(a, &self.p)
    }
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        montgomery::redc521(&b521::mul_wide(a, b), &self.p, self.n0inv)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool {
        b521::is_zero(a)
    }
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem {
        self.to_mont(&b521::from_bytes_be(b))
    }
    fn invert(&self, a: &Self::Elem) -> Self::Elem {
        pow_mod(self, a, &self.p_minus_2)
    }
}

pub struct Fast521Ctx {
    pub p: [u64; 9],
    pub p_minus_2: [u64; 9],
}

impl Fast521Ctx {
    pub fn new(p_hex: &str) -> Self {
        let p = b521::hex_to_limbs(p_hex);
        let p_minus_2 = two_and_pminus2!(b521, 9, p);
        Self { p, p_minus_2 }
    }
}

impl FieldCtx for Fast521Ctx {
    type Elem = [u64; 9];
    fn zero(&self) -> Self::Elem {
        [0; 9]
    }
    fn one(&self) -> Self::Elem {
        let mut v = [0u64; 9];
        v[0] = 1;
        v
    }
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b521::add_mod(a, b, &self.p)
    }
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        b521::sub_mod(a, b, &self.p)
    }
    fn neg(&self, a: &Self::Elem) -> Self::Elem {
        b521::neg_mod(a, &self.p)
    }
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem {
        fastreduce::fast_reduce_p521(&b521::mul_wide(a, b), &self.p)
    }
    fn is_zero(&self, a: &Self::Elem) -> bool {
        b521::is_zero(a)
    }
    fn from_bytes_be(&self, b: &[u8]) -> Self::Elem {
        b521::from_bytes_be(b)
    }
    fn invert(&self, a: &Self::Elem) -> Self::Elem {
        pow_mod(self, a, &self.p_minus_2)
    }
}
