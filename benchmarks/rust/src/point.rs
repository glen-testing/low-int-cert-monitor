use crate::field::FieldCtx;

#[derive(Clone, Copy)]
pub struct Affine<E> {
    pub x: E,
    pub y: E,
}

#[derive(Clone, Copy)]
pub struct Jacobian<E> {
    pub x: E,
    pub y: E,
    pub z: E,
}

/// Variant 1 baseline: affine doubling, one modular inverse per call.
pub fn affine_double<C: FieldCtx>(ctx: &C, p: &Affine<C::Elem>) -> Affine<C::Elem> {
    let three_x2 = {
        let x2 = ctx.square(&p.x);
        let x2_2 = ctx.add(&x2, &x2);
        ctx.add(&x2_2, &x2)
    };
    let three = {
        let one = ctx.one();
        let two = ctx.add(&one, &one);
        ctx.add(&two, &one)
    };
    let num = ctx.sub(&three_x2, &three);
    let two_y = ctx.add(&p.y, &p.y);
    let inv = ctx.invert(&two_y);
    let lambda = ctx.mul(&num, &inv);
    let lambda2 = ctx.square(&lambda);
    let two_x = ctx.add(&p.x, &p.x);
    let x3 = ctx.sub(&lambda2, &two_x);
    let y3 = ctx.sub(&ctx.mul(&lambda, &ctx.sub(&p.x, &x3)), &p.y);
    Affine { x: x3, y: y3 }
}

/// Variant 1 baseline: affine addition for P != Q, one modular inverse per call.
pub fn affine_add<C: FieldCtx>(ctx: &C, p: &Affine<C::Elem>, q: &Affine<C::Elem>) -> Affine<C::Elem> {
    let dx = ctx.sub(&q.x, &p.x);
    let dy = ctx.sub(&q.y, &p.y);
    let inv = ctx.invert(&dx);
    let lambda = ctx.mul(&dy, &inv);
    let lambda2 = ctx.square(&lambda);
    let x3 = ctx.sub(&ctx.sub(&lambda2, &p.x), &q.x);
    let y3 = ctx.sub(&ctx.mul(&lambda, &ctx.sub(&p.x, &x3)), &p.y);
    Affine { x: x3, y: y3 }
}

/// Variant 2: Jacobian doubling (a=-3), inversion-free ("dbl-2007-bl").
pub fn jac_double<C: FieldCtx>(ctx: &C, p: &Jacobian<C::Elem>) -> Jacobian<C::Elem> {
    let delta = ctx.square(&p.z);
    let gamma = ctx.square(&p.y);
    let beta = ctx.mul(&p.x, &gamma);
    let x1_minus_delta = ctx.sub(&p.x, &delta);
    let x1_plus_delta = ctx.add(&p.x, &delta);
    let alpha0 = ctx.mul(&x1_minus_delta, &x1_plus_delta);
    let alpha = {
        let a2 = ctx.add(&alpha0, &alpha0);
        ctx.add(&a2, &alpha0)
    };
    let beta4 = {
        let b2 = ctx.add(&beta, &beta);
        ctx.add(&b2, &b2)
    };
    let beta8 = ctx.add(&beta4, &beta4);
    let x3 = ctx.sub(&ctx.square(&alpha), &beta8);
    let y1_plus_z1 = ctx.add(&p.y, &p.z);
    let z3 = ctx.sub(&ctx.sub(&ctx.square(&y1_plus_z1), &gamma), &delta);
    let gamma2 = ctx.square(&gamma);
    let gamma8 = {
        let g2 = ctx.add(&gamma2, &gamma2);
        let g4 = ctx.add(&g2, &g2);
        ctx.add(&g4, &g4)
    };
    let y3 = ctx.sub(&ctx.mul(&alpha, &ctx.sub(&beta4, &x3)), &gamma8);
    Jacobian { x: x3, y: y3, z: z3 }
}

/// Variant 2: Jacobian += affine, inversion-free mixed addition ("madd-2007-bl").
/// Precondition: the two points are never equal within our sweep (see module docs).
pub fn jac_madd<C: FieldCtx>(ctx: &C, p: &Jacobian<C::Elem>, q: &Affine<C::Elem>) -> Jacobian<C::Elem> {
    let z1z1 = ctx.square(&p.z);
    let u2 = ctx.mul(&q.x, &z1z1);
    let s2 = ctx.mul(&ctx.mul(&q.y, &p.z), &z1z1);
    let h = ctx.sub(&u2, &p.x);
    let hh = ctx.square(&h);
    let i = ctx.add(&hh, &hh);
    let i = ctx.add(&i, &i);
    let j = ctx.mul(&h, &i);
    let r0 = ctx.sub(&s2, &p.y);
    let r = ctx.add(&r0, &r0);
    let v = ctx.mul(&p.x, &i);
    let v2 = ctx.add(&v, &v);
    let x3 = ctx.sub(&ctx.sub(&ctx.square(&r), &j), &v2);
    let y1j = ctx.mul(&p.y, &j);
    let y1j2 = ctx.add(&y1j, &y1j);
    let y3 = ctx.sub(&ctx.mul(&r, &ctx.sub(&v, &x3)), &y1j2);
    let z3 = ctx.add(&ctx.mul(&p.z, &h), &ctx.mul(&p.z, &h));
    Jacobian { x: x3, y: y3, z: z3 }
}

/// Montgomery's trick: normalize a whole block of Jacobian points to affine
/// with exactly one field inversion for the entire block.
pub fn batch_normalize<C: FieldCtx>(ctx: &C, pts: &[Jacobian<C::Elem>]) -> Vec<Affine<C::Elem>> {
    let n = pts.len();
    if n == 0 {
        return Vec::new();
    }
    let mut prefix: Vec<C::Elem> = Vec::with_capacity(n + 1);
    prefix.push(ctx.one());
    for p in pts {
        let last = *prefix.last().unwrap();
        prefix.push(ctx.mul(&last, &p.z));
    }
    let mut inv_total = ctx.invert(&prefix[n]);
    let mut out = vec![
        Affine { x: ctx.zero(), y: ctx.zero() };
        n
    ];
    for i in (0..n).rev() {
        let inv_zi = ctx.mul(&inv_total, &prefix[i]);
        let inv_zi2 = ctx.square(&inv_zi);
        let inv_zi3 = ctx.mul(&inv_zi2, &inv_zi);
        out[i] = Affine {
            x: ctx.mul(&pts[i].x, &inv_zi2),
            y: ctx.mul(&pts[i].y, &inv_zi3),
        };
        inv_total = ctx.mul(&inv_total, &pts[i].z);
    }
    out
}

/// Jacobian scalar multiplication via double-and-add. Only used to compute the
/// BSGS giant stride (once per curve/run), not performance critical.
pub fn jac_scalar_mul<C: FieldCtx>(ctx: &C, base: &Affine<C::Elem>, scalar: u64) -> Jacobian<C::Elem> {
    assert!(scalar >= 1);
    let mut acc = Jacobian { x: base.x, y: base.y, z: ctx.one() };
    let nbits = 64 - scalar.leading_zeros();
    for bit in (0..nbits - 1).rev() {
        acc = jac_double(ctx, &acc);
        if (scalar >> bit) & 1 == 1 {
            acc = jac_madd(ctx, &acc, base);
        }
    }
    acc
}
