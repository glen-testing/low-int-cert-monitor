use crate::field::FieldCtx;
use crate::point::{affine_add, affine_double, jac_double, jac_madd, Affine, Jacobian};
use crate::sweep::sweep_multiples;

fn time_ns<F: FnMut()>(mut f: F, iters: u64) -> f64 {
    let start = std::time::Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}

/// Variant 1: affine addition, one modular inverse per add.
pub fn measure_affine_add<C: FieldCtx>(ctx: &C, g: &Affine<C::Elem>, iters: u64) -> f64 {
    let mut cur = affine_double(ctx, g);
    let ns = time_ns(
        || {
            cur = affine_add(ctx, &cur, g);
            std::hint::black_box(&cur);
        },
        iters,
    );
    ns
}

/// Variant 2 (raw): Jacobian mixed addition, inversion-free, unbatched.
pub fn measure_jac_madd<C: FieldCtx>(ctx: &C, g: &Affine<C::Elem>, iters: u64) -> f64 {
    let mut cur = jac_double(ctx, &Jacobian { x: g.x, y: g.y, z: ctx.one() });
    let ns = time_ns(
        || {
            cur = jac_madd(ctx, &cur, g);
            std::hint::black_box(&cur);
        },
        iters,
    );
    ns
}

/// Raw modular inverse cost: BSGS giant steps amortize one inversion over
/// only `n_targets` points (not a tunable block), so this cost -- not the
/// raw add cost -- decides the baby/giant split that minimizes wall time.
pub fn measure_invert_ns<C: FieldCtx>(ctx: &C, seed: &C::Elem, iters: u64) -> f64 {
    let mut cur = *seed;
    time_ns(
        || {
            cur = ctx.invert(&cur);
            std::hint::black_box(&cur);
        },
        iters,
    )
}

/// Variant 2 (amortized): Jacobian adds with batched (Montgomery's-trick)
/// normalization folded in, block-sized B, as used by the real sweep.
pub fn measure_batched_sweep<C: FieldCtx>(ctx: &C, g: &Affine<C::Elem>, iters: u64, block: usize) -> f64 {
    let start = std::time::Instant::now();
    sweep_multiples(ctx, g, iters, block, |_, p| {
        std::hint::black_box(p);
    });
    start.elapsed().as_nanos() as f64 / iters as f64
}
