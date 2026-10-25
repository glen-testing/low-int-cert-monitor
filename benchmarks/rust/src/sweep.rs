use std::collections::HashMap;

use crate::field::FieldCtx;
use crate::point::{batch_normalize, jac_double, jac_madd, jac_scalar_mul, Affine, Jacobian};

/// Visits (d, dG) for d = 1..=count, in blocks of `block`, each block
/// normalized to affine with a single batched inversion (Montgomery's trick).
pub fn sweep_multiples<C: FieldCtx>(
    ctx: &C,
    g: &Affine<C::Elem>,
    count: u64,
    block: usize,
    mut visit: impl FnMut(u64, &Affine<C::Elem>),
) {
    if count == 0 {
        return;
    }
    visit(1, g);
    if count == 1 {
        return;
    }
    let mut acc = jac_double(ctx, &Jacobian { x: g.x, y: g.y, z: ctx.one() });
    let mut j: u64 = 2;
    let mut buf: Vec<Jacobian<C::Elem>> = Vec::with_capacity(block);
    while j <= count {
        let take = std::cmp::min(block as u64, count - j + 1) as usize;
        buf.clear();
        for _ in 0..take {
            buf.push(acc);
            acc = jac_madd(ctx, &acc, g);
        }
        let affs = batch_normalize(ctx, &buf);
        for (k, a) in affs.iter().enumerate() {
            visit(j + k as u64, a);
        }
        j += take as u64;
    }
}

pub fn build_baby_table<C: FieldCtx>(
    ctx: &C,
    g: &Affine<C::Elem>,
    m_b: u64,
    block: usize,
) -> HashMap<(C::Elem, C::Elem), u64> {
    let mut table = HashMap::with_capacity(m_b as usize);
    sweep_multiples(ctx, g, m_b, block, |j, p| {
        table.insert((p.x, p.y), j);
    });
    table
}

/// Variant 4: BSGS. Baby table + giant stride built once per curve; giant
/// steps advance every live target in lock-step and batch-normalize them
/// together, so membership checks cost one inversion per giant-step index
/// (not per target, not per step).
pub fn bsgs_search<C: FieldCtx>(
    ctx: &C,
    g: &Affine<C::Elem>,
    targets: &[Affine<C::Elem>],
    max_d: u64,
    m_b: u64,
    block: usize,
) -> Vec<Option<u64>> {
    let m_b = m_b.max(1);
    let m_g = (max_d + m_b - 1) / m_b;
    let baby = build_baby_table(ctx, g, m_b, block);

    let stride_jac = jac_scalar_mul(ctx, g, m_b);
    let stride_aff = batch_normalize(ctx, &[stride_jac])[0];
    let neg_stride = Affine { x: stride_aff.x, y: ctx.neg(&stride_aff.y) };

    let mut results: Vec<Option<u64>> = vec![None; targets.len()];
    let mut active: Vec<(usize, Jacobian<C::Elem>)> = targets
        .iter()
        .enumerate()
        .map(|(idx, t)| (idx, Jacobian { x: t.x, y: t.y, z: ctx.one() }))
        .collect();

    let mut i: u64 = 0;
    while i < m_g && !active.is_empty() {
        let pts: Vec<Jacobian<C::Elem>> = active.iter().map(|(_, p)| *p).collect();
        let affs = batch_normalize(ctx, &pts);
        for (k, (idx, _)) in active.iter().enumerate() {
            if let Some(&j) = baby.get(&(affs[k].x, affs[k].y)) {
                let d = i * m_b + j;
                if d >= 1 && d <= max_d {
                    results[*idx] = Some(d);
                }
            }
        }
        active.retain(|(idx, _)| results[*idx].is_none());
        if i + 1 < m_g && !active.is_empty() {
            for (_, p) in active.iter_mut() {
                *p = jac_madd(ctx, p, &neg_stride);
            }
        }
        i += 1;
    }
    results
}

/// Variant 2 functional path for `bench --method linear`: one pass d=1..max,
/// batched normalization, hashed membership check against the target set.
pub fn linear_sweep<C: FieldCtx>(
    ctx: &C,
    g: &Affine<C::Elem>,
    targets: &[Affine<C::Elem>],
    max_d: u64,
    block: usize,
) -> Vec<Option<u64>> {
    let mut lookup: HashMap<(C::Elem, C::Elem), Vec<usize>> = HashMap::with_capacity(targets.len());
    for (idx, t) in targets.iter().enumerate() {
        lookup.entry((t.x, t.y)).or_default().push(idx);
    }
    let mut results: Vec<Option<u64>> = vec![None; targets.len()];
    sweep_multiples(ctx, g, max_d, block, |d, p| {
        if let Some(idxs) = lookup.get(&(p.x, p.y)) {
            for &idx in idxs {
                results[idx] = Some(d);
            }
        }
    });
    results
}
