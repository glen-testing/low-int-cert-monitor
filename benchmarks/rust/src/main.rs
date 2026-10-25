mod bench;
mod bigint;
mod curves;
mod fastreduce;
mod field;
mod io;
mod montgomery;
mod point;
mod reference;
mod sweep;

use field::{Fast256Ctx, Fast384Ctx, Fast521Ctx, FieldCtx, Mont256Ctx, Mont384Ctx, Mont521Ctx};
use io::{AnswerRow, TargetRow};
use point::Affine;

fn hex_to_bytes(h: &str) -> Vec<u8> {
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
    let b = h.as_bytes();
    let mut out = Vec::with_capacity(h.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).expect("bad hex digit");
        let lo = (b[i + 1] as char).to_digit(16).expect("bad hex digit");
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    out
}

struct CurveReport {
    /// (target index, found d) for rows NOT in answers.tsv that still hit --
    /// genuine false positives among the live CCADB keys.
    false_positives: Vec<(usize, u64)>,
    /// (expected d, what BSGS actually found) for each control, matched by
    /// (x,y) against answers.tsv -- the 12 controls are embedded as rows
    /// inside targets.tsv itself (802 = 790 live + 12 planted), not a
    /// disjoint held-out set.
    control_results: Vec<(u64, Option<u64>)>,
}

fn affine_from_hex<C: FieldCtx>(ctx: &C, x_hex: &str, y_hex: &str) -> Affine<C::Elem> {
    Affine {
        x: ctx.from_bytes_be(&hex_to_bytes(x_hex)),
        y: ctx.from_bytes_be(&hex_to_bytes(y_hex)),
    }
}

/// Tuned baby/giant split: naive sqrt(max_d) starves on giant-step inversions
/// since those amortize over only `n_targets`, not a tunable block. See
/// README.md ("baby/giant split is tuned") for the derivation.
fn optimal_m_b<C: FieldCtx>(ctx: &C, g: &Affine<C::Elem>, max_d: u64, n_targets: u64) -> u64 {
    let madd_ns = bench::measure_jac_madd(ctx, g, 2_000).max(1.0);
    let seed = ctx.add(&g.x, &g.y); // arbitrary nonzero-ish seed, cheap to derive
    let invert_ns = bench::measure_invert_ns(ctx, &seed, 50).max(1.0);
    let ratio = invert_ns / madd_ns;
    let m_b = ((max_d as f64) * (n_targets as f64 + ratio)).sqrt().ceil() as u64;
    m_b.clamp(1, max_d.max(1))
}

fn run_bsgs_for_curve<C: FieldCtx>(
    ctx: &C,
    hex: &curves::CurveHex,
    target_rows: &[&TargetRow],
    answer_rows: &[&AnswerRow],
    max_d: u64,
    block: usize,
) -> CurveReport {
    let g = affine_from_hex(ctx, hex.gx, hex.gy);
    let rows: Vec<Affine<C::Elem>> = target_rows.iter().map(|r| affine_from_hex(ctx, &r.x_hex, &r.y_hex)).collect();
    let m_b = optimal_m_b(ctx, &g, max_d, rows.len() as u64);
    let results = sweep::bsgs_search(ctx, &g, &rows, max_d, m_b, block);

    // The 12 planted controls are rows inside targets.tsv (matched by exact
    // point), not a separate set, so classify each target row accordingly.
    let mut control_d_by_point: std::collections::HashMap<(String, String), u64> = std::collections::HashMap::new();
    for a in answer_rows {
        control_d_by_point.insert((a.x_hex.to_lowercase(), a.y_hex.to_lowercase()), a.d);
    }
    let mut control_found: std::collections::HashMap<u64, Option<u64>> =
        control_d_by_point.values().map(|&d| (d, None)).collect();

    let mut false_positives = Vec::new();
    for (i, r) in target_rows.iter().enumerate() {
        let key = (r.x_hex.to_lowercase(), r.y_hex.to_lowercase());
        if let Some(&expected_d) = control_d_by_point.get(&key) {
            control_found.insert(expected_d, results[i]);
        } else if let Some(d) = results[i] {
            false_positives.push((i, d));
        }
    }
    CurveReport { false_positives, control_results: control_found.into_iter().collect() }
}

const CURVE_NAMES: [&str; 3] = ["P-256", "P-384", "P-521"];

fn curve_hex(name: &str) -> &'static curves::CurveHex {
    match name {
        "P-256" => &curves::HEX_P256,
        "P-384" => &curves::HEX_P384,
        "P-521" => &curves::HEX_P521,
        _ => panic!("unknown curve {name}"),
    }
}

/// Runs BSGS using the fastest VALIDATED backend per curve (measured by
/// `variants`; see README.md's ns/add table): Montgomery for P-256, Fast
/// (Solinas/Mersenne) for P-384/P-521.
fn run_curve_best(
    name: &str,
    targets: &[&TargetRow],
    answers: &[&AnswerRow],
    max_d: u64,
    block: usize,
) -> CurveReport {
    let hex = curve_hex(name);
    match name {
        "P-256" => {
            let ctx = Mont256Ctx::new(hex.p);
            run_bsgs_for_curve(&ctx, hex, targets, answers, max_d, block)
        }
        "P-384" => {
            let ctx = Fast384Ctx::new(hex.p);
            run_bsgs_for_curve(&ctx, hex, targets, answers, max_d, block)
        }
        "P-521" => {
            let ctx = Fast521Ctx::new(hex.p);
            run_bsgs_for_curve(&ctx, hex, targets, answers, max_d, block)
        }
        _ => panic!("unknown curve {name}"),
    }
}

fn split_by_curve<'a>(targets: &'a [TargetRow]) -> std::collections::HashMap<&'a str, Vec<&'a TargetRow>> {
    let mut map: std::collections::HashMap<&str, Vec<&TargetRow>> = std::collections::HashMap::new();
    for t in targets {
        map.entry(t.curve.as_str()).or_default().push(t);
    }
    map
}

fn split_answers_by_curve<'a>(answers: &'a [AnswerRow]) -> std::collections::HashMap<&'a str, Vec<&'a AnswerRow>> {
    let mut map: std::collections::HashMap<&str, Vec<&AnswerRow>> = std::collections::HashMap::new();
    for a in answers {
        map.entry(a.curve.as_str()).or_default().push(a);
    }
    map
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn block_for(max_d: u64) -> usize {
    // Baby-table / sweep block size: bigger blocks amortize the one
    // Montgomery's-trick inversion per block further (cheap in memory --
    // a few hundred KB at most for our field-element sizes).
    let m_b = (max_d as f64).sqrt().ceil() as usize;
    m_b.min(8192).max(64)
}

fn cmd_selftest(args: &[String]) -> i32 {
    let targets_path = arg_value(args, "--targets").unwrap_or_else(|| "../common/targets.tsv".into());
    let answers_path = arg_value(args, "--answers").unwrap_or_else(|| "../common/answers.tsv".into());
    let max_d: u64 = arg_value(args, "--max").and_then(|s| s.parse().ok()).unwrap_or(100_000_000);

    eprintln!("[validate] cross-checking field arithmetic against RustCrypto...");
    if let Err(e) = reference::validate_all(&answers_path) {
        eprintln!("[validate] FAILED: {e}");
        return 1;
    }
    eprintln!("[validate] OK: hand-rolled field arithmetic matches RustCrypto on all 12 controls, 3 curves.");

    let targets = io::parse_targets(&targets_path);
    let answers = io::parse_answers(&answers_path);
    let t_by_curve = split_by_curve(&targets);
    let a_by_curve = split_answers_by_curve(&answers);

    let mut total_hits = 0usize;
    let mut total_answer_fail = 0usize;
    let mut fail_detail: Vec<String> = Vec::new();

    for &curve in CURVE_NAMES.iter() {
        let empty_t: Vec<&TargetRow> = Vec::new();
        let empty_a: Vec<&AnswerRow> = Vec::new();
        let t = t_by_curve.get(curve).unwrap_or(&empty_t);
        let a = a_by_curve.get(curve).unwrap_or(&empty_a);
        let block = block_for(max_d);
        let start = std::time::Instant::now();
        let report = run_curve_best(curve, t, a, max_d, block);
        let elapsed = start.elapsed();
        eprintln!(
            "[selftest] {curve}: {} live targets, {} controls, max_d={max_d}, wall={:.2}s",
            t.len(),
            a.len(),
            elapsed.as_secs_f64()
        );
        if !report.false_positives.is_empty() {
            total_hits += report.false_positives.len();
            for (idx, d) in &report.false_positives {
                fail_detail.push(format!("  FALSE POSITIVE: {curve} live target #{idx} flagged at d={d}"));
            }
        }
        for (expected_d, got) in &report.control_results {
            if *got != Some(*expected_d) {
                total_answer_fail += 1;
                match got {
                    Some(wrong_d) => fail_detail.push(format!(
                        "  WRONG CONTROL d: {curve} expected d={expected_d}, got d={wrong_d}"
                    )),
                    None => fail_detail
                        .push(format!("  MISSED CONTROL: {curve} expected d={expected_d}, not found")),
                }
            }
        }
    }

    if total_hits == 0 && total_answer_fail == 0 {
        eprintln!("[selftest] PASS: 12/12 controls found at correct d, 0/790 false positives.");
        0
    } else {
        eprintln!("[selftest] FAIL: {total_hits} false positives, {total_answer_fail} missed/wrong controls.");
        for line in fail_detail {
            eprintln!("{line}");
        }
        1
    }
}

fn cmd_bench(args: &[String]) -> i32 {
    let targets_path = arg_value(args, "--targets").unwrap_or_else(|| "../common/targets.tsv".into());
    let max_d: u64 = arg_value(args, "--max").and_then(|s| s.parse().ok()).unwrap_or(100_000_000);
    let method = arg_value(args, "--method").unwrap_or_else(|| "bsgs".into());
    let field = arg_value(args, "--field").unwrap_or_else(|| "fast".into());

    let targets = io::parse_targets(&targets_path);
    let t_by_curve = split_by_curve(&targets);
    let block = block_for(max_d);

    for &curve in CURVE_NAMES.iter() {
        let empty_t: Vec<&TargetRow> = Vec::new();
        let t = t_by_curve.get(curve).unwrap_or(&empty_t);
        if t.is_empty() {
            continue;
        }
        let hex = curve_hex(curve);
        let (ns_per_add, elapsed, hits) = match (curve, field.as_str(), method.as_str()) {
            ("P-256", "fast", "bsgs") => bench_one(Fast256Ctx::new(hex.p), hex, t, max_d, block, true),
            ("P-256", "fast", _) => bench_one(Fast256Ctx::new(hex.p), hex, t, max_d, block, false),
            ("P-256", _, "bsgs") => bench_one(Mont256Ctx::new(hex.p), hex, t, max_d, block, true),
            ("P-256", _, _) => bench_one(Mont256Ctx::new(hex.p), hex, t, max_d, block, false),
            ("P-384", "fast", "bsgs") => bench_one(Fast384Ctx::new(hex.p), hex, t, max_d, block, true),
            ("P-384", "fast", _) => bench_one(Fast384Ctx::new(hex.p), hex, t, max_d, block, false),
            ("P-384", _, "bsgs") => bench_one(Mont384Ctx::new(hex.p), hex, t, max_d, block, true),
            ("P-384", _, _) => bench_one(Mont384Ctx::new(hex.p), hex, t, max_d, block, false),
            ("P-521", "fast", "bsgs") => bench_one(Fast521Ctx::new(hex.p), hex, t, max_d, block, true),
            ("P-521", "fast", _) => bench_one(Fast521Ctx::new(hex.p), hex, t, max_d, block, false),
            ("P-521", _, "bsgs") => bench_one(Mont521Ctx::new(hex.p), hex, t, max_d, block, true),
            ("P-521", _, _) => bench_one(Mont521Ctx::new(hex.p), hex, t, max_d, block, false),
            _ => unreachable!(),
        };
        eprintln!(
            "[bench] {curve} field={field} method={method}: ns/add(amortized)={ns_per_add:.1} wall={:.3}s hits={}",
            elapsed.as_secs_f64(),
            hits.len()
        );
        for (idx, d) in hits {
            println!("{curve}\t{idx}\td={d}");
        }
    }
    0
}

fn bench_one<C: FieldCtx>(
    ctx: C,
    hex: &curves::CurveHex,
    targets: &[&TargetRow],
    max_d: u64,
    block: usize,
    use_bsgs: bool,
) -> (f64, std::time::Duration, Vec<(usize, u64)>) {
    let g = affine_from_hex(&ctx, hex.gx, hex.gy);
    let calib_iters = 2_000_000u64;
    let ns_per_add = bench::measure_batched_sweep(&ctx, &g, calib_iters, block);

    let rows: Vec<Affine<C::Elem>> = targets.iter().map(|r| affine_from_hex(&ctx, &r.x_hex, &r.y_hex)).collect();
    let start = std::time::Instant::now();
    let results = if use_bsgs {
        let m_b = optimal_m_b(&ctx, &g, max_d, rows.len() as u64);
        sweep::bsgs_search(&ctx, &g, &rows, max_d, m_b, block)
    } else {
        sweep::linear_sweep(&ctx, &g, &rows, max_d, block)
    };
    let elapsed = start.elapsed();
    let hits: Vec<(usize, u64)> = results
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.map(|d| (i, d)))
        .collect();
    (ns_per_add, elapsed, hits)
}

fn cmd_cert(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: wkd cert <file.pem|der> [--max N]");
        return 2;
    }
    let file = &args[0];
    let max_d: u64 = arg_value(args, "--max").and_then(|s| s.parse().ok()).unwrap_or(100_000_000);
    let point = match io::extract_point_from_file(file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let block = block_for(max_d);
    let row = TargetRow { curve: point.curve.clone(), x_hex: point.x_hex.clone(), y_hex: point.y_hex.clone() };
    let empty_a: Vec<&AnswerRow> = Vec::new();
    let result = match point.curve.as_str() {
        "P-256" | "P-384" | "P-521" => {
            let report = run_curve_best(&point.curve, &[&row], &empty_a, max_d, block);
            report.false_positives.first().map(|&(_, d)| d)
        }
        _ => None,
    };
    match result {
        Some(d) => {
            println!("WEAK: curve={} d={} (public point = d*G for a trivially small d)", point.curve, d);
            1
        }
        None => {
            println!("clean: curve={} no small scalar d<={} found", point.curve, max_d);
            0
        }
    }
}

fn cmd_variants(args: &[String]) -> i32 {
    let iters_slow: u64 = arg_value(args, "--iters-slow").and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let iters_fast: u64 = arg_value(args, "--iters-fast").and_then(|s| s.parse().ok()).unwrap_or(3_000_000);
    println!("curve\tfield\taffine_inv_ns\tjac_raw_ns\tjac_batched_ns");
    for &curve in CURVE_NAMES.iter() {
        let hex = curve_hex(curve);
        macro_rules! row {
            ($ctx:expr, $label:expr) => {{
                let ctx = $ctx;
                let g = affine_from_hex(&ctx, hex.gx, hex.gy);
                let a = bench::measure_affine_add(&ctx, &g, iters_slow);
                let j = bench::measure_jac_madd(&ctx, &g, iters_fast);
                let jb = bench::measure_batched_sweep(&ctx, &g, iters_fast, block_for(1_000_000));
                println!("{curve}\t{}\t{a:.1}\t{j:.1}\t{jb:.1}", $label);
            }};
        }
        match curve {
            "P-256" => {
                row!(Mont256Ctx::new(hex.p), "mont");
                row!(Fast256Ctx::new(hex.p), "fast");
            }
            "P-384" => {
                row!(Mont384Ctx::new(hex.p), "mont");
                row!(Fast384Ctx::new(hex.p), "fast");
            }
            "P-521" => {
                row!(Mont521Ctx::new(hex.p), "mont");
                row!(Fast521Ctx::new(hex.p), "fast");
            }
            _ => unreachable!(),
        }
    }
    println!("--- optional comparison datapoint: RustCrypto (constant-time) mixed add ---");
    println!("curve\tfield\tjac_raw_ns");
    println!("P-256\trustcrypto\t{:.1}", reference::bench_madd_ns_p256(iters_fast));
    println!("P-384\trustcrypto\t{:.1}", reference::bench_madd_ns_p384(iters_fast));
    println!("P-521\trustcrypto\t{:.1}", reference::bench_madd_ns_p521(iters_fast));
    0
}

fn main() {
    let all: Vec<String> = std::env::args().collect();
    if all.len() < 2 {
        eprintln!("usage: wkd <bench|selftest|cert|variants> [args...]");
        std::process::exit(2);
    }
    let sub = all[1].as_str();
    let rest: Vec<String> = all[2..].to_vec();
    let code = match sub {
        "bench" => cmd_bench(&rest),
        "selftest" => cmd_selftest(&rest),
        "cert" => cmd_cert(&rest),
        "variants" => cmd_variants(&rest),
        _ => {
            eprintln!("unknown subcommand {sub}");
            2
        }
    };
    std::process::exit(code);
}
