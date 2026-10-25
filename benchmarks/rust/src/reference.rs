use crate::io::parse_answers;

fn hex_eq(got: &[u8], want_hex: &str) -> bool {
    let want = want_hex.trim_start_matches('0');
    let mut got_hex = String::new();
    for b in got {
        got_hex.push_str(&format!("{:02x}", b));
    }
    let got_trim = got_hex.trim_start_matches('0');
    let want_lower = if want.is_empty() { "0" } else { want };
    let got_final = if got_trim.is_empty() { "0" } else { got_trim };
    got_final.eq_ignore_ascii_case(want_lower)
}

pub fn validate_all(answers_path: &str) -> Result<(), String> {
    let answers = parse_answers(answers_path);
    let mut checked = 0usize;
    for a in &answers {
        match a.curve.as_str() {
            "P-256" => {
                use p256::elliptic_curve::sec1::ToSec1Point;
                use p256::{ProjectivePoint, Scalar};
                let scalar = Scalar::from(a.d);
                let point = ProjectivePoint::GENERATOR * scalar;
                let enc = point.to_affine().to_encoded_point(false);
                let x = enc.x().ok_or("p256: no x")?;
                let y = enc.y().ok_or("p256: no y")?;
                if !hex_eq(x, &a.x_hex) || !hex_eq(y, &a.y_hex) {
                    return Err(format!("P-256 d={} mismatch vs RustCrypto", a.d));
                }
                checked += 1;
            }
            "P-384" => {
                use p384::elliptic_curve::sec1::ToSec1Point;
                use p384::{ProjectivePoint, Scalar};
                let scalar = Scalar::from(a.d);
                let point = ProjectivePoint::GENERATOR * scalar;
                let enc = point.to_affine().to_encoded_point(false);
                let x = enc.x().ok_or("p384: no x")?;
                let y = enc.y().ok_or("p384: no y")?;
                if !hex_eq(x, &a.x_hex) || !hex_eq(y, &a.y_hex) {
                    return Err(format!("P-384 d={} mismatch vs RustCrypto", a.d));
                }
                checked += 1;
            }
            "P-521" => {
                use p521::elliptic_curve::sec1::ToSec1Point;
                use p521::{ProjectivePoint, Scalar};
                let scalar = Scalar::from(a.d);
                let point = ProjectivePoint::GENERATOR * scalar;
                let enc = point.to_affine().to_encoded_point(false);
                let x = enc.x().ok_or("p521: no x")?;
                let y = enc.y().ok_or("p521: no y")?;
                if !hex_eq(x, &a.x_hex) || !hex_eq(y, &a.y_hex) {
                    return Err(format!("P-521 d={} mismatch vs RustCrypto", a.d));
                }
                checked += 1;
            }
            other => return Err(format!("unknown curve in answers.tsv: {other}")),
        }
    }
    if checked != answers.len() {
        return Err(format!("only checked {checked}/{} controls", answers.len()));
    }
    Ok(())
}

/// Optional comparison datapoint (spec item 5): ns/add for RustCrypto's own
/// constant-time mixed Projective+=Affine add, same shape as `jac_madd`.
/// Measured result is mixed, not uniformly slower -- see README.md.
pub fn bench_madd_ns_p256(iters: u64) -> f64 {
    use p256::{ProjectivePoint, Scalar};
    let g_affine = ProjectivePoint::GENERATOR.to_affine();
    let mut cur = ProjectivePoint::GENERATOR * Scalar::from(2u64);
    let start = std::time::Instant::now();
    for _ in 0..iters {
        cur = cur + &g_affine;
        std::hint::black_box(&cur);
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}

pub fn bench_madd_ns_p384(iters: u64) -> f64 {
    use p384::{ProjectivePoint, Scalar};
    let g_affine = ProjectivePoint::GENERATOR.to_affine();
    let mut cur = ProjectivePoint::GENERATOR * Scalar::from(2u64);
    let start = std::time::Instant::now();
    for _ in 0..iters {
        cur = cur + &g_affine;
        std::hint::black_box(&cur);
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}

pub fn bench_madd_ns_p521(iters: u64) -> f64 {
    use p521::{ProjectivePoint, Scalar};
    let g_affine = ProjectivePoint::GENERATOR.to_affine();
    let mut cur = ProjectivePoint::GENERATOR * Scalar::from(2u64);
    let start = std::time::Instant::now();
    for _ in 0..iters {
        cur = cur + &g_affine;
        std::hint::black_box(&cur);
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}
