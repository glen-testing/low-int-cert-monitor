use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::Instant;

const MAXD: u32 = 1_000_000;
const DEFAULT_TABLE: &str = "table.bin";
const DEFAULT_ANSWERS: &str = "/home/ec2-user/p4-inventory/common/answers.tsv";
const MAGIC: &[u8; 8] = b"P4MON001";

// compressed SEC1 length per curve: 1 prefix byte + field-size x
const L256: usize = 33; // field 32
const L384: usize = 49; // field 48
const L521: usize = 67; // field 66

type Map<const N: usize> = HashMap<[u8; N], u32, ahash::RandomState>;

struct Tables {
    p256: Map<L256>,
    p384: Map<L384>,
    p521: Map<L521>,
}

// ---- table build via RustCrypto reference curves ----------------------------
macro_rules! builder {
    ($name:ident, $cr:ident, $len:expr) => {
        fn $name(progress: &str) -> Vec<[u8; $len]> {
            use $cr::elliptic_curve::sec1::ToEncodedPoint;
            use $cr::ProjectivePoint;
            let g = ProjectivePoint::GENERATOR;
            let mut cur = g; // d = 1
            let mut out: Vec<[u8; $len]> = Vec::with_capacity(MAXD as usize);
            for d in 1..=MAXD {
                let aff = cur.to_affine();
                let ep = aff.to_encoded_point(true); // compressed
                let b = ep.as_bytes();
                let mut arr = [0u8; $len];
                arr.copy_from_slice(b);
                out.push(arr);
                cur = cur + g;
                if d % 200_000 == 0 {
                    eprintln!("  [{}] {}/{}", progress, d, MAXD);
                }
            }
            out
        }
    };
}
builder!(build_p256, p256, L256);
builder!(build_p384, p384, L384);
builder!(build_p521, p521, L521);

fn build_and_persist(path: &str) -> std::io::Result<()> {
    let t = Instant::now();
    eprintln!("building P-256 ..."); let a = build_p256("P-256");
    eprintln!("building P-384 ..."); let b = build_p384("P-384");
    eprintln!("building P-521 ..."); let c = build_p521("P-521");
    eprintln!("build done in {:.1}s; writing {}", t.elapsed().as_secs_f64(), path);
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    f.write_all(MAGIC)?;
    f.write_all(&MAXD.to_le_bytes())?;
    f.write_all(&3u32.to_le_bytes())?;
    for p in &a { f.write_all(p)?; }
    for p in &b { f.write_all(p)?; }
    for p in &c { f.write_all(p)?; }
    f.flush()?;
    eprintln!("wrote {} ({} entries/curve)", path, MAXD);
    Ok(())
}

fn load_tables(path: &str) -> std::io::Result<Tables> {
    let mut buf = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut buf)?;
    if buf.len() < 16 || &buf[0..8] != MAGIC {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad table file (run `build` first)"));
    }
    let n = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let mut off = 16usize;
    let hasher = ahash::RandomState::new(); // random per-process seed (resists hash-flooding)
    macro_rules! load {
        ($len:expr) => {{
            let mut m: Map<$len> = HashMap::with_capacity_and_hasher(n, hasher.clone());
            for i in 0..n {
                let mut k = [0u8; $len];
                k.copy_from_slice(&buf[off..off + $len]);
                off += $len;
                m.insert(k, (i as u32) + 1); // d = index + 1
            }
            m
        }};
    }
    let p256 = load!(L256);
    let p384 = load!(L384);
    let p521 = load!(L521);
    Ok(Tables { p256, p384, p521 })
}

// ---- point handling ---------------------------------------------------------
// Given a raw EC public point (SEC1, uncompressed 0x04 or compressed 0x02/0x03),
// return (curve_tag, compressed_key_len, compressed_key_bytes) or None.
// Allocation-free lookup: builds the compressed key on the stack from the raw
// SEC1 point slice (uncompressed 0x04||x||y or compressed 0x02/0x03||x). The
// y-parity prefix distinguishes d·G from (n−d)·G, so matches are exact.
#[inline]
fn lookup(t: &Tables, pt: &[u8]) -> Option<u32> {
    match *pt.first()? {
        0x04 => {
            let flen = match pt.len() { 65 => 32, 97 => 48, 133 => 66, _ => return None };
            let x = &pt[1..1 + flen];
            let prefix = 0x02 | (pt[2 * flen] & 1); // parity of y's last byte
            match flen {
                32 => { let mut k = [0u8; L256]; k[0] = prefix; k[1..].copy_from_slice(x); t.p256.get(&k).copied() }
                48 => { let mut k = [0u8; L384]; k[0] = prefix; k[1..].copy_from_slice(x); t.p384.get(&k).copied() }
                _  => { let mut k = [0u8; L521]; k[0] = prefix; k[1..].copy_from_slice(x); t.p521.get(&k).copied() }
            }
        }
        0x02 | 0x03 => match pt.len() {
            33 => { let k: [u8; L256] = pt.try_into().ok()?; t.p256.get(&k).copied() }
            49 => { let k: [u8; L384] = pt.try_into().ok()?; t.p384.get(&k).copied() }
            67 => { let k: [u8; L521] = pt.try_into().ok()?; t.p521.get(&k).copied() }
            _ => None,
        },
        _ => None,
    }
}

// Hot path: parse once, extract point slice (zero-copy), look up. Returns
// (is_ec, weak_d). No subject string, no point allocation.
#[inline]
fn check_der(t: &Tables, der: &[u8]) -> (bool, Option<u32>) {
    use x509_parser::prelude::*;
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => {
            let pt: &[u8] = cert.public_key().subject_public_key.data.as_ref();
            if matches!(pt.first(), Some(0x04 | 0x02 | 0x03)) { (true, lookup(t, pt)) } else { (false, None) }
        }
        Err(_) => (false, None),
    }
}

// Only called on an actual weak hit (rare) — re-parse to report the subject.
fn der_subject(der: &[u8]) -> String {
    use x509_parser::prelude::*;
    X509Certificate::from_der(der).map(|(_, c)| c.subject().to_string()).unwrap_or_default()
}

fn rss_mb() -> f64 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("VmRSS:") {
                if let Some(kb) = v.trim().split_whitespace().next() {
                    if let Ok(kb) = kb.parse::<f64>() { return kb / 1024.0; }
                }
            }
        }
    }
    0.0
}

// ---- hex + answers.tsv for selftest ----------------------------------------
fn hexdec(s: &str) -> Vec<u8> {
    let s = s.trim();
    let s = if s.len() % 2 == 1 { format!("0{}", s) } else { s.to_string() };
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn padl(v: Vec<u8>, n: usize) -> Vec<u8> {
    if v.len() >= n { return v[v.len() - n..].to_vec(); }
    let mut out = vec![0u8; n - v.len()];
    out.extend_from_slice(&v);
    out
}

fn selftest(ans: &str, tbl: &str) -> i32 {
    let t = match load_tables(tbl) { Ok(t) => t, Err(e) => { eprintln!("load error: {e}"); return 2; } };
    let data = match std::fs::read_to_string(ans) { Ok(d) => d, Err(e) => { eprintln!("answers read: {e}"); return 2; } };
    let mut ok = 0; let mut bad = 0;
    for line in data.lines() {
        if line.starts_with('#') || line.trim().is_empty() { continue; }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 4 { continue; }
        let (curve, xh, yh, d) = (f[0], f[1], f[2], f[3].parse::<u64>().unwrap());
        let flen = match curve { "P-256" => 32, "P-384" => 48, "P-521" => 66, _ => continue };
        let x = padl(hexdec(xh), flen);
        let y = padl(hexdec(yh), flen);
        let mut pt = vec![0x04u8]; pt.extend_from_slice(&x); pt.extend_from_slice(&y);
        let got = lookup(&t, &pt);
        let in_range = d <= MAXD as u64;
        let pass = if in_range { got == Some(d as u32) } else { got.is_none() };
        let note = if in_range { format!("expect d={d}") } else { format!("expect ABSENT (d={d} > {MAXD})") };
        println!("  {} {:<10} {:<28} got={:?}  [{}]", if pass {"PASS"} else {"FAIL"}, curve, note, got, if pass{"ok"}else{"MISMATCH"});
        if pass { ok += 1; } else { bad += 1; }
    }
    println!("\nselftest: {ok} pass, {bad} fail");
    if bad == 0 { 0 } else { 1 }
}

fn bench(tbl: &str) -> i32 {
    let t0 = Instant::now();
    let t = match load_tables(tbl) { Ok(t) => t, Err(e) => { eprintln!("load error: {e}"); return 2; } };
    println!("loaded 3x{} entries into RAM in {:.2}s; RSS {:.0} MB",
             MAXD, t0.elapsed().as_secs_f64(), rss_mb());
    // hit path: look up every stored P-384 point (reconstruct compressed keys)
    let keys: Vec<[u8; L384]> = t.p384.keys().copied().collect();
    let n = keys.len();
    let s = Instant::now();
    let mut acc = 0u64;
    for k in &keys { if t.p384.get(k).is_some() { acc += 1; } }
    let dt = s.elapsed().as_secs_f64();
    println!("hit-path  : {n} lookups in {:.3}s = {:.1} M/s ({:.1} ns/lookup) [hits {acc}]",
             dt, n as f64 / dt / 1e6, dt / n as f64 * 1e9);
    // miss path: 10M synthetic compressed points (won't be in table)
    let m = 10_000_000usize;
    let s = Instant::now();
    let mut miss = 0u64; let mut seed = 0x9e3779b97f4a7c15u64;
    let mut probe = [0x02u8; L384];
    for _ in 0..m {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        probe[1..9].copy_from_slice(&seed.to_le_bytes());
        if t.p384.get(&probe).is_none() { miss += 1; }
    }
    let dt = s.elapsed().as_secs_f64();
    println!("miss-path : {m} lookups in {:.3}s = {:.1} M/s ({:.1} ns/lookup) [miss {miss}]",
             dt, m as f64 / dt / 1e6, dt / m as f64 * 1e9);
    0
}

fn scan_corpus(path: &str, tbl: &str) -> i32 {
    let t = match load_tables(tbl) { Ok(t) => t, Err(e) => { eprintln!("load error: {e}"); return 2; } };
    println!("table in RAM; RSS {:.0} MB", rss_mb());
    let blob = match std::fs::read(path) { Ok(b) => b, Err(e) => { eprintln!("corpus read: {e}"); return 2; } };
    // index length-prefixed DER
    let mut certs: Vec<(usize, usize)> = Vec::new();
    let mut o = 0usize;
    while o + 4 <= blob.len() {
        let l = u32::from_le_bytes(blob[o..o + 4].try_into().unwrap()) as usize;
        o += 4;
        if o + l > blob.len() { break; }
        certs.push((o, l)); o += l;
    }
    let reps = std::env::var("REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(300usize);
    let s = Instant::now();
    let mut n = 0u64; let mut ec = 0u64; let mut weak = 0u64;
    let mut hits: Vec<(String, u32)> = Vec::new();
    for _ in 0..reps {
        for &(off, len) in &certs {
            n += 1;
            let der = &blob[off..off + len];
            let (is_ec, d) = check_der(&t, der);
            if is_ec {
                ec += 1;
                if let Some(d) = d {
                    weak += 1;
                    if hits.len() < 50 { hits.push((der_subject(der), d)); }
                }
            }
        }
    }
    let dt = s.elapsed().as_secs_f64();
    println!("scanned {} certs ({} EC) in {:.3}s", n, ec, dt);
    println!("  rate: {:.0} certs/sec ({:.2} us/cert)", n as f64 / dt, dt / n as f64 * 1e6);
    println!("  weak hits: {}", weak);
    for (s, d) in hits.iter().take(20) { println!("    WEAK d={:<6} {}", d, s); }
    0
}

#[inline]
fn fnv1a(b: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &x in b { h ^= x as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}

// 128-bit hash for dedup-before-parse: two independent FNV halves, collision
// probability negligible over millions of certs (so dedup never skips a distinct cert).
#[inline]
fn hash128(b: &[u8]) -> u128 {
    let (mut h1, mut h2) = (0xcbf29ce484222325u64, 0x84222325cbf29ce4u64);
    for &x in b {
        h1 ^= x as u64; h1 = h1.wrapping_mul(0x100000001b3);
        h2 = h2.wrapping_mul(0x100000001b3); h2 ^= x as u64;
    }
    ((h1 as u128) << 64) | (h2 as u128)
}

// Resident live-monitor mode: load table once, read [u32 len][DER] records from
// stdin forever, check each with a single lookup. Reused buffer, buffered reader.
// `sample` > 1 "sips" ~1/sample of certs (deterministic per-cert hash).
fn stream(tbl: &str, sample: u64) -> i32 {
    let t = match load_tables(tbl) { Ok(t) => t, Err(e) => { eprintln!("load error: {e}"); return 2; } };
    let dedup = std::env::var("DEDUP").is_ok();
    eprintln!("p4mon stream: table resident, RSS {:.0} MB; sample=1/{}; dedup={}; reading length-prefixed DER from stdin",
              rss_mb(), sample, dedup);
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicBool, Ordering::Relaxed};
    let seen = Arc::new(AtomicU64::new(0));
    let ec_seen = Arc::new(AtomicU64::new(0));
    let checked = Arc::new(AtomicU64::new(0));
    let dups = Arc::new(AtomicU64::new(0));
    let weak = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    // In-process telemetry thread: a line every 15s from our OWN counters + /proc/self RSS. No external calls.
    let th = {
        let (seen, ec_seen, checked, dups, weak, done) =
            (seen.clone(), ec_seen.clone(), checked.clone(), dups.clone(), weak.clone(), done.clone());
        std::thread::spawn(move || {
            let (mut last_seen, mut last_t) = (0u64, 0f64);
            loop {
                for _ in 0..15 { if done.load(Relaxed) { return; } std::thread::sleep(std::time::Duration::from_secs(1)); }
                let el = start.elapsed().as_secs_f64();
                let s = seen.load(Relaxed); let e = ec_seen.load(Relaxed); let dp = dups.load(Relaxed);
                let inst = (s - last_seen) as f64 / (el - last_t).max(1e-9);
                eprintln!("[t+{:>4.0}s] seen={} ec={} checked={} dups={} dedup={:.0}% weak={} cum={:.0}/s inst={:.0}/s rss={:.0}MB",
                          el, s, e, checked.load(Relaxed), dp,
                          if s > 0 { dp as f64 / s as f64 * 100.0 } else { 0.0 },
                          weak.load(Relaxed), s as f64 / el.max(1e-9), inst, rss_mb());
                last_seen = s; last_t = el;
            }
        })
    };
    let mut seen_keys: ahash::AHashSet<u128> = ahash::AHashSet::new();
    let mut findings = std::env::var("P4MON_FINDINGS").ok()
        .and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok());
    let mut r = std::io::BufReader::with_capacity(1 << 20, std::io::stdin().lock());
    let mut hdr = [0u8; 4];
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        if r.read_exact(&mut hdr).is_err() { break; }
        let len = u32::from_le_bytes(hdr) as usize;
        if len == 0 || len > (64 << 20) { break; }      // empty or absurd framing: stop
        if len > (1 << 20) {                             // oversized single record: skip it, stay frame-aligned
            let mut rem = len; let mut skip = [0u8; 8192]; let mut ok = true;
            while rem > 0 { let n = rem.min(skip.len()); if r.read_exact(&mut skip[..n]).is_err() { ok = false; break; } rem -= n; }
            if !ok { break; }
            continue;
        }
        buf.resize(len, 0);
        if r.read_exact(&mut buf).is_err() { break; }
        seen.fetch_add(1, Relaxed);
        if sample > 1 && fnv1a(&buf) % sample != 0 { continue; }
        if dedup {
            if seen_keys.len() >= 4_000_000 { seen_keys.clear(); } // bound memory for indefinite runs
            if !seen_keys.insert(hash128(&buf)) { dups.fetch_add(1, Relaxed); continue; } // skip identical certs before the parse
        }
        let (is_ec, d) = check_der(&t, &buf);
        if !is_ec { continue; }
        ec_seen.fetch_add(1, Relaxed);
        checked.fetch_add(1, Relaxed);
        if let Some(d) = d {
            weak.fetch_add(1, Relaxed);
            let subj = der_subject(&buf);
            println!("WEAK  d={}  {}", d, subj);
            if let Some(f) = findings.as_mut() {
                use std::io::Write;
                use sha2::{Sha256, Digest};
                let fp: String = Sha256::digest(&buf).iter().map(|b| format!("{:02x}", b)).collect();
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|x| x.as_secs()).unwrap_or(0);
                let subj_safe: String = subj.chars().map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '.' }).collect();
                let _ = writeln!(f, "{{\"ts\":{},\"d\":{},\"sha256\":{:?},\"subject\":{:?}}}", ts, d, fp, subj_safe);
                let _ = f.flush();
            }
        }
    }
    done.store(true, Relaxed); let _ = th.join();
    let dt = start.elapsed().as_secs_f64();
    let (s, e, c, dp, wk) = (seen.load(Relaxed), ec_seen.load(Relaxed), checked.load(Relaxed), dups.load(Relaxed), weak.load(Relaxed));
    eprintln!("stream done: seen {} certs, {} EC, {} distinct checked, {} dup skipped ({:.1}% collapse), {} weak, {:.1}s = {:.0} seen/sec, rss {:.0}MB",
              s, e, c, dp, if s > 0 { dp as f64 / s as f64 * 100.0 } else { 0.0 }, wk, dt, s as f64 / dt.max(1e-9), rss_mb());
    0
}

fn cert_one(path: &str, tbl: &str) -> i32 {
    let t = match load_tables(tbl) { Ok(t) => t, Err(e) => { eprintln!("load error: {e}"); return 2; } };
    let raw = match std::fs::read(path) { Ok(r) => r, Err(e) => { eprintln!("read: {e}"); return 2; } };
    let der: Vec<u8> = if raw.first() == Some(&0x30) {
        raw
    } else {
        match x509_parser::pem::parse_x509_pem(&raw) { Ok((_, p)) => p.contents, Err(e) => { eprintln!("pem: {e}"); return 2; } }
    };
    let (is_ec, d) = check_der(&t, &der);
    if !is_ec { println!("not an EC key on a supported curve (P-256/384/521)"); return 0; }
    match d {
        Some(d) => println!("WEAK  d={}  {}", d, der_subject(&der)),
        None => println!("clean (no small d <= {})  {}", MAXD, der_subject(&der)),
    }
    0
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(|s| s.as_str()).unwrap_or("help");
    let code = match cmd {
        "build" => match build_and_persist(a.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_TABLE)) {
            Ok(()) => 0, Err(e) => { eprintln!("build error: {e}"); 2 }
        },
        "selftest" => selftest(a.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_ANSWERS),
                               a.get(3).map(|s| s.as_str()).unwrap_or(DEFAULT_TABLE)),
        "bench" => bench(a.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_TABLE)),
        "scan" => match a.get(2) { Some(p) => scan_corpus(p, a.get(3).map(|s| s.as_str()).unwrap_or(DEFAULT_TABLE)),
                                   None => { eprintln!("usage: p4mon scan <corpus.der> [table.bin]"); 2 } },
        "stream" => stream(a.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_TABLE),
                            a.get(3).and_then(|s| s.parse().ok()).unwrap_or(1u64)),
        "cert" => match a.get(2) { Some(p) => cert_one(p, a.get(3).map(|s| s.as_str()).unwrap_or(DEFAULT_TABLE)),
                                   None => { eprintln!("usage: p4mon cert <file> [table.bin]"); 2 } },
        _ => { eprintln!("p4mon <build|selftest|bench|scan|cert> ..."); 1 }
    };
    std::process::exit(code);
}
