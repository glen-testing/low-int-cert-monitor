use std::process::Command;

pub struct TargetRow {
    pub curve: String,
    pub x_hex: String,
    pub y_hex: String,
}

pub struct AnswerRow {
    pub curve: String,
    pub x_hex: String,
    pub y_hex: String,
    pub d: u64,
}

pub fn parse_targets(path: &str) -> Vec<TargetRow> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }
        out.push(TargetRow {
            curve: parts[0].to_string(),
            x_hex: parts[1].to_string(),
            y_hex: parts[2].to_string(),
        });
    }
    out
}

pub fn parse_answers(path: &str) -> Vec<AnswerRow> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }
        out.push(AnswerRow {
            curve: parts[0].to_string(),
            x_hex: parts[1].to_string(),
            y_hex: parts[2].to_string(),
            d: parts[3].parse().unwrap_or_else(|_| panic!("bad d in: {line}")),
        });
    }
    out
}

pub struct ExtractedPoint {
    pub curve: String, // "P-256" | "P-384" | "P-521"
    pub x_hex: String,
    pub y_hex: String,
}

fn run_openssl_pkey_text(args: &[&str]) -> Option<String> {
    let out = Command::new("openssl").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn curve_name_to_label(name: &str) -> Option<&'static str> {
    match name {
        "prime256v1" | "secp256r1" | "P-256" => Some("P-256"),
        "secp384r1" | "P-384" => Some("P-384"),
        "secp521r1" | "P-521" => Some("P-521"),
        _ => None,
    }
}

/// Parses `openssl pkey -pubin ... -text -noout` output: looks for
/// "ASN1 OID: <curve>" and the "pub:" hex byte dump (04 || X || Y).
fn parse_pkey_text(text: &str) -> Option<ExtractedPoint> {
    let mut curve_label = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ASN1 OID:") {
            curve_label = curve_name_to_label(rest.trim());
        }
        if let Some(rest) = line.strip_prefix("NIST CURVE:") {
            if curve_label.is_none() {
                curve_label = curve_name_to_label(rest.trim());
            }
        }
    }
    let curve_label = curve_label?;

    let mut hexbytes = String::new();
    let mut in_pub = false;
    for line in text.lines() {
        if line.trim_start().starts_with("pub:") {
            in_pub = true;
            continue;
        }
        if in_pub {
            let t = line.trim();
            // Only the "04:ab:cd:..." hex-dump lines may follow; the next
            // header line (e.g. "ASN1 OID: prime256v1") starts with a hex
            // digit too ('A'), so checking just the first char is not
            // enough -- require every char be a hex digit or ':'.
            let is_hex_dump_line = !t.is_empty() && t.chars().all(|c| c == ':' || c.is_ascii_hexdigit());
            if !is_hex_dump_line {
                break;
            }
            for byte_str in t.split(':') {
                let byte_str = byte_str.trim();
                if byte_str.is_empty() {
                    continue;
                }
                hexbytes.push_str(byte_str);
            }
        }
    }
    if hexbytes.is_empty() {
        return None;
    }
    let bytes = hex_decode(&hexbytes)?;
    if bytes.first() != Some(&0x04) {
        return None; // only uncompressed points supported
    }
    let coord_len = (bytes.len() - 1) / 2;
    let x = &bytes[1..1 + coord_len];
    let y = &bytes[1 + coord_len..1 + 2 * coord_len];
    Some(ExtractedPoint {
        curve: curve_label.to_string(),
        x_hex: bytes_to_hex_unpadded(x),
        y_hex: bytes_to_hex_unpadded(y),
    })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn bytes_to_hex_unpadded(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
}

/// Extracts the EC public point from a PEM/DER X.509 cert or standalone
/// SubjectPublicKeyInfo, shelling out to OpenSSL. Tries: cert(PEM)->pubkey,
/// cert(DER)->pubkey, pubkey(PEM) direct, pubkey(DER) direct.
pub fn extract_point_from_file(path: &str) -> Result<ExtractedPoint, String> {
    // Try as an X.509 cert first (PEM, then DER), extracting its SPKI pubkey PEM.
    for inform in ["PEM", "DER"] {
        let out = Command::new("openssl")
            .args(["x509", "-pubkey", "-noout", "-inform", inform, "-in", path])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                let pubkey_pem = String::from_utf8_lossy(&out.stdout).to_string();
                if let Some(point) = pubkey_pem_to_point(&pubkey_pem) {
                    return Ok(point);
                }
            }
        }
    }
    // Fall back: maybe `path` is already a standalone public key.
    for inform in ["PEM", "DER"] {
        if let Some(text) =
            run_openssl_pkey_text(&["pkey", "-pubin", "-inform", inform, "-in", path, "-text", "-noout"])
        {
            if let Some(point) = parse_pkey_text(&text) {
                return Ok(point);
            }
        }
    }
    Err(format!("could not extract an EC public key from {path} via openssl"))
}

fn pubkey_pem_to_point(pubkey_pem: &str) -> Option<ExtractedPoint> {
    use std::io::Write;
    let mut child = Command::new("openssl")
        .args(["pkey", "-pubin", "-text", "-noout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(pubkey_pem.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_pkey_text(&String::from_utf8_lossy(&out.stdout))
}
