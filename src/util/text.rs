//! Small text helpers: tokens, evidence formatting, response similarity.

use std::collections::HashSet;
use std::hash::{BuildHasher, Hash, Hasher};

/// Random-ish, filesystem- and URL-safe token (16 hex chars).
///
/// `RandomState` is seeded from the OS entropy pool per instance, which is
/// plenty for correlation ids; no crypto is claimed here.
pub fn token(prefix: &str) -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    (&prefix as *const _ as usize).hash(&mut hasher);
    let value = hasher.finish();
    if prefix.is_empty() {
        format!("{value:016x}")
    } else {
        format!("{prefix}{value:016x}")
    }
}

/// Truncate to `max` chars on a char boundary, appending an ellipsis.
pub fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Collapse all whitespace so a value fits on one terminal line.
pub fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Build a copy-pasteable curl command from the parts we recorded.
pub fn curl(method: &str, url: &str, headers: &[(String, String)], body: Option<&str>) -> String {
    let mut parts = vec![
        "curl".to_string(),
        "-i".to_string(),
        "-sS".to_string(),
        "-X".to_string(),
        method.to_string(),
    ];
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        parts.push("-H".to_string());
        parts.push(shell_quote(&format!(
            "{name}: {}",
            redact_value(name, value)
        )));
    }
    if let Some(body) = body {
        if !body.is_empty() {
            parts.push("--data-raw".to_string());
            parts.push(shell_quote(body));
        }
    }
    parts.push(shell_quote(url));
    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let safe = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:=?&%@+~[]{}()".contains(ch));
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Never leak credentials into a report that gets shared or submitted.
pub fn redact_value(name: &str, value: &str) -> String {
    const SENSITIVE: &[&str] = &[
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "token",
        "session",
    ];
    let lowered = name.to_ascii_lowercase();
    if SENSITIVE.iter().any(|needle| lowered.contains(needle)) {
        "[redacted]".to_string()
    } else {
        value.to_string()
    }
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Jaccard similarity over 5-char shingles of the normalised body.
///
/// Used by the SQLi boolean and SSRF differential checks: identical pages score
/// 1.0, structurally different pages score near 0.
pub fn similarity(a: &str, b: &str) -> f32 {
    if a == b {
        return 1.0;
    }
    let left = shingles(a);
    let right = shingles(b);
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    let intersection = left.intersection(&right).count() as f32;
    let union = left.union(&right).count() as f32;
    if union == 0.0 {
        1.0
    } else {
        intersection / union
    }
}

fn shingles(value: &str) -> HashSet<u64> {
    let normalized: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = normalized.chars().take(16_000).collect();
    if chars.len() < 5 {
        let mut set = HashSet::new();
        set.insert(fnv(&normalized));
        return set;
    }
    let mut set = HashSet::with_capacity(chars.len());
    for window in chars.windows(5) {
        let text: String = window.iter().collect();
        set.insert(fnv(&text));
    }
    set
}

fn fnv(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_prefixed() {
        let a = token("bt");
        let b = token("bt");
        assert!(a.starts_with("bt"));
        assert_eq!(a.len(), 18);
        assert_ne!(a, b);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("héllo wörld", 4), "hél…");
    }

    #[test]
    fn curl_quotes_payloads() {
        let command = curl(
            "GET",
            "https://x.test/a?id=1'",
            &[("User-Agent".into(), "bt".into())],
            None,
        );
        assert!(command.starts_with("curl -i -sS -X GET"));
        assert!(command.contains("'https://x.test/a?id=1'\\''"));
    }

    #[test]
    fn evidence_redacts_secrets() {
        assert_eq!(redact_value("Set-Cookie", "sid=1"), "[redacted]");
        assert_eq!(redact_value("Authorization", "Bearer x"), "[redacted]");
        assert_eq!(redact_value("Content-Type", "text/html"), "text/html");
    }

    #[test]
    fn similarity_matches_intuition() {
        let baseline = "<html><body><h1>Item 1</h1><p>Everything is fine</p></body></html>";
        assert_eq!(similarity(baseline, baseline), 1.0);
        assert!(similarity(baseline, baseline) > similarity(baseline, "SQL syntax error"));
    }

    #[test]
    fn percent_encoding_covers_specials() {
        assert_eq!(percent_encode("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(percent_encode("../../etc/passwd"), "..%2F..%2Fetc%2Fpasswd");
    }
}
