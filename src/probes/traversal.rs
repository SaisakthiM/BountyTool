//! Path traversal detection (read-only signal: password file markers).

use crate::findings::Category;
use crate::models::{Confidence, ParamCandidate, ParamKind, Severity};

use super::{ProbeCtx, finding, inject};

const PAYLOADS: &[&str] = &[
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
];

/// Signatures that only appear when a real file was served.
const MARKERS: &[&str] = &[
    "root:x:0:",
    "root:*:0:",
    "daemon:x:",
    "[fonts]",
    "[extensions]",
];

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<crate::findings::Finding> {
    let mut findings = Vec::new();

    for candidate in candidates {
        let interesting = matches!(
            candidate.kind,
            ParamKind::File | ParamKind::Url | ParamKind::Redirect | ParamKind::Other
        );
        if !interesting {
            continue;
        }
        let headers = ctx.auth_headers();

        for payload in PAYLOADS {
            let Some(url) = inject(&candidate.url, &candidate.name, payload) else {
                continue;
            };
            let Some(response) = ctx.get(&candidate.host, &url, &headers, true).await else {
                continue;
            };
            let lower = response.body.to_ascii_lowercase();
            let matched = MARKERS
                .iter()
                .find(|marker| response.body.contains(**marker) || lower.contains(**marker));

            if let Some(marker) = matched {
                ctx.events.info(format!(
                    "path traversal on {} ({}) marker `{}`",
                    candidate.endpoint(),
                    candidate.name,
                    marker.trim()
                ));
                findings.push(finding(
                    ctx,
                    candidate,
                    Category::PathTraversal,
                    Severity::High,
                    Confidence::Confirmed,
                    "traversal",
                    payload,
                    &url,
                    &response,
                    format!("Path traversal via `{}` parameter", candidate.name),
                ));
                break;
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_cover_unix_and_windows() {
        assert!(MARKERS.contains(&"root:x:0:"));
        assert!(MARKERS.contains(&"[fonts]"));
    }

    #[test]
    fn payloads_include_encoded_variants() {
        assert!(PAYLOADS.iter().any(|payload| payload.contains("%2f")));
        assert!(PAYLOADS.iter().any(|payload| payload.contains("....//")));
    }
}
