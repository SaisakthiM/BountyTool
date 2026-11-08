//! CRLF / response-splitting detection.

use crate::findings::Category;
use crate::models::{Confidence, ParamCandidate, Severity};

use super::{ProbeCtx, finding, inject};

/// Header we try to inject; also the marker we look for in the response.
const INJECTED_HEADER: &str = "x-bt-inject";

const PAYLOADS: &[(&str, &str)] = &[
    ("\r\nX-BT-Inject: 1", "raw CRLF"),
    ("%0d%0aX-BT-Inject: 1", "encoded CRLF"),
    ("\nX-BT-Inject: 1", "LF only"),
];

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<crate::findings::Finding> {
    let mut findings = Vec::new();

    for candidate in candidates.iter().take(30) {
        let headers = ctx.auth_headers();

        for (payload, label) in PAYLOADS {
            let Some(url) = inject(&candidate.url, &candidate.name, payload) else {
                continue;
            };
            let Some(response) = ctx.get(&candidate.host, &url, &headers, false).await else {
                continue;
            };

            if response.header(INJECTED_HEADER).is_some() {
                ctx.events.info(format!(
                    "CRLF injection ({label}) on {} ({})",
                    candidate.endpoint(),
                    candidate.name
                ));
                findings.push(finding(
                    ctx,
                    candidate,
                    Category::CrlfInjection,
                    Severity::Medium,
                    Confidence::Firm,
                    "crlf",
                    payload,
                    &url,
                    &response,
                    format!(
                        "CRLF / header injection via `{}` parameter ({label})",
                        candidate.name
                    ),
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
    fn injected_header_name_matches_lookup() {
        assert_eq!(INJECTED_HEADER, "x-bt-inject");
        assert!(PAYLOADS.iter().any(|(payload, _)| payload.contains("\r\n")));
    }
}
