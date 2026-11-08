//! Open redirect detection: `Location` header and in-body navigation sinks.

use crate::findings::Category;
use crate::models::{Confidence, ParamCandidate, ParamKind, Severity};

use super::{ProbeCtx, finding, inject};

/// A reserved TLD: guaranteed never to resolve, so nothing is ever followed.
const MARKER: &str = "bountytool-redirect.invalid";

const PAYLOADS: &[&str] = &[
    "//bountytool-redirect.invalid/",
    "https://bountytool-redirect.invalid/",
    "/\\bountytool-redirect.invalid",
    "%2f%2fbountytool-redirect.invalid",
    "https:bountytool-redirect.invalid",
    "///bountytool-redirect.invalid",
];

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<crate::findings::Finding> {
    let mut findings = Vec::new();

    for candidate in candidates {
        let interesting = matches!(candidate.kind, ParamKind::Redirect | ParamKind::Url)
            || candidate.value.starts_with('/')
            || candidate.value.starts_with("http");
        if !interesting {
            continue;
        }
        let headers = ctx.auth_headers();

        for payload in PAYLOADS {
            let Some(url) = inject(&candidate.url, &candidate.name, payload) else {
                continue;
            };
            // Never follow: we want the raw 30x.
            let Some(response) = ctx.get(&candidate.host, &url, &headers, false).await else {
                continue;
            };

            let in_location = response
                .header("location")
                .map(|location| location.contains(MARKER))
                .unwrap_or(false);
            let in_body = is_redirect_status(response.status) || body_navigates_to(&response.body);

            if in_location {
                ctx.events.info(format!(
                    "open redirect on {} ({}) -> {}",
                    candidate.endpoint(),
                    candidate.name,
                    response.header("location").unwrap_or("-")
                ));
                findings.push(finding(
                    ctx,
                    candidate,
                    Category::OpenRedirect,
                    Severity::Medium,
                    Confidence::Firm,
                    "redirect",
                    payload,
                    &url,
                    &response,
                    format!("Open redirect via `{}` parameter", candidate.name),
                ));
                break;
            } else if in_body && response.body.contains(MARKER) {
                findings.push(finding(
                    ctx,
                    candidate,
                    Category::OpenRedirect,
                    Severity::Medium,
                    Confidence::Tentative,
                    "redirect",
                    payload,
                    &url,
                    &response,
                    format!("Possible open redirect via `{}` parameter", candidate.name),
                ));
                break;
            }
        }
    }
    findings
}

fn is_redirect_status(status: u16) -> bool {
    (300..400).contains(&status)
}

fn body_navigates_to(body: &str) -> bool {
    let lowered = body.to_ascii_lowercase();
    lowered.contains("http-equiv=\"refresh\"")
        || lowered.contains("window.location")
        || lowered.contains("location.href")
        || lowered.contains("location.replace")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_cover_protocol_relative_and_scheme_tricks() {
        assert!(PAYLOADS.iter().any(|p| p.starts_with("//")));
        assert!(PAYLOADS.iter().any(|p| p.starts_with("https:")));
        assert!(PAYLOADS.iter().any(|p| p.contains("%2f")));
    }

    #[test]
    fn body_navigation_detection() {
        assert!(body_navigates_to(
            "<meta http-equiv=\"refresh\" content=\"0;url=x\">"
        ));
        assert!(body_navigates_to("window.location = 'x'"));
        assert!(!body_navigates_to("<p>hello</p>"));
    }
}
