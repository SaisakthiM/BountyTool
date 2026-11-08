//! Reflected input detection.
//!
//! This probe intentionally reports *reflection context*, not "XSS": a reflected
//! payload is a hint, and calling it XSS without browser verification produces
//! the low-quality reports that programs close as informative. `dalfox` performs
//! the actual verification when it is installed.

use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, ParamCandidate, ParamKind, Severity};

use super::{ProbeCtx, inject};

const CANDIDATE_LIMIT: usize = 25;

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut checked = 0usize;

    for candidate in candidates {
        if checked >= CANDIDATE_LIMIT {
            break;
        }
        // Only parameters that plausibly render back into a page.
        if !matches!(
            candidate.kind,
            ParamKind::Query | ParamKind::Other | ParamKind::Id
        ) {
            continue;
        }
        checked += 1;
        let headers = ctx.auth_headers();

        let marker = format!("btx{}", &crate::util::text::token("")[..10]);
        let payload = format!("<{marker}>");
        let Some(url) = inject(&candidate.url, &candidate.name, &payload) else {
            continue;
        };
        let Some(response) = ctx.get(&candidate.host, &url, &headers, true).await else {
            continue;
        };
        if !response.is_html() || !response.body.contains(&payload) {
            continue;
        }

        let context = reflection_context(&response.body, &payload);
        ctx.events.info(format!(
            "reflected input on {} ({}) context={context}",
            candidate.endpoint(),
            candidate.name
        ));

        let (request, evidence) = crate::util::http::describe_exchange(
            "GET",
            &url,
            &[("User-Agent", ctx.http.user_agent.clone())],
            &response,
        );

        findings.push(
            Finding::new(
                Category::ReflectedInput,
                Severity::Low,
                Confidence::Tentative,
                candidate.host.clone(),
                candidate.endpoint(),
            )
            .with_title(format!(
                "Reflected input in `{}` parameter ({context} context)",
                candidate.name
            ))
            .with_param(candidate.name.clone())
            .with_payload(payload.clone())
            .with_evidence(
                request,
                evidence,
                crate::util::text::curl(
                    "GET",
                    &url,
                    &[("User-Agent".to_string(), ctx.http.user_agent.clone())],
                    None,
                ),
            )
            .with_status(response.status)
            .with_source(Source::native("xss-reflect"))
            .seal(),
        );
    }
    findings
}

/// Where in the document the payload landed: `html`, `attribute` or `script`.
fn reflection_context(body: &str, payload: &str) -> &'static str {
    let Some(position) = body.find(payload) else {
        return "unknown";
    };
    let before = &body[..position];

    let last_script_open = before.to_ascii_lowercase().rfind("<script");
    let last_script_close = before.to_ascii_lowercase().rfind("</script");
    if let Some(open) = last_script_open {
        if last_script_close.map(|close| close < open).unwrap_or(true) {
            return "script";
        }
    }

    let quote = before.chars().rev().take(200).collect::<String>();
    let single = quote.matches('\'').count();
    let double = quote.matches('"').count();
    if single % 2 == 1 || double % 2 == 1 {
        return "attribute";
    }
    "html"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_detection() {
        assert_eq!(reflection_context("<p><marker></p>", "<marker>"), "html");
        assert_eq!(
            reflection_context("<input value='<marker>'>", "<marker>"),
            "attribute"
        );
        assert_eq!(
            reflection_context("<script>var a = '<marker>';</script>", "<marker>"),
            "script"
        );
        assert_eq!(reflection_context("nothing here", "<marker>"), "unknown");
    }
}
