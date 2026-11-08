//! CORS misconfiguration detection.
//!
//! Reports one finding per host, based on the strongest response observed.

use std::collections::HashMap;

use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, ParamCandidate, Severity};

use super::ProbeCtx;

const PROBE_ORIGIN: &str = "https://bountytool.invalid";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Grade {
    ReflectedWithCredentials,
    WildcardWithCredentials,
    NullOrigin,
    ReflectedOrigin,
}

impl Grade {
    fn severity(&self) -> Severity {
        match self {
            Grade::ReflectedWithCredentials | Grade::WildcardWithCredentials => Severity::High,
            Grade::NullOrigin => Severity::Medium,
            Grade::ReflectedOrigin => Severity::Medium,
        }
    }

    fn confidence(&self) -> Confidence {
        match self {
            Grade::ReflectedWithCredentials => Confidence::Confirmed,
            Grade::WildcardWithCredentials => Confidence::Tentative,
            Grade::NullOrigin | Grade::ReflectedOrigin => Confidence::Firm,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Grade::ReflectedWithCredentials => {
                "CORS: arbitrary origin reflected with credentials enabled"
            }
            Grade::WildcardWithCredentials => "CORS: wildcard origin combined with credentials",
            Grade::NullOrigin => "CORS: `null` origin trusted",
            Grade::ReflectedOrigin => "CORS: arbitrary origin reflected",
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Grade::ReflectedWithCredentials => 4,
            Grade::WildcardWithCredentials => 3,
            Grade::NullOrigin => 2,
            Grade::ReflectedOrigin => 1,
        }
    }
}

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<Finding> {
    // One probe per host is enough: CORS is a server-level policy.
    let mut seen: HashMap<String, &ParamCandidate> = HashMap::new();
    for candidate in candidates {
        seen.entry(candidate.host.clone()).or_insert(candidate);
    }

    let mut findings = Vec::new();
    for (host, candidate) in seen {
        if !host.is_empty() {
            if let Some(finding) = check_host(ctx, candidate).await {
                ctx.events.finding(finding.clone());
                findings.push(finding);
            }
        }
    }
    findings
}

async fn check_host(ctx: &ProbeCtx, candidate: &ParamCandidate) -> Option<Finding> {
    let mut best: Option<(Grade, crate::util::http::HttpResponse)> = None;

    for origin in [PROBE_ORIGIN, "null"] {
        let mut headers = ctx.auth_headers();
        headers.push(("Origin", origin.to_string()));
        let response = ctx
            .get(&candidate.host, &candidate.url, &headers, true)
            .await?;

        let allow_origin = response
            .header("access-control-allow-origin")
            .unwrap_or_default()
            .trim()
            .to_string();
        let allow_credentials = response
            .header("access-control-allow-credentials")
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("true");

        let grade = if allow_origin == origin && allow_origin != "null" && allow_credentials {
            Some(Grade::ReflectedWithCredentials)
        } else if allow_origin == "*" && allow_credentials {
            Some(Grade::WildcardWithCredentials)
        } else if allow_origin == "null" {
            Some(Grade::NullOrigin)
        } else if allow_origin == origin && allow_origin != "*" {
            Some(Grade::ReflectedOrigin)
        } else {
            None
        };

        if let Some(grade) = grade {
            let better = best
                .as_ref()
                .map(|(current, _)| grade.rank() > current.rank())
                .unwrap_or(true);
            if better {
                best = Some((grade, response));
            }
        }
    }

    let (grade, response) = best?;
    ctx.events
        .info(format!("CORS: {} on {}", grade.title(), candidate.host));

    let origin_header = format!("Origin: {PROBE_ORIGIN}");
    let headers = vec![("Origin", PROBE_ORIGIN.to_string())];
    let (request, evidence) = crate::util::http::describe_exchange(
        "GET",
        &candidate.url,
        &[
            ("User-Agent", ctx.http.user_agent.clone()),
            ("Origin", PROBE_ORIGIN.to_string()),
        ],
        &response,
    );

    Some(
        Finding::new(
            Category::CorsMisconfig,
            grade.severity(),
            grade.confidence(),
            candidate.host.clone(),
            candidate.endpoint(),
        )
        .with_title(grade.title().to_string())
        .with_evidence(
            format!("{request}{origin_header}\n"),
            evidence,
            crate::util::text::curl(
                "GET",
                &candidate.url,
                &headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value))
                    .collect::<Vec<_>>(),
                None,
            ),
        )
        .with_status(response.status)
        .with_source(Source::native("cors"))
        .seal(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_ordering_puts_credentials_first() {
        assert!(Grade::ReflectedWithCredentials.rank() > Grade::ReflectedOrigin.rank());
        assert_eq!(Grade::ReflectedWithCredentials.severity(), Severity::High);
    }

    #[test]
    fn probe_origin_never_resolves() {
        assert!(PROBE_ORIGIN.ends_with(".invalid"));
    }
}
