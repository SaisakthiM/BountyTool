//! Server-side request forgery detection.
//!
//! Two signals:
//! 1. Differential: injecting an internal address changes the response in a way
//!    the original value does not.
//! 2. Out-of-band: an `interactsh` callback fires for a labelled parameter.
//!
//! Only URLs are requested; internal data is never exfiltrated into the report.

use crate::findings::Category;
use crate::models::{Confidence, ParamCandidate, ParamKind, Severity};
use crate::util::text::similarity;

use super::oast::Oast;
use super::{ProbeCtx, finding, inject};

/// Internal destinations that produce distinguishable behaviour.
const INTERNAL_TARGETS: &[(&str, &str)] = &[
    ("http://127.0.0.1:80/", "loopback"),
    ("http://127.0.0.1:22/", "loopback-ssh"),
    ("http://169.254.169.254/latest/meta-data/", "cloud-metadata"),
    ("http://[::1]/", "ipv6-loopback"),
    ("http://0.0.0.0:80/", "wildcard-address"),
];

/// Strings that only appear when a request actually left the target.
const MARKERS: &[&str] = &[
    "ssh-2.0",
    "ami-id",
    "instance-id",
    "security-credentials",
    "root:x:0",
    "meta-data",
    "it works!",
    "connection refused",
];

pub async fn run(
    ctx: &ProbeCtx,
    candidates: &[ParamCandidate],
    oast: Option<&Oast>,
) -> Vec<crate::findings::Finding> {
    let mut findings = Vec::new();
    let mut url_candidates: Vec<&ParamCandidate> = candidates
        .iter()
        .filter(|candidate| {
            candidate.kind.accepts_url()
                || candidate.kind == ParamKind::Other && candidate.value.starts_with("http")
        })
        .collect();
    url_candidates.truncate(25);

    for (index, candidate) in url_candidates.iter().enumerate() {
        if let Some(item) = check_candidate(ctx, candidate, index, oast).await {
            ctx.events.finding(item.clone());
            findings.push(item);
        }
    }
    findings
}

async fn check_candidate(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    index: usize,
    oast: Option<&Oast>,
) -> Option<crate::findings::Finding> {
    let headers = ctx.auth_headers();
    let baseline = ctx
        .get(&candidate.host, &candidate.url, &headers, true)
        .await?;

    // Out-of-band payload first: cheap, and the only way to catch blind SSRF.
    if let Some(oast) = oast {
        let label = format!("s{index}");
        let payload = oast.url(&label);
        if let Some(url) = inject(&candidate.url, &candidate.name, &payload) {
            oast.register(&label, candidate);
            let _ = ctx.get(&candidate.host, &url, &headers, true).await;
            ctx.events.tool_log(
                "ssrf",
                format!("queued OAST payload {payload} for {}", candidate.name),
            );
        }
    }

    for (target, label) in INTERNAL_TARGETS {
        let Some(url) = inject(&candidate.url, &candidate.name, target) else {
            continue;
        };
        let Some(response) = ctx.get(&candidate.host, &url, &headers, true).await else {
            continue;
        };

        let similarity_to_baseline = similarity(&baseline.body, &response.body);
        let body = response.body.to_ascii_lowercase();
        let marker = MARKERS
            .iter()
            .find(|marker| body.contains(*marker))
            .copied();

        let behaviour_changed = similarity_to_baseline < 0.80 && response.status != baseline.status;
        let strong = marker.is_some() && similarity_to_baseline < 0.95;

        if !strong && !behaviour_changed {
            continue;
        }

        let confidence = if strong {
            Confidence::Firm
        } else {
            Confidence::Tentative
        };
        ctx.events.info(format!(
            "SSRF candidate on {} ({}): target={label} similarity={similarity_to_baseline:.2}",
            candidate.endpoint(),
            candidate.name
        ));

        return Some(finding(
            ctx,
            candidate,
            Category::Ssrf,
            Severity::High,
            confidence,
            "ssrf",
            target,
            &url,
            &response,
            format!(
                "Server-side request forgery via `{}` parameter ({} objective)",
                candidate.name, label
            ),
        ));
    }
    None
}

/// Build the finding for a confirmed out-of-band callback.
pub fn oast_finding(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    payload: &str,
    hit: &super::oast::OastHit,
) -> crate::findings::Finding {
    crate::findings::Finding::new(
        Category::Ssrf,
        Severity::High,
        Confidence::Confirmed,
        candidate.host.clone(),
        candidate.endpoint(),
    )
    .with_title(format!(
        "Blind SSRF confirmed out-of-band via `{}` parameter",
        candidate.name
    ))
    .with_param(candidate.name.clone())
    .with_payload(payload.to_string())
    .with_evidence(
        format!("payload: {payload}"),
        format!(
            "callback: {} {} from {}",
            hit.protocol, hit.full_id, hit.remote_address
        ),
        crate::util::text::curl(
            "GET",
            payload,
            &[("User-Agent".to_string(), ctx.http.user_agent.clone())],
            None,
        ),
    )
    .with_source(crate::findings::Source::native("ssrf-oast"))
    .seal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parameters_are_the_target_set() {
        let url_param = ParamCandidate::new("https://a.test/f?url=http://x", "url", "http://x");
        let id_param = ParamCandidate::new("https://a.test/f?id=1", "id", "1");
        assert!(url_param.kind.accepts_url());
        assert!(!id_param.kind.accepts_url());
    }

    #[test]
    fn markers_cover_ssh_and_metadata() {
        assert!(MARKERS.contains(&"ssh-2.0"));
        assert!(MARKERS.contains(&"ami-id"));
    }
}
