//! Native vulnerability probes.
//!
//! These are the checks that keep BountyTool useful when no external scanner is
//! installed. Every request passes three gates: scope, the global rate limiter
//! and the per-host budget. Probes are detection-only: they never dump data,
//! never chain requests to exploit a finding and never touch authentication.

pub mod cors;
pub mod crlf;
pub mod oast;
pub mod redirect;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod traversal;
pub mod xss;

use url::Url;

use crate::config::Config;
use crate::error::Result;
use crate::events::Events;
use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, ParamCandidate, Profile, Severity};
use crate::scope::Scope;
use crate::util::http::HttpResponse;
use crate::util::{Http, Limiter};

/// Everything a probe needs. Shared by reference so probes stay cheap to call.
pub struct ProbeCtx {
    pub http: Http,
    pub limiter: Limiter,
    pub scope: Scope,
    pub profile: Profile,
    pub events: Events,
    pub params_limit: usize,
    pub oast_domain: Option<String>,
}

impl ProbeCtx {
    pub fn new(
        config: &Config,
        scope: &Scope,
        profile: Profile,
        events: Events,
        oast_domain: Option<String>,
    ) -> Result<ProbeCtx> {
        let rps = scope.max_rps.unwrap_or(config.rate_limit);
        Ok(ProbeCtx {
            http: Http::new(config)?,
            limiter: Limiter::new(rps, config.per_host_budget),
            scope: scope.clone(),
            profile,
            events,
            params_limit: config.probe_params_limit.max(1),
            oast_domain,
        })
    }

    pub fn deep(&self) -> bool {
        self.profile == Profile::Deep
    }

    /// Scope + rate-limit + budget guarded GET. `None` means "do not report
    /// anything from this request", including refused or failed requests.
    pub async fn get(
        &self,
        host: &str,
        url: &str,
        headers: &[(&str, String)],
        follow: bool,
    ) -> Option<HttpResponse> {
        if let Some(reason) = self.scope.deny_reason(host) {
            self.events.warn(format!("scope refused {url}: {reason}"));
            return None;
        }
        if !self.limiter.acquire(host).await {
            self.events.warn(format!(
                "per-host request budget exhausted for {host}; skipping"
            ));
            return None;
        }
        match self.http.get(url, headers, follow).await {
            Ok(response) => Some(response),
            Err(error) => {
                self.events.tool_log("probe", format!("{url} -> {error}"));
                None
            }
        }
    }

    pub fn auth_headers(&self) -> Vec<(&'static str, String)> {
        vec![("User-Agent", self.http.user_agent.clone())]
    }
}

/// Replace one query parameter value, preserving everything else.
pub fn inject(url: &str, name: &str, value: &str) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    if pairs.is_empty() {
        return None;
    }
    let mut found = false;
    let replaced: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(key, existing)| {
            if key == name {
                found = true;
                (key, value.to_string())
            } else {
                (key, existing)
            }
        })
        .collect();
    if !found {
        return None;
    }
    parsed.query_pairs_mut().clear().extend_pairs(replaced);
    Some(parsed.to_string())
}

/// Append a payload to the existing parameter value.
pub fn append(url: &str, name: &str, existing: &str, payload: &str) -> Option<String> {
    inject(url, name, &format!("{existing}{payload}"))
}

/// Standard evidence-rich finding builder shared by all probes.
#[allow(clippy::too_many_arguments)]
pub fn finding(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    category: Category,
    severity: Severity,
    confidence: Confidence,
    probe: &'static str,
    payload: &str,
    url: &str,
    response: &HttpResponse,
    title: String,
) -> Finding {
    let headers = vec![("User-Agent", ctx.http.user_agent.clone())];
    let (request, evidence) = crate::util::http::describe_exchange("GET", url, &headers, response);
    let curl = crate::util::text::curl("GET", url, &headers.map_clone(), None);

    Finding::new(
        category,
        severity,
        confidence,
        candidate.host.clone(),
        candidate.endpoint(),
    )
    .with_title(title)
    .with_param(candidate.name.clone())
    .with_payload(payload.to_string())
    .with_evidence(request, evidence, curl)
    .with_status(response.status)
    .with_source(Source::native(probe))
    .seal()
}

/// Small helper so `finding` can reuse the same header set for curl.
trait MapClone {
    fn map_clone(&self) -> Vec<(String, String)>;
}

impl MapClone for Vec<(&'static str, String)> {
    fn map_clone(&self) -> Vec<(String, String)> {
        self.iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect()
    }
}

/// Trim the candidate list to the configured budget, keeping parameter
/// families that are most likely to yield a finding.
pub fn limit_candidates(mut candidates: Vec<ParamCandidate>, limit: usize) -> Vec<ParamCandidate> {
    candidates.sort_by_key(|candidate| match candidate.kind {
        crate::models::ParamKind::Id => 0,
        crate::models::ParamKind::Url => 1,
        crate::models::ParamKind::Redirect => 2,
        crate::models::ParamKind::Query => 3,
        crate::models::ParamKind::File => 4,
        crate::models::ParamKind::Other => 5,
    });
    candidates.dedup_by(|a, b| a.endpoint() == b.endpoint() && a.name == b.name);
    candidates.truncate(limit);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_replaces_only_the_target_parameter() {
        let url = "https://a.test/item?id=1&page=2";
        let injected = inject(url, "id", "1'").unwrap();
        assert!(injected.contains("id=1%27"));
        assert!(injected.contains("page=2"));
    }

    #[test]
    fn injection_of_unknown_parameter_returns_none() {
        assert!(inject("https://a.test/item?id=1", "missing", "x").is_none());
        assert!(inject("https://a.test/item", "id", "x").is_none());
    }

    #[test]
    fn append_keeps_original_value() {
        let url = "https://a.test/item?id=1";
        let injected = append(url, "id", "1", "'").unwrap();
        assert!(injected.contains("id=1%27"));
    }

    #[test]
    fn candidate_limit_prefers_ids_and_urls() {
        let candidates = vec![
            ParamCandidate::new("https://a.test/x?q=1", "q", "1"),
            ParamCandidate::new("https://a.test/x?id=1", "id", "1"),
            ParamCandidate::new("https://a.test/x?next=/", "next", "/"),
        ];
        let limited = limit_candidates(candidates, 2);
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].name, "id");
        assert_eq!(limited[1].name, "next");
    }
}
