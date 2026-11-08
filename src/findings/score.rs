//! Suspiciousness scoring and triage split.
//!
//! The score answers "how much attention does this deserve?" and is the only
//! ordering the report and the TUI use. Findings below
//! [`PRIMARY_THRESHOLD`] are still reported, but in the observations appendix.

use crate::findings::Finding;

/// Findings at or above this score are reported as primary findings.
pub const PRIMARY_THRESHOLD: f32 = 1.5;

#[derive(Debug, Clone, Default)]
pub struct TriageResult {
    /// Ranked, confirmed-ish findings for the main report body.
    pub primary: Vec<Finding>,
    /// Lower signal items: reflected input, headers, hints.
    pub observations: Vec<Finding>,
}

/// `score = severity weight x confidence weight x reachability`.
pub fn compute(finding: &Finding) -> f32 {
    let reachability = match finding.status {
        Some(200..=299) => 1.0,
        Some(300..=399) => 0.9,
        Some(500..=599) => 0.85,
        Some(400..=499) => 0.6,
        _ => 0.75,
    };
    finding.severity.weight() * finding.confidence.weight() * reachability
}

/// Dedupe by identity (keeping the strongest instance), rank, then split.
pub fn triage(findings: Vec<Finding>, threshold: f32) -> TriageResult {
    let mut best: Vec<Finding> = Vec::new();

    for candidate in findings {
        match best
            .iter_mut()
            .find(|existing| existing.dedupe_key() == candidate.dedupe_key())
        {
            Some(existing) => {
                if candidate.score > existing.score
                    || (candidate.score == existing.score
                        && candidate.confidence > existing.confidence)
                {
                    *existing = candidate;
                }
            }
            None => best.push(candidate),
        }
    }

    best.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.endpoint.cmp(&b.endpoint))
    });

    let (primary, observations) = best.into_iter().partition(|f| f.score >= threshold);
    TriageResult {
        primary,
        observations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Category, Source};
    use crate::models::{Confidence, Severity};

    fn finding(sev: Severity, conf: Confidence, endpoint: &str, param: &str) -> Finding {
        Finding::new(
            Category::SqlInjection,
            sev,
            conf,
            "app.example.com",
            endpoint,
        )
        .with_param(param)
        .with_status(200)
        .seal()
    }

    #[test]
    fn duplicates_collapse_keeping_the_strongest() {
        let weak = finding(Severity::Medium, Confidence::Tentative, "/item", "id");
        let strong = finding(Severity::High, Confidence::Confirmed, "/item", "id");
        let result = triage(vec![weak, strong], PRIMARY_THRESHOLD);
        assert_eq!(result.primary.len(), 1);
        assert_eq!(result.primary[0].severity, Severity::High);
    }

    #[test]
    fn low_signal_items_become_observations() {
        let noise = Finding::new(
            Category::ReflectedInput,
            Severity::Info,
            Confidence::Tentative,
            "app.example.com",
            "/search",
        )
        .with_param("q")
        .with_status(404)
        .seal();
        let result = triage(vec![noise], PRIMARY_THRESHOLD);
        assert!(result.primary.is_empty());
        assert_eq!(result.observations.len(), 1);
    }

    #[test]
    fn ordering_is_by_score() {
        let low = finding(Severity::Low, Confidence::Firm, "/a", "id");
        let crit = finding(Severity::Critical, Confidence::Confirmed, "/b", "id");
        let result = triage(vec![low, crit], PRIMARY_THRESHOLD);
        assert_eq!(result.primary[0].severity, Severity::Critical);
    }

    #[test]
    fn tool_and_native_hits_merge() {
        let native = finding(Severity::High, Confidence::Firm, "/item", "id")
            .with_source(Source::native("sqli"));
        let tool = finding(Severity::High, Confidence::Firm, "/item", "id")
            .with_source(Source::tool("nuclei"));
        let result = triage(vec![native, tool], PRIMARY_THRESHOLD);
        assert_eq!(result.primary.len(), 1);
    }
}
