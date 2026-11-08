//! SQL injection detection: error-based, boolean-based and (deep only) time-based.
//!
//! Detection only. No dumping, no stacked queries, no `--os-shell`.

use std::time::{Duration, Instant};

use crate::findings::Category;
use crate::models::{Confidence, ParamCandidate, Severity};
use crate::util::text::similarity;

use super::{ProbeCtx, append, finding};

/// Database error signatures across the common engines and frameworks.
const ERROR_SIGNATURES: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(",
    "postgresql query failed",
    "syntax error at or near",
    "ora-00933",
    "ora-01756",
    "ora-06512",
    "sqlite3.operationalerror",
    "sqlite error",
    "sqlstate[",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "system.data.sqlclient",
    "mysqli_sql_exception",
    "doctrine\\dbal\\exception",
    "org.hibernate.exception",
    "jdbc.sqlexception",
    "division by zero",
    "unknown column",
    "unrecognized token:",
];

/// Payloads that break out of the common quoting contexts.
const ERROR_PAYLOADS: &[&str] = &["'", "\"", "')", "\\", "';"];

/// How many candidates get the slow time-based treatment.
const TIME_BASED_BUDGET: usize = 12;

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<crate::findings::Finding> {
    let mut findings = Vec::new();

    for (index, candidate) in candidates.iter().enumerate() {
        match check_candidate(ctx, candidate, index).await {
            Some(found) => {
                for item in &found {
                    ctx.events.finding(item.clone());
                }
                findings.extend(found);
            }
            None => continue,
        }
    }
    findings
}

async fn check_candidate(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    index: usize,
) -> Option<Vec<crate::findings::Finding>> {
    let headers = ctx.auth_headers();
    let baseline = ctx
        .get(&candidate.host, &candidate.url, &headers, true)
        .await?;
    // A baseline that is already an error page tells us nothing.
    if baseline.status >= 500 || baseline.body.len() < 32 {
        return None;
    }
    let baseline_lower = baseline.body.to_ascii_lowercase();

    if let Some(found) = error_based(ctx, candidate, &headers, &baseline_lower).await {
        return Some(vec![found]);
    }
    if let Some(found) = boolean_based(ctx, candidate, &headers, &baseline.body).await {
        return Some(vec![found]);
    }
    if ctx.deep() && index < TIME_BASED_BUDGET {
        if let Some(found) = time_based(ctx, candidate, &headers).await {
            return Some(vec![found]);
        }
    }
    None
}

async fn error_based(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    headers: &[(&'static str, String)],
    baseline_lower: &str,
) -> Option<crate::findings::Finding> {
    for payload in ERROR_PAYLOADS {
        let Some(url) = append(&candidate.url, &candidate.name, &candidate.value, payload) else {
            continue;
        };
        let Some(response) = ctx.get(&candidate.host, &url, headers, true).await else {
            continue;
        };
        let body = response.body.to_ascii_lowercase();
        let hit = ERROR_SIGNATURES
            .iter()
            .find(|signature| body.contains(*signature) && !baseline_lower.contains(*signature));
        if let Some(signature) = hit {
            ctx.events.info(format!(
                "SQL error signature `{}` triggered on {} ({})",
                signature,
                candidate.endpoint(),
                candidate.name
            ));
            return Some(finding(
                ctx,
                candidate,
                Category::SqlInjection,
                Severity::High,
                Confidence::Firm,
                "sqli-error",
                payload,
                &url,
                &response,
                format!(
                    "SQL injection (error-based) in `{}` parameter",
                    candidate.name
                ),
            ));
        }
    }
    None
}

async fn boolean_based(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    headers: &[(&'static str, String)],
    baseline_body: &str,
) -> Option<crate::findings::Finding> {
    let families = [
        (
            format!("{} AND 1=1", candidate.value),
            format!("{} AND 1=2", candidate.value),
        ),
        (
            format!("{}' AND '1'='1", candidate.value),
            format!("{}' AND '1'='2", candidate.value),
        ),
    ];

    for (truthy, falsy) in families {
        let Some(truthy_url) = super::inject(&candidate.url, &candidate.name, &truthy) else {
            continue;
        };
        let Some(falsy_url) = super::inject(&candidate.url, &candidate.name, &falsy) else {
            continue;
        };

        let Some(truthy_response) = ctx.get(&candidate.host, &truthy_url, headers, true).await
        else {
            continue;
        };
        let Some(falsy_response) = ctx.get(&candidate.host, &falsy_url, headers, true).await else {
            continue;
        };
        if truthy_response.status >= 500 || falsy_response.status >= 500 {
            continue;
        }

        let truthy_similarity = similarity(baseline_body, &truthy_response.body);
        let falsy_similarity = similarity(baseline_body, &falsy_response.body);
        let divergence = truthy_similarity - falsy_similarity;

        if truthy_similarity >= 0.90 && divergence >= 0.15 {
            ctx.events.info(format!(
                "boolean differential on {} ({}) truthy={:.2} falsy={:.2}",
                candidate.endpoint(),
                candidate.name,
                truthy_similarity,
                falsy_similarity
            ));
            return Some(finding(
                ctx,
                candidate,
                Category::SqlInjection,
                Severity::High,
                Confidence::Firm,
                "sqli-boolean",
                &truthy,
                &truthy_url,
                &truthy_response,
                format!(
                    "SQL injection (boolean-based) in `{}` parameter",
                    candidate.name
                ),
            ));
        }
    }
    None
}

async fn time_based(
    ctx: &ProbeCtx,
    candidate: &ParamCandidate,
    headers: &[(&'static str, String)],
) -> Option<crate::findings::Finding> {
    // MySQL/PostgreSQL style delay; two consecutive slow responses confirm it.
    for payload in [" AND SLEEP(5)", "' AND SLEEP(5)-- -", "\" AND SLEEP(5)-- -"] {
        let Some(url) = append(&candidate.url, &candidate.name, &candidate.value, payload) else {
            continue;
        };

        let started = Instant::now();
        let Some(response) = ctx.get(&candidate.host, &url, headers, true).await else {
            continue;
        };
        let first = started.elapsed();
        if first < Duration::from_secs(4) {
            continue;
        }

        let confirm_started = Instant::now();
        let _ = ctx.get(&candidate.host, &url, headers, true).await;
        if confirm_started.elapsed() < Duration::from_secs(4) {
            continue;
        }

        ctx.events.info(format!(
            "time-based delay of {:.1}s reproduced twice on {} ({})",
            first.as_secs_f32(),
            candidate.endpoint(),
            candidate.name
        ));
        return Some(finding(
            ctx,
            candidate,
            Category::SqlInjection,
            Severity::High,
            Confidence::Confirmed,
            "sqli-time",
            payload,
            &url,
            &response,
            format!(
                "SQL injection (time-based) in `{}` parameter",
                candidate.name
            ),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_cover_major_engines() {
        let haystack = ERROR_SIGNATURES.join(" ");
        for engine in [
            "mysql",
            "postgresql",
            "ora-",
            "sqlite",
            "sql server",
            "jdbc",
        ] {
            assert!(haystack.contains(engine), "missing {engine} signature");
        }
    }

    #[test]
    fn time_based_budget_is_small() {
        const _: () = assert!(TIME_BASED_BUDGET <= 20);
    }
}
