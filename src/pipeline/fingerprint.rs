//! Fingerprinting: aggregate what the hosts are running and look for the
//! cheap, high-signal misconfigurations that show up in almost every program
//! (missing security headers, exposed `.git`, exposed `.env`, directory
//! listings).
//!
//! Deliberately small: a handful of GETs per host, no brute forcing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, Severity, Stage};
use crate::util::fs as files;
use crate::util::{Http, Limiter};

use super::{Ctx, ScanState};

/// Hosts we inspect in detail. Fingerprinting every host of a large program
/// would dominate the scan budget for very little extra signal.
const INSPECT_LIMIT: usize = 25;

/// Headers whose absence is worth a single low-severity observation.
const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
];

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let mut technologies: BTreeMap<String, usize> = BTreeMap::new();
    let mut servers: BTreeMap<String, usize> = BTreeMap::new();
    let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
    for host in &state.hosts {
        for tech in &host.tech {
            *technologies.entry(tech.clone()).or_insert(0) += 1;
        }
        if !host.webserver.is_empty() {
            *servers.entry(host.webserver.clone()).or_insert(0) += 1;
        }
        if host.status != 0 {
            *statuses.entry(host.status.to_string()).or_insert(0) += 1;
        }
    }

    let http = Http::new(ctx.config)?;
    let limiter = Limiter::new(
        ctx.scope.max_rps.unwrap_or(ctx.config.rate_limit),
        ctx.config.per_host_budget,
    );
    let headers = [("User-Agent", http.user_agent.clone())];

    let targets: Vec<String> = state
        .hosts
        .iter()
        .filter(|host| host.reachable())
        .map(|host| host.url.clone())
        .take(INSPECT_LIMIT)
        .collect();

    let mut missing_headers: BTreeMap<String, usize> = BTreeMap::new();
    let mut interesting: Vec<serde_json::Value> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut bare_hosts: Vec<(String, String, Vec<&'static str>)> = Vec::new();

    for (index, url) in targets.iter().enumerate() {
        ctx.check_cancel()?;
        let name = crate::models::host_of(url);
        if !limiter.acquire(&name).await {
            ctx.events.warn(format!(
                "fingerprint budget for {name} exhausted; skipping detail pass"
            ));
            continue;
        }

        let Some(response) = http.get(url, &headers, true).await.ok() else {
            continue;
        };

        let absent: Vec<&str> = SECURITY_HEADERS
            .iter()
            .copied()
            .filter(|header| response.header(header).is_none())
            .collect();
        for header in &absent {
            *missing_headers.entry((*header).to_string()).or_insert(0) += 1;
        }
        if absent.len() >= 3 {
            bare_hosts.push((name.clone(), url.clone(), absent.clone()));
        }

        if let Some(title) = response.title() {
            if title.to_ascii_lowercase().starts_with("index of /") {
                interesting.push(serde_json::json!({ "url": url, "note": "directory listing" }));
                findings.push(
                    Finding::new(
                        Category::Exposure,
                        Severity::Low,
                        Confidence::Firm,
                        name.clone(),
                        url.clone(),
                    )
                    .with_title(format!("Directory listing enabled: {title}"))
                    .with_status(response.status)
                    .with_evidence(
                        format!("GET {url}"),
                        title.clone(),
                        crate::util::text::curl(
                            "GET",
                            url,
                            &[("User-Agent".to_string(), http.user_agent.clone())],
                            None,
                        ),
                    )
                    .with_source(Source::native("fingerprint"))
                    .with_references(&["https://cwe.mitre.org/data/definitions/548.html"])
                    .seal(),
                );
            }
        }

        // A short list of files whose presence is never acceptable in
        // production and whose 200 is unambiguous.
        for (path, needle, label) in [
            ("/.git/HEAD", "ref: refs/", "Exposed Git repository"),
            ("/.env", "APP_KEY", "Exposed .env file"),
            ("/.env", "DB_", "Exposed .env file"),
        ] {
            let probe_url = format!("{}{}", url.trim_end_matches('/'), path);
            if !limiter.acquire(&name).await {
                break;
            }
            let Ok(candidate) = http.get(&probe_url, &headers, false).await else {
                continue;
            };
            if candidate.status != 200 || !candidate.body.contains(needle) {
                continue;
            }
            if findings.iter().any(|existing| {
                existing.endpoint == probe_url && existing.category == Category::Exposure
            }) {
                break;
            }
            interesting.push(serde_json::json!({ "url": probe_url, "note": label }));
            findings.push(
                Finding::new(
                    Category::Exposure,
                    Severity::High,
                    Confidence::Confirmed,
                    name.clone(),
                    probe_url.clone(),
                )
                .with_title(label)
                .with_status(candidate.status)
                .with_evidence(
                    format!("GET {probe_url}"),
                    candidate.snippet(200),
                    crate::util::text::curl(
                        "GET",
                        &probe_url,
                        &[("User-Agent".to_string(), http.user_agent.clone())],
                        None,
                    ),
                )
                .with_source(Source::native("fingerprint"))
                .with_references(&["https://cwe.mitre.org/data/definitions/538.html"])
                .seal(),
            );
            break;
        }

        ctx.events.progress(
            Stage::Fingerprint,
            (index + 1) as u64,
            Some(targets.len() as u64),
            format!("{} hosts inspected", index + 1),
        );
    }

    // One observation per host that sends practically no security headers.
    // Kept as Info: it is context for the primary findings, not a bug on its
    // own.
    for (name, url, absent) in &bare_hosts {
        findings.push(
            Finding::new(
                Category::SecurityHeader,
                Severity::Info,
                Confidence::Tentative,
                name.clone(),
                url.clone(),
            )
            .with_title(format!(
                "Missing {} security header(s): {}",
                absent.len(),
                absent.join(", ")
            ))
            .with_evidence(
                format!("GET {url}"),
                format!("absent: {}", absent.join(", ")),
                crate::util::text::curl(
                    "GET",
                    url,
                    &[("User-Agent".to_string(), http.user_agent.clone())],
                    None,
                ),
            )
            .with_source(Source::native("fingerprint"))
            .with_references(&["https://cwe.mitre.org/data/definitions/693.html"])
            .seal(),
        );
    }

    for finding in &findings {
        ctx.events.finding(finding.clone());
    }
    state.findings.extend(findings);

    let artifact = ctx.artifact("fingerprint.json");
    files::write_json(
        &artifact,
        &serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "hosts": state.hosts.len(),
            "inspected": targets.len(),
            "status_codes": statuses,
            "web_servers": servers,
            "technologies": technologies,
            "missing_headers": missing_headers,
            "interesting": interesting,
        }),
    )?;

    ctx.events.progress(
        Stage::Fingerprint,
        targets.len() as u64,
        Some(targets.len() as u64),
        format!(
            "{} technologies, {} servers",
            technologies.len(),
            servers.len()
        ),
    );
    Ok(vec![artifact])
}
