//! Active vulnerability probing: the native detection engine.
//!
//! Every probe is detection-only. Nothing here dumps data, chains requests or
//! attempts to escalate: a finding says "this looks exploitable, here is the
//! request that proves it", and the operator takes it from there.

use std::path::PathBuf;

use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, Severity, Stage};
use crate::probes::{self, ProbeCtx, oast::Oast, sqli};
use crate::tools::{args, parsers, registry};
use crate::util::fs as files;

use super::{Ctx, ScanState};

/// Candidates handed to sqlmap. It is by far the slowest probe, so only the
/// most suspicious parameters get there.
const SQLMAP_LIMIT: usize = 3;

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let candidates = probes::limit_candidates(state.params.clone(), ctx.config.probe_params_limit);
    let mut artifacts: Vec<PathBuf> = Vec::new();

    if candidates.is_empty() {
        ctx.events
            .warn("no parameters were discovered; active probes skipped");
        state.degrade("active: no injectable parameters were found".to_string());
        let artifact = ctx.artifact("active-findings.jsonl");
        files::write_jsonl(&artifact, &Vec::<Finding>::new())?;
        return Ok(vec![artifact]);
    }

    ctx.events.info(format!(
        "probing {} parameters across {} endpoints",
        candidates.len(),
        state.params.len()
    ));

    let probe_ctx = ProbeCtx::new(ctx.config, ctx.scope, ctx.profile, ctx.events.clone(), None)?;
    let oast = if ctx.config.oast {
        if registry::which("interactsh-client").is_none() {
            ctx.events
                .warn("oast is enabled but interactsh-client is not installed");
            state.degrade("active: out-of-band checks unavailable".to_string());
            None
        } else {
            Oast::start(&ctx.session.raw_dir(), ctx.events).await
        }
    } else {
        None
    };
    let registered = oast
        .as_ref()
        .map(|client| client.registrations())
        .unwrap_or_default();

    let mut findings: Vec<Finding> = Vec::new();

    findings.extend(sqli::run(&probe_ctx, &candidates).await);
    ctx.events
        .progress(Stage::Active, 1, Some(6), "SQL injection");

    findings.extend(probes::ssrf::run(&probe_ctx, &candidates, oast.as_ref()).await);
    ctx.events.progress(Stage::Active, 2, Some(6), "SSRF");

    findings.extend(probes::redirect::run(&probe_ctx, &candidates).await);
    ctx.events
        .progress(Stage::Active, 3, Some(6), "open redirect");

    findings.extend(probes::cors::run(&probe_ctx, &candidates).await);
    ctx.events.progress(Stage::Active, 4, Some(6), "CORS");

    findings.extend(probes::crlf::run(&probe_ctx, &candidates).await);
    findings.extend(probes::traversal::run(&probe_ctx, &candidates).await);
    findings.extend(probes::ssti::run(&probe_ctx, &candidates).await);
    findings.extend(probes::xss::run(&probe_ctx, &candidates).await);
    ctx.events
        .progress(Stage::Active, 6, Some(6), "injection and reflection checks");

    for finding in &findings {
        ctx.events.finding(finding.clone());
    }

    // Out-of-band callbacks arrived while the probes were running.
    if let Some(client) = oast {
        let hits = client.collect().await;
        let mut confirmed: Vec<Finding> = Vec::new();
        for hit in &hits {
            let Some((_, candidate)) = registered.iter().find(|(label, _)| *label == hit.label)
            else {
                continue;
            };
            let payload = format!("http://{}", hit.full_id);
            confirmed.push(probes::ssrf::oast_finding(
                &probe_ctx, candidate, &payload, hit,
            ));
        }
        let artifact = ctx.session.artifact("oast.jsonl");
        files::write_jsonl(&artifact, &hits)?;
        artifacts.push(artifact);
        for finding in &confirmed {
            ctx.events.finding(finding.clone());
        }
        findings.extend(confirmed);
    }

    if ctx.config.sqlmap_verify {
        let verified = sqlmap_verify(ctx, &findings).await;
        for finding in &verified {
            ctx.events.finding(finding.clone());
        }
        findings.extend(verified);
    }

    let artifact = ctx.artifact("active-findings.jsonl");
    files::write_jsonl(&artifact, &findings)?;
    artifacts.push(artifact);

    state.findings.extend(findings.clone());

    ctx.events.progress(
        Stage::Active,
        findings.len() as u64,
        Some(findings.len() as u64),
        format!("{} findings from native probes", findings.len()),
    );
    Ok(artifacts)
}

/// Re-test SQL injection candidates with sqlmap. Only uses the boolean and
/// time based techniques: no data extraction, no stacked queries.
async fn sqlmap_verify(ctx: &Ctx<'_>, findings: &[Finding]) -> Vec<Finding> {
    if registry::which("sqlmap").is_none() {
        ctx.events
            .warn("sqlmap_verify is enabled but sqlmap is not installed");
        return Vec::new();
    }

    let suspects: Vec<(String, String)> = findings
        .iter()
        .filter(|finding| finding.category == Category::SqlInjection)
        .filter_map(|finding| {
            finding
                .parameter
                .as_ref()
                .map(|parameter| (finding.endpoint.clone(), parameter.clone()))
        })
        .take(SQLMAP_LIMIT)
        .collect();

    let mut verified = Vec::new();
    let output_dir = ctx.session.raw_dir().join("sqlmap");
    for (index, (endpoint, parameter)) in suspects.iter().enumerate() {
        if ctx.cancel.is_cancelled() {
            break;
        }
        let output_arg = output_dir
            .join(format!("case-{index}"))
            .display()
            .to_string();
        let arguments = args(&[
            "-u",
            endpoint,
            "-p",
            parameter,
            "--batch",
            "--level=1",
            "--risk=1",
            "--technique=BT",
            "--timeout=10",
            "--retries=0",
            "--disable-coloring",
            "--flush-session",
            "--output-dir",
            &output_arg,
        ]);
        let Ok(output) = ctx.runner.capture("sqlmap", &arguments).await else {
            continue;
        };
        for hit in parsers::parse_sqlmap(&output.stdout) {
            let command = crate::tools::ToolRunner::command_line("sqlmap", &arguments);
            verified.push(
                Finding::new(
                    Category::SqlInjection,
                    Severity::High,
                    Confidence::Confirmed,
                    crate::models::host_of(endpoint),
                    endpoint.clone(),
                )
                .with_title(format!(
                    "SQL injection confirmed by sqlmap ({})",
                    hit.technique
                ))
                .with_param(hit.parameter.clone())
                .with_payload(hit.payload.clone())
                .with_evidence(
                    command.clone(),
                    format!("sqlmap: {}\npayload: {}", hit.technique, hit.payload),
                    command.clone(),
                )
                .with_source(Source::tool("sqlmap"))
                .with_references(&[
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ])
                .seal(),
            );
        }
    }

    if verified.is_empty() {
        ctx.events
            .info("sqlmap did not confirm any of the SQL injection candidates");
    }
    verified
}
