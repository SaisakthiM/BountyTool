//! Template based scanning with `nuclei`.
//!
//! nuclei is the only external tool that reports findings directly, so its
//! output is mapped onto the native finding model and merged into the same
//! triage pass as the native probes.

use std::path::PathBuf;

use crate::models::Stage;
use crate::tools::{args, parsers, registry};
use crate::util::fs as files;

use super::{Ctx, ScanState};

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let mut targets: Vec<String> = state
        .hosts
        .iter()
        .filter(|host| !host.url.is_empty())
        .map(|host| host.url.clone())
        .collect();

    if targets.is_empty() {
        // No httpx output: give nuclei the bare names, it upgrades the scheme.
        let mut names: Vec<String> = state.subdomains.iter().cloned().collect();
        names.sort();
        targets = names.iter().map(|name| format!("https://{name}")).collect();
    }

    if targets.is_empty() {
        state.degrade("nuclei: nothing to scan".to_string());
        let artifact = ctx.artifact("nuclei.jsonl");
        files::write_lines(&artifact, Vec::<String>::new())?;
        return Ok(vec![artifact]);
    }

    let input = ctx.artifact("nuclei-input.txt");
    files::write_lines(&input, targets.iter().cloned())?;

    if registry::which("nuclei").is_none() {
        ctx.events
            .warn("nuclei is not installed; template scanning skipped");
        state.degrade("nuclei: not installed".to_string());
        return Ok(vec![input]);
    }

    let rate = ctx.config.nuclei_rate_limit.max(1).to_string();
    let concurrency = ctx.config.concurrency.clamp(2, 50).to_string();
    let arguments = args(&[
        "-l",
        &input.display().to_string(),
        "-jsonl",
        "-silent",
        "-no-color",
        "-severity",
        &ctx.config.nuclei_severity,
        "-rate-limit",
        &rate,
        "-c",
        &concurrency,
        "-timeout",
        "10",
        "-retries",
        "1",
        "-disable-update-check",
    ]);

    let raw = ctx.artifact("nuclei.jsonl");
    let findings = match ctx.runner.capture("nuclei", &arguments).await {
        Ok(output) => {
            files::write_lines(&raw, output.stdout.lines().map(ToString::to_string))?;
            state.record_tool("nuclei", None);
            if output.timed_out {
                state.degrade("nuclei: hit the tool timeout, results may be partial".to_string());
            }
            parsers::parse_nuclei(&output.stdout)
        }
        Err(error) => {
            ctx.events.warn(format!("nuclei failed: {error}"));
            state.degrade(format!("nuclei: failed ({error})"));
            Vec::new()
        }
    };

    let mut kept = 0usize;
    for finding in findings {
        if !ctx.scope.allows(&finding.host) {
            continue;
        }
        ctx.events.finding(finding.clone());
        state.findings.push(finding);
        kept += 1;
    }

    ctx.events.progress(
        Stage::VulnScan,
        kept as u64,
        Some(kept as u64),
        format!("{kept} template matches"),
    );
    Ok(vec![input, raw])
}
