//! Port discovery, deep profile only.
//!
//! `naabu` is the fast first pass; `nmap` adds service versions. The stage is
//! intentionally conservative: top ports only and a hard timeout per host, so
//! a scan never turns into a full-range sweep.

use std::path::PathBuf;

use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, Severity, Stage};
use crate::tools::{args, parsers, registry};
use crate::util::fs as files;

use super::{Ctx, ScanState};

/// Services that must never be reachable from the public internet.
const RISKY_PORTS: &[(u16, &str)] = &[
    (2375, "Docker daemon API"),
    (2376, "Docker daemon API (TLS)"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (9300, "Elasticsearch transport"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
    (5601, "Kibana"),
];

const MAX_FINDINGS: usize = 20;

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let input = ctx.artifact("probe-input.txt");
    if !input.exists() {
        let mut names: Vec<String> = state.subdomains.iter().cloned().collect();
        names.sort();
        files::write_lines(&input, names)?;
    }

    let mut ports: Vec<(String, u16)> = Vec::new();
    let mut artifacts: Vec<PathBuf> = Vec::new();

    if registry::which("naabu").is_some() {
        let rate = ctx.config.rate_limit.max(1).to_string();
        let concurrency = ctx.config.concurrency.clamp(2, 50).to_string();
        let arguments = args(&[
            "-list",
            &input.display().to_string(),
            "-silent",
            "-top-ports",
            "100",
            "-rate",
            &rate,
            "-c",
            &concurrency,
        ]);
        match ctx.runner.capture("naabu", &arguments).await {
            Ok(output) => {
                ports.extend(parsers::parse_naabu(&output.stdout));
                state.record_tool("naabu", None);
                ctx.events
                    .progress(Stage::Ports, ports.len() as u64, None, "naabu");
            }
            Err(error) => {
                ctx.events.warn(format!("naabu failed: {error}"));
                state.degrade(format!("ports: naabu failed ({error})"));
            }
        }
    } else {
        state.degrade("ports: naabu missing".to_string());
    }

    if registry::which("nmap").is_some() {
        // `-sT` keeps the scan usable without root; `-Pn` because most bounty
        // targets sit behind a CDN or firewall that drops ICMP.
        let arguments = args(&[
            "-iL",
            &input.display().to_string(),
            "-sT",
            "-sV",
            "--top-ports",
            "100",
            "--open",
            "-Pn",
            "-n",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "5m",
            "-oG",
            "-",
        ]);
        match ctx.runner.capture("nmap", &arguments).await {
            Ok(output) => {
                let found = parsers::parse_nmap_grep(&output.stdout);
                ctx.events
                    .progress(Stage::Ports, found.len() as u64, None, "nmap");
                ports.extend(found);
                state.record_tool("nmap", None);
            }
            Err(error) => {
                ctx.events.warn(format!("nmap failed: {error}"));
                state.degrade(format!("ports: nmap failed ({error})"));
            }
        }
    } else {
        state.degrade("ports: nmap missing".to_string());
    }

    ports.sort();
    ports.dedup();

    if ports.is_empty() {
        state.degrade("ports: no open ports were discovered".to_string());
    }

    let artifact = ctx.artifact("ports.tsv");
    files::write_lines(
        &artifact,
        ports.iter().map(|(host, port)| format!("{host}\t{port}")),
    )?;
    artifacts.push(artifact);

    let mut reported = 0usize;
    for (host, port) in &ports {
        if reported >= MAX_FINDINGS {
            break;
        }
        let Some((_, service)) = RISKY_PORTS.iter().find(|(risky, _)| risky == port) else {
            continue;
        };
        let finding = Finding::new(
            Category::Exposure,
            Severity::High,
            Confidence::Firm,
            host.clone(),
            format!("{host}:{port}"),
        )
        .with_title(format!("{service} reachable on port {port}"))
        .with_evidence(
            format!("TCP connect to {host}:{port}"),
            format!("port {port} open ({service})"),
            format!("nc -vz {host} {port}"),
        )
        .with_source(Source::native("ports"))
        .with_references(&["https://cwe.mitre.org/data/definitions/284.html"])
        .seal();
        ctx.events.finding(finding.clone());
        state.findings.push(finding);
        reported += 1;
    }

    ctx.events.progress(
        Stage::Ports,
        ports.len() as u64,
        Some(ports.len() as u64),
        format!("{} open ports", ports.len()),
    );
    Ok(artifacts)
}
