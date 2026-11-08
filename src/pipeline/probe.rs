//! HTTP probing: which names actually speak HTTP, on which scheme, and what
//! are they running.
//!
//! `httpx` does the heavy lifting when installed. The native fallback exists so
//! a scan still produces hosts when ProjectDiscovery's httpx is missing, which
//! is common on fresh Arch installs.

use std::path::PathBuf;

use crate::models::{Host, Stage};
use crate::tools::{args, parsers, registry};
use crate::util::fs as files;
use crate::util::{Http, Limiter};

use super::{Ctx, ScanState};

/// Upper bound for the native fallback; it is deliberately much slower than
/// httpx and only meant to keep the pipeline alive.
const NATIVE_LIMIT: usize = 60;

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let mut names: Vec<String> = state.subdomains.iter().cloned().collect();
    names.sort();

    if names.is_empty() {
        ctx.events
            .warn("nothing to probe: no in-scope names resolved");
        state.degrade("probe: no names survived DNS resolution".to_string());
        let artifact = ctx.artifact("hosts.jsonl");
        files::write_jsonl(&artifact, &state.hosts)?;
        return Ok(vec![artifact]);
    }

    let input = ctx.artifact("probe-input.txt");
    files::write_lines(&input, names.iter().cloned())?;
    let mut artifacts = vec![input.clone()];

    if registry::which("httpx").is_some() {
        let concurrency = ctx.config.concurrency.clamp(2, 50).to_string();
        let rate = ctx.config.rate_limit.max(1).to_string();
        let arguments = args(&[
            "-l",
            &input.display().to_string(),
            "-json",
            "-silent",
            "-no-color",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-threads",
            &concurrency,
            "-rate-limit",
            &rate,
            "-timeout",
            "10",
        ]);

        match ctx.runner.capture("httpx", &arguments).await {
            Ok(output) => {
                let raw = ctx.artifact("httpx.jsonl");
                files::write_lines(&raw, output.stdout.lines().map(ToString::to_string))?;
                artifacts.push(raw);
                let hosts = parsers::parse_httpx(&output.stdout);
                absorb(ctx, state, hosts);
                state.record_tool("httpx", None);
            }
            Err(error) => {
                ctx.events.warn(format!("httpx failed: {error}"));
                state.degrade(format!("probe: httpx failed ({error})"));
            }
        }
    } else {
        state.degrade("probe: httpx missing, used the native prober".to_string());
    }

    if state.hosts.is_empty() {
        native_probe(ctx, &names, state).await;
    }

    state.hosts.sort_by(|a, b| a.url.cmp(&b.url));
    state.hosts.dedup_by(|a, b| a.url == b.url);

    let artifact = ctx.artifact("hosts.jsonl");
    files::write_jsonl(&artifact, &state.hosts)?;
    artifacts.push(artifact);

    ctx.events.progress(
        Stage::Probe,
        state.hosts.len() as u64,
        Some(names.len() as u64),
        format!("{} live HTTP endpoints", state.hosts.len()),
    );
    Ok(artifacts)
}

fn absorb(ctx: &Ctx<'_>, state: &mut ScanState, hosts: Vec<Host>) {
    for host in hosts {
        if host.url.is_empty() {
            continue;
        }
        let name = if host.host.is_empty() {
            crate::models::host_of(&host.url)
        } else {
            host.host.clone()
        };
        if !ctx.scope.allows(&name) {
            continue;
        }
        if state.hosts.iter().any(|existing| existing.url == host.url) {
            continue;
        }
        ctx.events.host(host.clone());
        state.hosts.push(host);
    }
}

/// Minimal replacement for httpx: try HTTPS, then HTTP, keep the first answer.
async fn native_probe(ctx: &Ctx<'_>, names: &[String], state: &mut ScanState) {
    let http = match Http::new(ctx.config) {
        Ok(http) => http,
        Err(error) => {
            ctx.events
                .warn(format!("native prober unavailable: {error}"));
            state.degrade(format!("probe: native client failed ({error})"));
            return;
        }
    };
    let limiter = Limiter::new(
        ctx.scope.max_rps.unwrap_or(ctx.config.rate_limit),
        ctx.config.per_host_budget,
    );
    let headers = [("User-Agent", http.user_agent.clone())];
    let total = names.len().min(NATIVE_LIMIT);

    for (index, name) in names.iter().take(NATIVE_LIMIT).enumerate() {
        if ctx.cancel.is_cancelled() {
            return;
        }
        if !limiter.acquire(name).await {
            continue;
        }

        for scheme in ["https", "http"] {
            let url = format!("{scheme}://{name}");
            let Ok(response) = http.get(&url, &headers, true).await else {
                continue;
            };
            let host = Host {
                host: name.clone(),
                url: response.url.clone(),
                status: response.status,
                title: response.title().unwrap_or_default(),
                webserver: response.header("server").unwrap_or_default().to_string(),
                tech: Vec::new(),
                cdn: response
                    .header("cf-ray")
                    .map(|_| "cloudflare".to_string())
                    .or_else(|| {
                        response
                            .header("x-akamai-request-id")
                            .map(|_| "akamai".to_string())
                    }),
                content_length: response.body.len() as u64,
            };
            ctx.events.host(host.clone());
            state.hosts.push(host);
            break;
        }

        if index % 5 == 0 || index + 1 == total {
            ctx.events.progress(
                Stage::Probe,
                (index + 1) as u64,
                Some(total as u64),
                format!("{} live", state.hosts.len()),
            );
        }
    }
}
