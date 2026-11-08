//! URL collection.
//!
//! `katana` crawls with JavaScript support when installed; the native crawler
//! always runs on the root pages because it is cheap and it feeds parameters
//! to the active stage, which is where findings actually come from.

use std::collections::BTreeSet;
use std::path::PathBuf;

use regex::Regex;
use url::Url;

use crate::models::Stage;
use crate::tools::{args, parsers, registry};
use crate::util::fs as files;
use crate::util::{Http, Limiter};

use super::{Ctx, ScanState};

/// Root pages the native crawler visits.
const CRAWL_LIMIT: usize = 40;
/// Hard ceiling so a link-heavy site cannot blow up the later stages.
const URL_BUDGET: usize = 4_000;

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

    let mut urls: BTreeSet<String> = state.urls.clone();
    for host in &state.hosts {
        if !host.url.is_empty() {
            urls.insert(host.url.clone());
        }
    }
    let mut artifacts: Vec<PathBuf> = Vec::new();

    if registry::which("katana").is_some() {
        let depth = ctx.config.katana_depth.max(1).to_string();
        let rate = ctx.config.rate_limit.max(1).to_string();
        let concurrency = ctx.config.concurrency.clamp(2, 50).to_string();
        let arguments = args(&[
            "-list",
            &input.display().to_string(),
            "-silent",
            "-d",
            &depth,
            "-jc",
            "-kf",
            "all",
            "-rate-limit",
            &rate,
            "-c",
            &concurrency,
            "-timeout",
            "10",
            "-no-color",
        ]);
        match ctx.runner.capture("katana", &arguments).await {
            Ok(output) => {
                let raw = ctx.artifact("katana.txt");
                files::write_lines(&raw, output.stdout.lines().map(ToString::to_string))?;
                artifacts.push(raw);
                let mut added = 0usize;
                for url in parsers::parse_urls(&output.stdout) {
                    if urls.insert(url.clone()) {
                        added += 1;
                        ctx.events.url(url);
                    }
                }
                state.record_tool("katana", None);
                ctx.events
                    .progress(Stage::Urls, added as u64, None, "katana");
            }
            Err(error) => {
                ctx.events.warn(format!("katana failed: {error}"));
                state.degrade(format!("urls: katana failed ({error})"));
            }
        }
    } else {
        state.degrade("urls: katana missing, used the native crawler".to_string());
    }

    let seeds: Vec<String> = state
        .hosts
        .iter()
        .filter(|host| host.reachable())
        .map(|host| host.url.clone())
        .take(CRAWL_LIMIT)
        .collect();
    for url in crawl(ctx, &seeds).await {
        if urls.len() >= URL_BUDGET {
            state.degrade(format!("urls: stopped at the {URL_BUDGET} URL budget"));
            break;
        }
        if urls.insert(url.clone()) {
            ctx.events.url(url);
        }
    }

    state.urls = urls;

    let artifact = ctx.artifact("urls.txt");
    files::write_lines(&artifact, state.urls.iter().cloned())?;
    artifacts.push(artifact);

    ctx.events.progress(
        Stage::Urls,
        state.urls.len() as u64,
        Some(state.urls.len() as u64),
        format!("{} URLs collected", state.urls.len()),
    );
    Ok(artifacts)
}

/// Fetch each seed page and follow the links it advertises.
async fn crawl(ctx: &Ctx<'_>, seeds: &[String]) -> Vec<String> {
    let Ok(http) = Http::new(ctx.config) else {
        return Vec::new();
    };
    let limiter = Limiter::new(
        ctx.scope.max_rps.unwrap_or(ctx.config.rate_limit),
        ctx.config.per_host_budget,
    );
    let headers = [("User-Agent", http.user_agent.clone())];
    let link_pattern = match Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']([^"'#<>]+)["']"#) {
        Ok(pattern) => pattern,
        Err(_) => return Vec::new(),
    };

    let mut found: BTreeSet<String> = BTreeSet::new();
    for seed in seeds {
        if ctx.cancel.is_cancelled() {
            break;
        }
        let name = crate::models::host_of(seed);
        if !limiter.acquire(&name).await {
            continue;
        }
        let Ok(response) = http.get(seed, &headers, true).await else {
            continue;
        };
        if !response.is_html() {
            continue;
        }
        for capture in link_pattern.captures_iter(&response.body) {
            let Some(raw) = capture.get(1) else { continue };
            let raw = raw.as_str().trim();
            if raw.is_empty() || raw.starts_with("javascript:") || raw.starts_with("mailto:") {
                continue;
            }
            let Ok(base) = Url::parse(&response.url) else {
                continue;
            };
            let Ok(resolved) = base.join(raw) else {
                continue;
            };
            if !matches!(resolved.scheme(), "http" | "https") {
                continue;
            }
            let host = crate::models::host_of(resolved.as_str());
            if !ctx.scope.allows(&host) {
                continue;
            }
            let mut clean = resolved;
            clean.set_fragment(None);
            found.insert(clean.to_string());
            if found.len() >= URL_BUDGET {
                return found.into_iter().collect();
            }
        }
    }
    found.into_iter().collect()
}
