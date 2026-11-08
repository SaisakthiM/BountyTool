//! DNS resolution with wildcard detection.
//!
//! Names that do not resolve are dropped so the HTTP stage stays fast and does
//! not hammer a wildcard DNS entry with thousands of identical answers.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use futures::StreamExt;

use crate::models::Stage;
use crate::util::fs as files;

use super::{Ctx, ScanState};

const MAX_NAMES: usize = 2_000;
const CONCURRENCY: usize = 32;

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let mut names: Vec<String> = state.subdomains.iter().cloned().collect();
    names.sort();
    if names.len() > MAX_NAMES {
        ctx.events.warn(format!(
            "{} names exceed the {} resolution budget; truncating",
            names.len(),
            MAX_NAMES
        ));
        state.degrade(format!(
            "dns: only {MAX_NAMES} of {} names were resolved",
            names.len()
        ));
        names.truncate(MAX_NAMES);
    }

    // Wildcard DNS makes every positive answer meaningless, so record it.
    for root in ctx.scope.root_domains() {
        ctx.check_cancel()?;
        let probe = format!("bt-wildcard-{}.{root}", &crate::util::text::token("")[..10]);
        if resolve(&probe).await {
            ctx.events.warn(format!(
                "{root} answers wildcard DNS; resolution-based filtering is unreliable"
            ));
            state.degrade(format!("dns: {root} has wildcard DNS"));
        }
    }

    let total = names.len();
    let resolved: Vec<(String, bool)> =
        futures::stream::iter(names.clone().into_iter().map(|name| async move {
            let ok = resolve(&name).await;
            (name, ok)
        }))
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;

    let mut live: Vec<String> = Vec::new();
    let mut done = 0usize;
    for (name, ok) in resolved {
        done += 1;
        if ok {
            live.push(name);
        }
        if done % 10 == 0 || done == total {
            ctx.events.progress(
                Stage::Dns,
                done as u64,
                Some(total as u64),
                format!("{} live", live.len()),
            );
        }
    }

    live.sort();
    state.subdomains = live.iter().cloned().collect();

    let artifact = ctx.artifact("resolved.txt");
    files::write_lines(&artifact, live.iter().cloned())?;
    ctx.events.progress(
        Stage::Dns,
        live.len() as u64,
        Some(total as u64),
        format!("{} of {} names resolve", live.len(), total),
    );
    Ok(vec![artifact])
}

/// Resolve a name (or accept a literal IP).
pub async fn resolve(host: &str) -> bool {
    if IpAddr::from_str(host).is_ok() {
        return true;
    }
    let target = format!("{host}:443");
    match tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host(&target)).await {
        Ok(Ok(mut addresses)) => addresses.next().is_some(),
        _ => false,
    }
}
