//! Content discovery with `ffuf`, falling back to `gobuster`.
//!
//! Only a bounded slice of the host list is fuzzed: content discovery is the
//! most expensive stage per host and the marginal value drops quickly.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::config::MINI_WORDLIST;
use crate::models::Stage;
use crate::tools::{args, parsers, registry};
use crate::util::fs as files;

use super::{Ctx, ScanState};

const HOST_LIMIT: usize = 12;
const MATCH_CODES: &str = "200,204,301,302,307,401,403";

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let wordlist = match ctx.config.directory_wordlist() {
        Some(path) => path,
        None => {
            let path = ctx.artifact("mini-dirs.txt");
            files::write_lines(&path, MINI_WORDLIST.lines().map(ToString::to_string))?;
            ctx.events
                .info("SecLists not found; using the bundled directory wordlist");
            state.degrade("content: used the bundled mini wordlist".to_string());
            path
        }
    };
    let wordlist_arg = wordlist.display().to_string();

    let targets: Vec<String> = state
        .hosts
        .iter()
        .filter(|host| host.reachable())
        .map(|host| host.url.trim_end_matches('/').to_string())
        .take(HOST_LIMIT)
        .collect();

    if targets.is_empty() {
        state.degrade("content: no reachable hosts to fuzz".to_string());
        let artifact = ctx.artifact("content.txt");
        files::write_lines(&artifact, Vec::<String>::new())?;
        return Ok(vec![artifact]);
    }

    let use_ffuf = registry::which("ffuf").is_some();
    let use_gobuster = registry::which("gobuster").is_some();
    if !use_ffuf && !use_gobuster {
        state.degrade("content: neither ffuf nor gobuster is installed".to_string());
        let artifact = ctx.artifact("content.txt");
        files::write_lines(&artifact, Vec::<String>::new())?;
        return Ok(vec![artifact]);
    }

    let mut discovered: BTreeSet<String> = BTreeSet::new();
    let rate = ctx.config.rate_limit.max(1).to_string();
    let threads = ctx.config.concurrency.clamp(2, 40).to_string();

    for (index, base) in targets.iter().enumerate() {
        ctx.check_cancel()?;

        if use_ffuf {
            let template = format!("{base}/FUZZ");
            let output_file = ctx.session.raw_dir().join(format!("ffuf-{index}.json"));
            let _ = std::fs::remove_file(&output_file);
            let output_arg = output_file.display().to_string();
            let arguments = args(&[
                "-u",
                &template,
                "-w",
                &wordlist_arg,
                "-of",
                "json",
                "-o",
                &output_arg,
                "-mc",
                MATCH_CODES,
                "-t",
                &threads,
                "-rate",
                &rate,
                "-s",
            ]);
            match ctx.runner.capture("ffuf", &arguments).await {
                Ok(_) => {
                    if let Ok(text) = std::fs::read_to_string(&output_file) {
                        for url in parsers::parse_ffuf(&text) {
                            if !ctx.scope.allows(&crate::models::host_of(&url)) {
                                continue;
                            }
                            if discovered.insert(url.clone()) {
                                ctx.events.url(url);
                            }
                        }
                    }
                }
                Err(error) => {
                    ctx.events
                        .warn(format!("ffuf against {base} failed: {error}"));
                    state.degrade(format!("content: ffuf failed on {base}"));
                }
            }
            state.record_tool("ffuf", None);
        } else {
            let arguments = args(&[
                "dir",
                "-u",
                base,
                "-w",
                &wordlist_arg,
                "-q",
                "-t",
                &threads,
                "-k",
                "--no-error",
                "--timeout",
                "10s",
            ]);
            match ctx.runner.capture("gobuster", &arguments).await {
                Ok(output) => {
                    for url in parsers::parse_gobuster(&output.stdout, base) {
                        if !ctx.scope.allows(&crate::models::host_of(&url)) {
                            continue;
                        }
                        if discovered.insert(url.clone()) {
                            ctx.events.url(url);
                        }
                    }
                }
                Err(error) => {
                    ctx.events
                        .warn(format!("gobuster against {base} failed: {error}"));
                    state.degrade(format!("content: gobuster failed on {base}"));
                }
            }
            state.record_tool("gobuster", None);
        }

        ctx.events.progress(
            Stage::Content,
            (index + 1) as u64,
            Some(targets.len() as u64),
            format!("{} paths from {base}", discovered.len()),
        );
    }

    let artifact = ctx.artifact("content.txt");
    files::write_lines(&artifact, discovered.iter().cloned())?;
    state.urls.extend(discovered);

    ctx.events.progress(
        Stage::Content,
        state.urls.len() as u64,
        Some(state.urls.len() as u64),
        format!("{} paths discovered", state.urls.len()),
    );
    Ok(vec![artifact])
}
