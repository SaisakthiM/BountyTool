//! Passive subdomain enumeration: subfinder, findomain and certificate transparency.

use std::path::PathBuf;

use crate::models::Stage;
use crate::tools::{args, parsers, registry};
use crate::util::Http;
use crate::util::fs as files;

use super::{Ctx, ScanState};

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let roots = ctx.scope.root_domains();
    let roots_file = ctx.artifact("roots.txt");
    files::write_lines(&roots_file, roots.iter().cloned())?;

    if roots.is_empty() {
        ctx.events
            .warn("no root domains in scope; passive enumeration skipped");
        state.degrade("passive: scope contained no domains".to_string());
        let artifact = ctx.artifact("subdomains.txt");
        files::write_lines(
            &artifact,
            state.subdomains.iter().cloned().collect::<Vec<String>>(),
        )?;
        return Ok(vec![artifact, roots_file]);
    }

    let mut discovered = 0usize;

    // subfinder: the primary passive source.
    if registry::which("subfinder").is_some() {
        let arguments = args(&[
            "-dL",
            &roots_file.display().to_string(),
            "-all",
            "-silent",
            "-json",
        ]);
        match ctx.runner.capture("subfinder", &arguments).await {
            Ok(output) => {
                let found = parsers::parse_subdomains(&output.stdout);
                ctx.events
                    .progress(Stage::Passive, found.len() as u64, None, "subfinder");
                for host in found {
                    if ctx.scope.allows(&host) {
                        state.subdomains.insert(host);
                        discovered += 1;
                    }
                }
                let version = registry::detect(registry::spec("subfinder").unwrap())
                    .await
                    .version;
                state.record_tool("subfinder", version.as_deref());
            }
            Err(error) => {
                ctx.events.warn(format!("subfinder failed: {error}"));
                state.degrade(format!("passive: subfinder failed ({error})"));
            }
        }
    } else {
        state.degrade("passive: subfinder missing".to_string());
    }

    // findomain: cheap second opinion, optional.
    if registry::which("findomain").is_some() {
        for root in &roots {
            ctx.check_cancel()?;
            let arguments = args(&["-t", root, "-q"]);
            if let Ok(output) = ctx.runner.capture("findomain", &arguments).await {
                for host in parsers::parse_subdomains(&output.stdout) {
                    if ctx.scope.allows(&host) {
                        state.subdomains.insert(host);
                        discovered += 1;
                    }
                }
            }
        }
        state.record_tool("findomain", None);
    }

    // Certificate transparency logs, straight from crt.sh.
    let http = Http::new(ctx.config)?;
    for root in &roots {
        ctx.check_cancel()?;
        let url = format!("https://crt.sh/?q=%25.{root}&output=json");
        match http.get(&url, &[], true).await {
            Ok(response) if response.status == 200 => {
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&response.body)
                {
                    let mut added = 0usize;
                    for entry in entries {
                        let Some(value) = entry.get("name_value").and_then(|value| value.as_str())
                        else {
                            continue;
                        };
                        for name in value.lines() {
                            let name = name.trim().trim_start_matches("*.").to_ascii_lowercase();
                            if name.is_empty() || !name.contains('.') {
                                continue;
                            }
                            if ctx.scope.allows(&name) && state.subdomains.insert(name) {
                                added += 1;
                            }
                        }
                    }
                    discovered += added;
                    ctx.events.progress(
                        Stage::Passive,
                        discovered as u64,
                        None,
                        format!("crt.sh {root}: +{added}"),
                    );
                }
            }
            Ok(response) => ctx.events.warn(format!(
                "crt.sh for {root} returned HTTP {}",
                response.status
            )),
            Err(error) => {
                ctx.events
                    .warn(format!("crt.sh for {root} failed: {error}"));
                state.degrade("passive: certificate transparency lookup failed".to_string());
            }
        }
    }

    state.subdomains.extend(roots.iter().cloned());
    let artifact = ctx.artifact("subdomains.txt");
    let mut names: Vec<String> = state.subdomains.iter().cloned().collect();
    names.sort();
    files::write_lines(&artifact, names.iter().cloned())?;

    ctx.events.progress(
        Stage::Passive,
        names.len() as u64,
        Some(names.len() as u64),
        format!("{} subdomains in scope", names.len()),
    );
    Ok(vec![artifact, roots_file])
}
