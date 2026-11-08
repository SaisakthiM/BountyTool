//! The scan pipeline: ordered stages over one shared state object.
//!
//! `run` is frontend agnostic. It emits [`ScanEvent`]s and never prints, which
//! is what lets the CLI and the TUI share this exact code path.

pub mod active;
pub mod content;
pub mod dns;
pub mod fingerprint;
pub mod params;
pub mod passive;
pub mod ports;
pub mod probe;
pub mod triage;
pub mod urls;
pub mod vulnscan;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::events::Events;
use crate::findings::{Finding, TriageResult, triage as run_triage};
use crate::models::{Host, ParamCandidate, Profile, ScanSummary, Stage, ToolVersion};
use crate::report;
use crate::scope::Scope;
use crate::session::Session;
use crate::tools::{ToolRunner, registry};
use crate::util::fs as files;

/// Everything the stages accumulate. Also the resume cache content.
#[derive(Default)]
pub struct ScanState {
    pub subdomains: BTreeSet<String>,
    pub hosts: Vec<Host>,
    pub urls: BTreeSet<String>,
    pub params: Vec<ParamCandidate>,
    pub findings: Vec<Finding>,
    pub triage: Option<TriageResult>,
    pub tools: Vec<ToolVersion>,
    pub degraded: Vec<String>,
    pub extra_artifacts: Vec<PathBuf>,
}

impl ScanState {
    /// Record a degraded capability; surfaced in the report and the TUI.
    pub fn degrade(&mut self, note: impl Into<String>) {
        let note = note.into();
        if !self.degraded.contains(&note) {
            self.degraded.push(note);
        }
    }

    pub fn record_tool(&mut self, name: &str, version: Option<&str>) {
        let version = version.unwrap_or("unknown").to_string();
        if self.tools.iter().any(|tool| tool.name == name) {
            return;
        }
        self.tools.push(ToolVersion {
            name: name.to_string(),
            version,
        });
    }
}

/// Read-only context handed to each stage.
pub struct Ctx<'a> {
    pub session: &'a Session,
    pub scope: &'a Scope,
    pub config: &'a Config,
    pub profile: Profile,
    pub events: &'a Events,
    pub runner: &'a ToolRunner,
    pub formats: &'a [report::Format],
    pub cancel: CancellationToken,
    pub started: Instant,
}

impl Ctx<'_> {
    pub fn check_cancel(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn artifact(&self, name: &str) -> PathBuf {
        self.session.artifact(name)
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

pub struct RunOptions {
    pub target: String,
    pub profile: Profile,
    pub scope: Scope,
    pub config: Config,
    pub stages: Vec<Stage>,
    pub dry_run: bool,
    pub authorized: bool,
    pub resume: Option<PathBuf>,
    pub formats: Vec<report::Format>,
    /// `doctor` already validated the toolchain, or the caller wants to skip it.
    pub skip_preflight: bool,
}

pub struct RunResult {
    pub summary: ScanSummary,
    pub triage: TriageResult,
    pub session_dir: PathBuf,
    pub reports: Vec<PathBuf>,
    /// True when the run only planned the stages and never touched the target.
    pub dry_run: bool,
}

/// Execute the pipeline. The authorization gate runs before any I/O.
pub async fn run(
    options: RunOptions,
    events: Events,
    cancel: CancellationToken,
) -> Result<RunResult> {
    options.scope.check_authorization(options.authorized)?;

    // A dry run must be safe to point at anything, so it plans and returns
    // before a session directory or a single packet exists.
    if options.dry_run {
        return plan(&options, &events, &cancel).await;
    }

    if !options.skip_preflight {
        check_required(options.profile, &events).await?;
    }

    let mut session = match &options.resume {
        Some(dir) => Session::open(dir)?,
        None => Session::create(&options.target, options.profile, &options.config)?,
    };
    session.set_scope(&options.scope);

    let mut state = ScanState::default();
    if options.resume.is_some() {
        load_state(&mut state, &session)?;
        events.info(format!("resuming session {}", session.id));
    }

    let started = Instant::now();
    events.started(
        &options.target,
        options.profile.as_str(),
        &session.dir,
        &options.stages,
    );

    let runner = ToolRunner::new(
        session.raw_dir(),
        Duration::from_secs(options.config.tool_timeout_secs.max(60)),
        options.dry_run,
        events.clone(),
    );

    let total = options.stages.len();
    for (index, stage) in options.stages.iter().enumerate() {
        if cancel.is_cancelled() {
            session.set_status("cancelled");
            return Err(Error::Cancelled);
        }
        if options.resume.is_some() && session.stage_done(*stage) {
            events.stage_skipped(*stage, "completed in a previous run");
            continue;
        }

        events.stage_started(*stage, index, total);
        let stage_started = Instant::now();

        let outcome = {
            let ctx = Ctx {
                session: &session,
                scope: &options.scope,
                config: &options.config,
                profile: options.profile,
                events: &events,
                runner: &runner,
                formats: &options.formats,
                cancel: cancel.clone(),
                started,
            };
            dispatch(*stage, &ctx, &mut state).await
        };

        let elapsed = stage_started.elapsed();
        match outcome {
            Ok(artifacts) => {
                session.record_stage(*stage, elapsed, &artifacts, true);
                events.stage_finished(*stage, elapsed, artifacts, true);
            }
            Err(Error::Cancelled) => {
                session.set_status("cancelled");
                return Err(Error::Cancelled);
            }
            Err(error) => {
                // A failed stage degrades the scan instead of aborting it: the
                // remaining stages usually still produce value.
                events.error(format!("{} failed: {error}", stage.label()));
                state.degrade(format!("{}: {}", stage.key(), error));
                session.record_stage(*stage, elapsed, &[], false);
                events.stage_finished(*stage, elapsed, vec![], false);
            }
        }
    }

    let triage_result = state
        .triage
        .clone()
        .unwrap_or_else(|| run_triage(state.findings.clone(), crate::findings::PRIMARY_THRESHOLD));
    let summary = build_summary(
        &options,
        &state,
        &triage_result,
        started.elapsed(),
        &session,
    );
    let reports = state.extra_artifacts.clone();

    session.manifest.tools = state.tools.clone();
    session.manifest.degraded = state.degraded.clone();
    session.set_status("completed");
    events.finished(summary.clone());

    Ok(RunResult {
        summary,
        triage: triage_result,
        session_dir: session.dir.clone(),
        reports,
        dry_run: false,
    })
}

/// Plan-only run: no session directory, no network, no child processes.
async fn plan(
    options: &RunOptions,
    events: &Events,
    cancel: &CancellationToken,
) -> Result<RunResult> {
    let session_dir = PathBuf::from("(dry run)");
    events.started(
        &options.target,
        options.profile.as_str(),
        &session_dir,
        &options.stages,
    );

    let total = options.stages.len();
    for (index, stage) in options.stages.iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        events.stage_started(*stage, index, total);
        for line in describe_stage(*stage, options) {
            events.info(format!("[dry-run] {line}"));
        }
        events.stage_finished(*stage, Duration::ZERO, Vec::new(), true);
    }

    let summary = ScanSummary {
        target: options.target.clone(),
        profile: options.profile.as_str().to_string(),
        session_dir: session_dir.display().to_string(),
        ..Default::default()
    };
    events.finished(summary.clone());

    Ok(RunResult {
        summary,
        triage: TriageResult::default(),
        session_dir,
        reports: Vec::new(),
        dry_run: true,
    })
}

/// What each stage would do, with the configured limits spelled out.
fn describe_stage(stage: Stage, options: &RunOptions) -> Vec<String> {
    let config = &options.config;
    match stage {
        Stage::Scope => vec![
            format!(
                "validate {} scope entr(ies) for {}",
                options.scope.targets.len(),
                options.target
            ),
            format!("would resolve: {}", options.scope.root_domains().join(", ")),
        ],
        Stage::Passive => vec![
            "subfinder -dL roots.txt -all -silent -json".to_string(),
            "findomain -t <root> if installed, plus certificate transparency".to_string(),
        ],
        Stage::Dns => vec!["resolve every discovered name and flag wildcard DNS".to_string()],
        Stage::Probe => vec![
            "httpx -l probe-input.txt -json -status-code -title -tech-detect -web-server"
                .to_string(),
            "native HTTP prober as fallback when httpx is absent".to_string(),
        ],
        Stage::Fingerprint => vec![
            "inspect up to 25 live hosts: security headers, /.git/HEAD, /.env, directory listings"
                .to_string(),
        ],
        Stage::Ports => {
            vec!["naabu -top-ports 100, then nmap -sT -sV --open on the open ports".to_string()]
        }
        Stage::Urls => vec![format!(
            "katana -d {} -jc -kf all, native link crawler as fallback",
            config.katana_depth
        )],
        Stage::Content => vec![format!(
            "ffuf -mc 200,204,301,302,307,401,403 with {}",
            config
                .directory_wordlist()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "the embedded mini wordlist".to_string())
        )],
        Stage::Params => vec![format!(
            "harvest query strings and GET forms, cap {}",
            config.probe_params_limit
        )],
        Stage::VulnScan => vec![format!(
            "nuclei -severity {} -rate-limit {}",
            config.nuclei_severity, config.nuclei_rate_limit
        )],
        Stage::Active => {
            let mut lines = vec![
                "native probes: sqli, ssrf, redirect, cors, crlf, traversal, ssti, xss".to_string(),
            ];
            if config.oast {
                lines.push("out-of-band callbacks through interactsh".to_string());
            }
            if config.sqlmap_verify {
                lines.push("sqlmap --level=1 --risk=1 to confirm native SQLi hits".to_string());
            }
            lines
        }
        Stage::Triage => {
            vec!["dedupe by identity, score severity x confidence x reachability".to_string()]
        }
        Stage::Report => vec![format!("write {}", formats_label(options))],
    }
}

fn formats_label(options: &RunOptions) -> String {
    let formats: Vec<&str> = if options.formats.is_empty() {
        report::Format::all()
            .iter()
            .map(|format| format.label())
            .collect()
    } else {
        options
            .formats
            .iter()
            .map(|format| format.label())
            .collect()
    };
    formats.join(", ")
}

async fn check_required(profile: Profile, events: &Events) -> Result<()> {
    for spec in registry::required_for(profile, true) {
        let status = registry::detect(spec).await;
        if !status.usable() {
            let detail = registry::describe(&status);
            events.error(format!(
                "{} is required for the `{profile}` profile: {detail}",
                spec.name
            ));
            return Err(Error::MissingTool {
                tool: spec.name,
                package: spec.package,
            });
        }
    }
    Ok(())
}

async fn dispatch(stage: Stage, ctx: &Ctx<'_>, state: &mut ScanState) -> Result<Vec<PathBuf>> {
    match stage {
        Stage::Scope => scope_stage(ctx, state).await,
        Stage::Passive => passive::run(ctx, state).await,
        Stage::Dns => dns::run(ctx, state).await,
        Stage::Probe => probe::run(ctx, state).await,
        Stage::Fingerprint => fingerprint::run(ctx, state).await,
        Stage::Ports => ports::run(ctx, state).await,
        Stage::Urls => urls::run(ctx, state).await,
        Stage::Content => content::run(ctx, state).await,
        Stage::Params => params::run(ctx, state).await,
        Stage::VulnScan => vulnscan::run(ctx, state).await,
        Stage::Active => active::run(ctx, state).await,
        Stage::Triage => triage::run(ctx, state).await,
        Stage::Report => report_stage(ctx, state).await,
    }
}

/// Validate that the declared scope is resolvable and snapshot it.
async fn scope_stage(ctx: &Ctx<'_>, state: &mut ScanState) -> Result<Vec<PathBuf>> {
    let roots = ctx.scope.root_domains();
    if roots.is_empty() && ctx.scope.ips().is_empty() {
        return Err(Error::Scope(
            "scope contains no resolvable domain or address".to_string(),
        ));
    }

    let mut resolved = Vec::new();
    for root in &roots {
        ctx.check_cancel()?;
        let target = format!("{root}:443");
        let ok = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(&target))
            .await
            .map(|result| {
                result
                    .map(|mut addrs| addrs.next().is_some())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if ok {
            resolved.push(root.clone());
        } else {
            ctx.events
                .warn(format!("{root} did not resolve; continuing anyway"));
        }
        ctx.events.progress(
            Stage::Scope,
            resolved.len() as u64,
            Some(roots.len() as u64),
            root.clone(),
        );
    }

    state.subdomains.extend(roots.iter().cloned());
    state.subdomains.extend(ctx.scope.ips());

    let artifact = ctx.artifact("scope.json");
    files::write_json(
        &artifact,
        &serde_json::json!({
            "target": ctx.session.target,
            "profile": ctx.profile.as_str(),
            "roots": roots,
            "resolved": resolved,
            "ips": ctx.scope.ips(),
            "excluded": ctx.scope.exclude,
            "platform": ctx.scope.platform,
            "program": ctx.scope.program,
            "description": ctx.scope.describe(),
            "authorized_at": chrono::Utc::now().to_rfc3339(),
        }),
    )?;
    Ok(vec![artifact])
}

/// Build the report bundle and remember the paths for the caller.
async fn report_stage(ctx: &Ctx<'_>, state: &mut ScanState) -> Result<Vec<PathBuf>> {
    let triage = state
        .triage
        .clone()
        .unwrap_or_else(|| run_triage(state.findings.clone(), crate::findings::PRIMARY_THRESHOLD));
    let summary = build_summary_of(ctx.profile, ctx.session, state, &triage, ctx.elapsed());

    let formats = if ctx.formats.is_empty() {
        vec![
            report::Format::Markdown,
            report::Format::Json,
            report::Format::Html,
        ]
    } else {
        ctx.formats.to_vec()
    };

    let paths = report::write_all(
        ctx.session,
        ctx.scope,
        &summary,
        &triage,
        &state.hosts,
        &formats,
    )?;
    state.extra_artifacts.extend(paths.iter().cloned());
    ctx.events.progress(
        Stage::Report,
        paths.len() as u64,
        Some(paths.len() as u64),
        "reports written",
    );
    Ok(paths)
}

fn build_summary(
    options: &RunOptions,
    state: &ScanState,
    triage: &TriageResult,
    elapsed: Duration,
    session: &Session,
) -> ScanSummary {
    build_summary_of(options.profile, session, state, triage, elapsed)
}

fn build_summary_of(
    profile: Profile,
    session: &Session,
    state: &ScanState,
    triage: &TriageResult,
    elapsed: Duration,
) -> ScanSummary {
    let mut by_severity: Vec<(String, usize)> = Vec::new();
    for severity in crate::models::Severity::all() {
        let count = triage
            .primary
            .iter()
            .chain(triage.observations.iter())
            .filter(|finding| finding.severity == severity)
            .count();
        if count > 0 {
            by_severity.push((severity.as_str().to_string(), count));
        }
    }

    ScanSummary {
        target: session.target.clone(),
        profile: profile.as_str().to_string(),
        hosts: state.hosts.len(),
        urls: state.urls.len(),
        params: state.params.len(),
        findings: triage.primary.len() + triage.observations.len(),
        by_severity,
        elapsed_secs: elapsed.as_secs_f64(),
        session_dir: session.dir.display().to_string(),
        tools: state.tools.clone(),
        degraded: state.degraded.clone(),
    }
}

fn load_state(state: &mut ScanState, session: &Session) -> Result<()> {
    for host in files::read_lines(session.artifact("subdomains.txt"))? {
        state.subdomains.insert(host);
    }
    for host in files::read_lines(session.artifact("resolved.txt"))? {
        state.subdomains.insert(host);
    }
    state.hosts = files::read_jsonl(session.artifact("hosts.jsonl"))?;
    for url in files::read_lines(session.artifact("urls.txt"))? {
        state.urls.insert(url);
    }
    for url in files::read_lines(session.artifact("content.txt"))? {
        state.urls.insert(url);
    }
    state.params = files::read_jsonl(session.artifact("params.jsonl"))?;
    state.findings = files::read_jsonl(session.artifact("findings.jsonl"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degraded_notes_are_deduplicated() {
        let mut state = ScanState::default();
        state.degrade("nuclei missing");
        state.degrade("nuclei missing");
        assert_eq!(state.degraded.len(), 1);
    }
}
