//! BountyTool binary.
//!
//! Dispatch, the `indicatif` progress renderer, and the exit-code contract
//! documented in [`bountytool::error::Error::exit_code`]. The engine itself
//! lives in the library; the TUI is just another consumer of it.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use tokio_util::sync::CancellationToken;

use bountytool::cli::{
    CONFIG_TEMPLATE, Cli, Command, ConfigArgs, DoctorArgs, ScanArgs, SessionsArgs,
};
use bountytool::config::Config;
use bountytool::doctor;
use bountytool::error::{Error, Result};
use bountytool::events::{Events, LogLevel, ScanEvent};
use bountytool::findings::Finding;
use bountytool::pipeline::{self, RunResult};
use bountytool::report::human_duration;
use bountytool::session::Session;
use bountytool::tui;

/// How many findings to echo on the terminal before pointing at the report.
const TOP_FINDINGS: usize = 12;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bountytool: {error}");
            ExitCode::from(error.exit_code() as u8)
        }
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Doctor(args)) => doctor_command(args).await,
        Some(Command::Sessions(args)) => sessions_command(args),
        Some(Command::Config(args)) => config_command(args),
        Some(Command::Tui(args)) => scan_command(args, true).await,
        Some(Command::Scan(args)) => scan_command(args, false).await,
        None => scan_command(cli.scan, false).await,
    }
}

async fn scan_command(args: ScanArgs, force_tui: bool) -> Result<()> {
    let prepared = args.prepare()?;

    let result = if force_tui || args.tui {
        tui::run(prepared.options).await?
    } else {
        run_with_progress(prepared.options, prepared.quiet, prepared.verbose).await?
    };

    print_result(&result);

    if prepared.open {
        open_reports(&result.reports);
    }
    Ok(())
}

/// Drain the event bus into a spinner, exactly like the TUI drains it into
/// widget state. The engine has no idea which one it is talking to.
async fn run_with_progress(
    options: pipeline::RunOptions,
    quiet: bool,
    verbose: bool,
) -> Result<RunResult> {
    let (events, mut receiver) = Events::channel();
    let cancel = CancellationToken::new();

    let mut renderer = CliRenderer::new(quiet, verbose);
    let scan_cancel = cancel.clone();
    let scan = tokio::spawn(async move { pipeline::run(options, events, scan_cancel).await });

    // Every sender lives inside the scan task, so a closed channel means the
    // task is done and the join below cannot block.
    loop {
        tokio::select! {
            biased;

            event = receiver.recv() => match event {
                Some(event) => renderer.apply(event),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => {
                renderer.note("interrupt received, cancelling (again to force)…");
                cancel.cancel();
            }
        }
    }

    let joined = scan
        .await
        .map_err(|error| Error::Other(format!("scan task failed: {error}")))?;
    renderer.finish();
    joined
}

async fn doctor_command(args: DoctorArgs) -> Result<()> {
    let group = args.resolved_group()?;
    let config = Config::load(None)?;

    if args.install {
        let commands = doctor::install_commands(group);
        if args.dry_run {
            for command in commands {
                println!("{command}");
            }
            return Ok(());
        }
        if commands.is_empty() {
            println!("nothing to install for the `{}` group", group.as_str());
        } else {
            let (events, mut receiver) = Events::channel();
            let outcome = doctor::install(group, false, &events);
            drop(events);
            while let Ok(event) = receiver.try_recv() {
                if let ScanEvent::Log { text, .. } = event {
                    eprintln!("{text}");
                }
            }
            outcome?;
        }
    }

    let report = doctor::inspect(&config).await;
    print!("{}", doctor::render(&report));

    let missing = report.missing_required();
    if !missing.is_empty() {
        println!();
        println!("Install with:");
        for command in doctor::install_commands(group) {
            println!("  {command}");
        }
    }

    if args.strict {
        if let Some(status) = missing.first() {
            return Err(Error::MissingTool {
                tool: status.name,
                package: status.package,
            });
        }
    }
    Ok(())
}

fn sessions_command(args: SessionsArgs) -> Result<()> {
    let config = Config::load(None)?;
    let root = config.sessions_root();
    let manifests = Session::list(&root)?;

    if manifests.is_empty() {
        println!("no sessions under {}", root.display());
        return Ok(());
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifests)?);
        return Ok(());
    }

    println!(
        "{:<30} {:<10} {:<20} {:>6}  STATUS",
        "SESSION", "PROFILE", "STARTED", "STAGES"
    );
    for manifest in manifests.iter().take(args.limit) {
        println!(
            "{:<30} {:<10} {:<20} {:>6}  {}",
            manifest.id,
            manifest.profile.as_str(),
            short_timestamp(&manifest.created_at),
            manifest.stages.len(),
            if manifest.status.is_empty() {
                "unknown"
            } else {
                manifest.status.as_str()
            }
        );
    }
    if manifests.len() > args.limit {
        println!(
            "\n{} more session(s); use --limit to list them",
            manifests.len() - args.limit
        );
    }
    println!("\nroot: {}", root.display());
    Ok(())
}

fn config_command(args: ConfigArgs) -> Result<()> {
    if args.init {
        let path = match args.file.clone().or_else(Config::user_config_path) {
            Some(path) => path,
            None => {
                return Err(Error::Config(
                    "cannot determine a config directory; pass --file <FILE>".to_string(),
                ));
            }
        };
        if path.exists() && !args.force {
            return Err(Error::Config(format!(
                "{} already exists; use --force to overwrite",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| Error::io(parent, error))?;
        }
        std::fs::write(&path, CONFIG_TEMPLATE).map_err(|error| Error::io(&path, error))?;
        println!("wrote {}", path.display());
        return Ok(());
    }

    let config = Config::load(args.file.as_deref())?;
    let text = toml::to_string_pretty(&config)
        .map_err(|error| Error::Config(format!("cannot render config: {error}")))?;
    print!("{text}");
    Ok(())
}

/// `2026-11-08T10:22:31.5+00:00` -> `2026-11-08 10:22:31`.
fn short_timestamp(value: &str) -> String {
    value
        .get(..19)
        .unwrap_or(value)
        .replace('T', " ")
        .to_string()
}

fn open_reports(paths: &[PathBuf]) {
    let html = paths
        .iter()
        .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("html"));
    let Some(target) = html.or_else(|| paths.first()) else {
        return;
    };
    match std::process::Command::new("xdg-open").arg(target).spawn() {
        Ok(_) => {}
        Err(error) => eprintln!("bountytool: cannot open {}: {error}", target.display()),
    }
}

fn print_result(result: &RunResult) {
    let summary = &result.summary;
    let triage = &result.triage;

    println!();
    println!("Scan complete: {}", summary.target);
    println!("  profile    : {}", summary.profile);
    println!("  duration   : {}", human_duration(summary.elapsed_secs));
    println!("  hosts      : {}", summary.hosts);
    println!("  urls       : {}", summary.urls);
    println!("  parameters : {}", summary.params);
    println!("  session    : {}", summary.session_dir);

    if result.dry_run {
        println!("\nDry run: no traffic was sent and no session was created.");
        return;
    }

    if triage.primary.is_empty() {
        println!("\nNo primary findings.");
    } else {
        println!("\n{} primary finding(s):", triage.primary.len());
        for finding in triage.primary.iter().take(TOP_FINDINGS) {
            println!("  {}", headline(finding));
        }
        if triage.primary.len() > TOP_FINDINGS {
            println!(
                "  … and {} more (see the report)",
                triage.primary.len() - TOP_FINDINGS
            );
        }
    }

    if !triage.observations.is_empty() {
        println!(
            "{} lower-confidence observation(s) recorded in the report appendix.",
            triage.observations.len()
        );
    }

    if !summary.degraded.is_empty() {
        println!("\nDegraded coverage:");
        for note in &summary.degraded {
            println!("  - {note}");
        }
    }

    if result.reports.is_empty() {
        println!("\nNo report written (the report stage did not run).");
    } else {
        println!("\nReports:");
        for path in &result.reports {
            println!("  {}", path.display());
        }
    }
}

fn headline(finding: &Finding) -> String {
    let param = finding
        .parameter
        .as_deref()
        .map(|name| format!(" [{name}]"))
        .unwrap_or_default();
    format!(
        "[{:<4}] {}{} — {} ({}, score {:.1})",
        finding.severity.label(),
        finding.category.label(),
        param,
        finding.host,
        finding.confidence.as_str(),
        finding.score
    )
}

/// CLI frontend: one spinner plus log lines above it.
///
/// The final numbers are printed by [`print_result`] once the scan returns, so
/// this renderer only reports progress and anything worth interrupting for.
struct CliRenderer {
    bar: ProgressBar,
    quiet: bool,
    verbose: bool,
}

impl CliRenderer {
    fn new(quiet: bool, verbose: bool) -> CliRenderer {
        let bar = ProgressBar::new_spinner();
        if quiet {
            bar.set_draw_target(ProgressDrawTarget::hidden());
        } else {
            let style = ProgressStyle::with_template("{spinner} {prefix} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .tick_strings(&["-", "\\", "|", "/"]);
            bar.set_style(style);
            bar.set_draw_target(ProgressDrawTarget::stderr());
            bar.enable_steady_tick(Duration::from_millis(120));
        }
        CliRenderer {
            bar,
            quiet,
            verbose,
        }
    }

    fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started {
                target,
                profile,
                session_dir,
                stages,
            } => {
                self.note(format!(
                    "scanning {target} ({profile} profile, {} stage(s))",
                    stages.len()
                ));
                self.note(format!("session: {}", session_dir.display()));
            }
            ScanEvent::StageStarted {
                stage,
                index,
                total,
            } => {
                self.bar.set_prefix(format!("[{}/{}]", index + 1, total));
                self.bar.set_message(stage.label().to_string());
            }
            ScanEvent::StageProgress {
                done, total, label, ..
            } => {
                let counter = match total {
                    Some(total) if total > 0 => format!("{done}/{total}"),
                    _ => done.to_string(),
                };
                self.bar.set_message(format!("{counter}  {label}"));
            }
            ScanEvent::StageSkipped { stage, reason } => {
                self.note(format!("- {} skipped ({reason})", stage.label()));
            }
            ScanEvent::StageFinished {
                stage,
                elapsed,
                artifacts,
                ok,
            } => {
                if ok {
                    self.note(format!(
                        "+ {} ({}, {} artifact(s))",
                        stage.label(),
                        human_duration(elapsed.as_secs_f64()),
                        artifacts.len()
                    ));
                } else {
                    self.note(format!("! {} failed", stage.label()));
                }
            }
            ScanEvent::HostFound(_) | ScanEvent::UrlFound(_) | ScanEvent::ParamFound(_) => {}
            ScanEvent::Finding(finding) => {
                self.note(format!("* {}", headline(&finding)));
            }
            ScanEvent::Log { level, tool, text } => {
                if let Some(line) = render_log(level, tool, &text, self.verbose) {
                    self.note(line);
                }
            }
            // The summary is printed by `print_result` on the terminal proper,
            // after the spinner is cleared.
            ScanEvent::Finished(_) => {}
            ScanEvent::Failed(message) => self.note(format!("failed: {message}")),
        }
    }

    fn note(&self, text: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        let text = text.as_ref();
        self.bar.suspend(|| {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "{text}");
        });
    }

    fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

/// Info lines are the normal voice of the pipeline, so they go out bare;
/// warnings and errors keep a prefix so they are easy to spot in a long run.
fn render_log(
    level: LogLevel,
    tool: Option<&'static str>,
    text: &str,
    verbose: bool,
) -> Option<String> {
    let prefix = match level {
        LogLevel::Debug => {
            if !verbose {
                return None;
            }
            "debug: "
        }
        LogLevel::Info => "",
        LogLevel::Warn => "warn: ",
        LogLevel::Error => "error: ",
    };
    Some(match tool {
        Some(tool) => format!("{prefix}{tool}: {text}"),
        None => format!("{prefix}{text}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bountytool::models::Stage;

    #[test]
    fn debug_logs_are_hidden_unless_verbose() {
        assert!(render_log(LogLevel::Debug, None, "raw", false).is_none());
        assert!(render_log(LogLevel::Debug, None, "raw", true).is_some());
        assert!(render_log(LogLevel::Warn, None, "careful", false).is_some());
    }

    #[test]
    fn timestamps_are_shortened() {
        assert_eq!(
            short_timestamp("2026-11-08T10:22:31.123+00:00"),
            "2026-11-08 10:22:31"
        );
    }

    #[test]
    fn stage_labels_are_reachable() {
        assert_eq!(Stage::Probe.label(), "HTTP probing");
    }
}
