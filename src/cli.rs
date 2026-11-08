//! The command line surface.
//!
//! This module is pure argument handling: parse, resolve, validate. It never
//! touches the network and never prints. `main.rs` dispatches on the result and
//! [`ScanArgs::prepare`] hands the pipeline exactly what it needs.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::models::{Profile, Stage};
use crate::pipeline::RunOptions;
use crate::report::Format;
use crate::scope::{self, Scope};
use crate::session::Session;
use crate::tools::Group;

const STAGE_LIST: &str = "scope, passive, dns, probe, fingerprint, ports, urls, content, params, nuclei, active, triage, report";

const QUICK_START: &str = "\
Examples:
  bountytool example.com -y                      # standard scan, CLI progress
  bountytool example.com -y --tui                # same scan, full-screen TUI
  bountytool -y --scope scope.toml --profile deep
  bountytool example.com -y --only probe,nuclei,active,report
  bountytool doctor --install --group recommended
  bountytool sessions --limit 10

Active scanning is refused without -y/--i-have-authorization and a scope.";

#[derive(Debug, Parser)]
#[command(
    name = "bountytool",
    version,
    about = "End-to-end bug bounty reconnaissance, vulnerability triage and reporting",
    args_conflicts_with_subcommands = true,
    after_help = QUICK_START
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// No subcommand: run a scan with these options.
    #[command(flatten)]
    pub scan: ScanArgs,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a scan inside the full-screen TUI
    Tui(ScanArgs),
    /// Run a scan and print progress (the default)
    Scan(ScanArgs),
    /// Inspect (and optionally install) the external toolchain
    Doctor(DoctorArgs),
    /// List previous scan sessions
    Sessions(SessionsArgs),
    /// Print the merged configuration, or write a starter file
    Config(ConfigArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// Target domain, host or IP (optional when --scope lists targets)
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Scope file (a ./scope.toml is picked up automatically)
    #[arg(long, value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Additional in-scope host or domain (repeatable)
    #[arg(long = "in-scope", value_name = "HOST")]
    pub in_scope: Vec<String>,

    /// How deep to go
    #[arg(long, short = 'p', value_enum, default_value_t = Profile::Standard)]
    pub profile: Profile,

    /// Confirm you are authorised to test this target (required)
    #[arg(long, short = 'y', alias = "yes")]
    pub i_have_authorization: bool,

    /// Run the scan in the full-screen TUI
    #[arg(long)]
    pub tui: bool,

    /// Show the commands the pipeline would run, without running them
    #[arg(long)]
    pub dry_run: bool,

    /// Run only these stages
    #[arg(long, value_name = "STAGE", value_delimiter = ',')]
    pub only: Vec<String>,

    /// Skip these stages
    #[arg(long, value_name = "STAGE", value_delimiter = ',')]
    pub skip: Vec<String>,

    /// Report formats to write: md,json,html
    #[arg(long, short = 'f', value_name = "FORMAT", value_delimiter = ',')]
    pub format: Vec<String>,

    /// Resume a previous session directory
    #[arg(long, value_name = "DIR")]
    pub resume: Option<PathBuf>,

    /// Open the HTML report when the scan finishes
    #[arg(long)]
    pub open: bool,

    /// Only print the final result
    #[arg(long)]
    pub quiet: bool,

    /// Include debug logs and raw tool output
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Configuration file to use instead of the default
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

/// A validated scan, ready to hand to the engine.
pub struct Prepared {
    pub options: RunOptions,
    pub quiet: bool,
    pub verbose: bool,
    pub open: bool,
}

impl ScanArgs {
    pub fn prepare(&self) -> Result<Prepared> {
        let config = Config::load(self.config.as_deref())?;
        let scope = self.resolve_scope()?;
        let target = self.resolve_target(&scope)?;
        let stages = self.resolve_stages()?;
        let formats = self.resolve_formats()?;

        Ok(Prepared {
            options: RunOptions {
                target,
                profile: self.profile,
                scope,
                config,
                stages,
                dry_run: self.dry_run,
                authorized: self.i_have_authorization,
                resume: self.resume.clone(),
                formats,
                skip_preflight: false,
            },
            quiet: self.quiet,
            verbose: self.verbose,
            open: self.open,
        })
    }

    /// Explicit `--scope` wins, then `./scope.toml`, then the inline target.
    pub fn resolve_scope(&self) -> Result<Scope> {
        let from_file = match &self.scope {
            Some(path) => Some(Scope::load(path)?),
            None => match Scope::scope_path() {
                Some(path) if path.is_file() => Some(Scope::load(&path)?),
                _ => None,
            },
        };

        let scope = match from_file {
            Some(scope) => with_targets(scope, self.target.as_deref(), &self.in_scope),
            None if self.target.is_some() => {
                with_targets(Scope::default(), self.target.as_deref(), &self.in_scope)
            }
            None => match &self.resume {
                // A resumed session already recorded the scope it ran under.
                Some(dir) => {
                    let session = Session::open(dir)?;
                    let base = session.manifest.scope.clone().unwrap_or_else(|| Scope {
                        targets: vec![session.target.clone()],
                        ..Default::default()
                    });
                    with_targets(base, None, &self.in_scope)
                }
                None => {
                    return Err(Error::Config(format!(
                        "no scope given: pass a target, --scope <FILE> or --in-scope <HOST> (stages: {STAGE_LIST})"
                    )));
                }
            },
        };

        scope.validate()?;
        Ok(scope)
    }

    /// The name the session is filed under.
    pub fn resolve_target(&self, scope: &Scope) -> Result<String> {
        if let Some(target) = &self.target {
            let normalized = scope::normalize(target);
            if normalized.is_empty() {
                return Err(Error::BadTarget(target.clone()));
            }
            return Ok(normalized);
        }
        if let Some(dir) = &self.resume {
            return Ok(Session::open(dir)?.target);
        }
        scope.targets.first().cloned().ok_or_else(|| {
            Error::Config(
                "no target given: pass a domain, --scope <FILE> or --resume <DIR>".to_string(),
            )
        })
    }

    /// Profile stages, narrowed by `--only` and pruned by `--skip`.
    pub fn resolve_stages(&self) -> Result<Vec<Stage>> {
        let only = parse_stages(&self.only)?;
        let skip = parse_stages(&self.skip)?;

        let mut stages = if only.is_empty() {
            self.profile.stages()
        } else {
            Stage::all()
        };
        stages.retain(|stage| !skip.contains(stage));
        if !only.is_empty() {
            stages.retain(|stage| only.contains(stage));
        }
        if stages.is_empty() {
            return Err(Error::Config(
                "no stages left to run after --only/--skip".to_string(),
            ));
        }
        Ok(stages)
    }

    pub fn resolve_formats(&self) -> Result<Vec<Format>> {
        if self.format.is_empty() {
            return Ok(Format::all().to_vec());
        }
        let mut formats = Vec::new();
        for raw in &self.format {
            for piece in raw.split(',') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                match Format::parse(piece) {
                    Some(format) => {
                        if !formats.contains(&format) {
                            formats.push(format);
                        }
                    }
                    None => {
                        return Err(Error::Config(format!(
                            "unknown report format `{piece}`; valid formats: md, json, html"
                        )));
                    }
                }
            }
        }
        if formats.is_empty() {
            return Err(Error::Config(
                "no report format selected; valid formats: md, json, html".to_string(),
            ));
        }
        Ok(formats)
    }
}

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Install the missing packages for the group
    #[arg(long)]
    pub install: bool,

    /// Package group to install or check
    #[arg(long, value_name = "GROUP", default_value = "core")]
    pub group: String,

    /// Print the install commands without running them
    #[arg(long)]
    pub dry_run: bool,

    /// Exit non-zero when a required tool is missing
    #[arg(long)]
    pub strict: bool,
}

impl DoctorArgs {
    pub fn resolved_group(&self) -> Result<Group> {
        Group::parse(&self.group).ok_or_else(|| {
            Error::Config(format!(
                "unknown group `{}`; valid groups: core, recommended, heavy",
                self.group
            ))
        })
    }
}

#[derive(Debug, Clone, Args)]
pub struct SessionsArgs {
    /// How many sessions to list
    #[arg(long, value_name = "N", default_value_t = 20)]
    pub limit: usize,

    /// Print the raw JSON manifests
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigArgs {
    /// Write a starter config file instead of printing the merged one
    #[arg(long)]
    pub init: bool,

    /// Overwrite an existing config file with --init
    #[arg(long)]
    pub force: bool,

    /// Config file path (defaults to ~/.config/bountytool/config.toml)
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

/// Starter config written by `bountytool config --init`.
///
/// The same file the binary compiles in, so a generated config always matches
/// the documented defaults.
pub const CONFIG_TEMPLATE: &str = include_str!("../config/default.toml");

fn parse_stages(values: &[String]) -> Result<Vec<Stage>> {
    let mut stages = Vec::new();
    for raw in values {
        for piece in raw.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            match Stage::parse(piece) {
                Some(stage) => {
                    if !stages.contains(&stage) {
                        stages.push(stage);
                    }
                }
                None => {
                    return Err(Error::Config(format!(
                        "unknown stage `{piece}`; valid stages: {STAGE_LIST}"
                    )));
                }
            }
        }
    }
    Ok(stages)
}

/// Overlay the positional target and any `--in-scope` values onto a scope.
fn with_targets(mut scope: Scope, target: Option<&str>, in_scope: &[String]) -> Scope {
    for entry in in_scope {
        let normalized = scope::normalize(entry);
        if !normalized.is_empty() && !scope.targets.contains(&normalized) {
            scope.targets.push(normalized);
        }
    }
    if let Some(target) = target {
        let normalized = scope::normalize(target);
        if !normalized.is_empty() && !scope.targets.contains(&normalized) {
            scope.targets.insert(0, normalized);
        }
    }
    scope
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scan_parses_without_a_subcommand() {
        let cli = Cli::try_parse_from(["bountytool", "example.com", "-y"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.scan.target.as_deref(), Some("example.com"));
        assert!(cli.scan.i_have_authorization);
    }

    #[test]
    fn doctor_is_a_subcommand() {
        let cli = Cli::try_parse_from(["bountytool", "doctor", "--install"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Doctor(ref args)) if args.install));
    }

    #[test]
    fn only_and_skip_narrow_the_profile() {
        let args = ScanArgs {
            target: Some("example.com".to_string()),
            profile: Profile::Standard,
            only: vec!["probe".to_string(), "report".to_string()],
            skip: vec!["report".to_string()],
            ..Cli::try_parse_from(["bountytool", "example.com"])
                .unwrap()
                .scan
        };
        let stages = args.resolve_stages().unwrap();
        assert_eq!(stages, vec![Stage::Probe]);
    }

    #[test]
    fn unknown_stage_is_rejected() {
        let args = ScanArgs {
            target: Some("example.com".to_string()),
            only: vec!["nope".to_string()],
            ..Cli::try_parse_from(["bountytool", "example.com"])
                .unwrap()
                .scan
        };
        assert!(args.resolve_stages().is_err());
    }

    #[test]
    fn inline_scope_includes_the_target() {
        let args =
            Cli::try_parse_from(["bountytool", "example.com", "--in-scope", "api.example.com"])
                .unwrap()
                .scan;
        let scope = args.resolve_scope().unwrap();
        assert!(scope.allows("example.com"));
        assert!(scope.allows("api.example.com"));
    }

    #[test]
    fn formats_default_to_all_and_accept_a_list() {
        let args = Cli::try_parse_from(["bountytool", "example.com", "-f", "md,html"])
            .unwrap()
            .scan;
        assert_eq!(
            args.resolve_formats().unwrap(),
            vec![Format::Markdown, Format::Html]
        );
    }
}
