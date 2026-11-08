//! The single source of truth for every external tool BountyTool drives.
//!
//! One table powers three things: the pipeline's availability checks, the
//! `doctor` report, and `doctor --install` (which groups packages for pacman
//! and yay).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use regex::Regex;
use tokio::process::Command;

use crate::models::Stage;

/// Installation grouping used by `doctor --install --group <name>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Bare minimum for a useful scan.
    Core,
    /// Strongly recommended; unlocks more stages.
    Recommended,
    /// Heavy or situational.
    Heavy,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Core => "core",
            Group::Recommended => "recommended",
            Group::Heavy => "heavy",
        }
    }

    pub fn parse(value: &str) -> Option<Group> {
        match value.to_ascii_lowercase().as_str() {
            "core" => Some(Group::Core),
            "recommended" | "rec" => Some(Group::Recommended),
            "heavy" | "optional" | "all" => Some(Group::Heavy),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ToolSpec {
    /// Executable name.
    pub name: &'static str,
    /// Arch package, prefixed with the repository it comes from.
    pub package: &'static str,
    pub group: Group,
    pub stage: Stage,
    pub purpose: &'static str,
    /// Required by the `standard` profile; absent = hard error.
    pub required: bool,
    /// Arguments that print the version.
    pub version_args: &'static [&'static str],
    /// Case-insensitive substring proving we detected the right project
    /// (notably distinguishes ProjectDiscovery `httpx` from python-httpx).
    pub version_needle: &'static str,
    pub min_version: &'static str,
}

pub const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "nuclei",
        package: "aur/nuclei",
        group: Group::Core,
        stage: Stage::VulnScan,
        purpose: "template based vulnerability scanning",
        required: true,
        version_args: &["-version"],
        version_needle: "nuclei engine",
        min_version: "3.0.0",
    },
    ToolSpec {
        name: "subfinder",
        package: "aur/subfinder",
        group: Group::Core,
        stage: Stage::Passive,
        purpose: "passive subdomain enumeration",
        required: true,
        version_args: &["-version"],
        version_needle: "subfinder",
        min_version: "2.5.0",
    },
    ToolSpec {
        name: "httpx",
        package: "aur/httpx",
        group: Group::Core,
        stage: Stage::Probe,
        purpose: "HTTP probing and technology detection",
        required: true,
        version_args: &["-version"],
        version_needle: "projectdiscovery",
        min_version: "1.3.0",
    },
    ToolSpec {
        name: "katana",
        package: "aur/katana-bin",
        group: Group::Recommended,
        stage: Stage::Urls,
        purpose: "crawling for endpoints and parameters",
        required: false,
        version_args: &["-version"],
        version_needle: "katana",
        min_version: "1.0.0",
    },
    ToolSpec {
        name: "ffuf",
        package: "aur/ffuf-bin",
        group: Group::Recommended,
        stage: Stage::Content,
        purpose: "content and directory discovery",
        required: false,
        version_args: &["-V"],
        version_needle: "ffuf",
        min_version: "2.0.0",
    },
    ToolSpec {
        name: "gobuster",
        package: "extra/gobuster",
        group: Group::Recommended,
        stage: Stage::Content,
        purpose: "fallback content discovery when ffuf is absent",
        required: false,
        version_args: &["version"],
        version_needle: "gobuster",
        min_version: "3.0.0",
    },
    ToolSpec {
        name: "dalfox",
        package: "aur/dalfox",
        group: Group::Recommended,
        stage: Stage::Active,
        purpose: "XSS verification of reflected parameters",
        required: false,
        version_args: &["version"],
        version_needle: "dalfox",
        min_version: "2.8.0",
    },
    ToolSpec {
        name: "sqlmap",
        package: "extra/sqlmap",
        group: Group::Recommended,
        stage: Stage::Active,
        purpose: "SQL injection verification (non-destructive)",
        required: false,
        version_args: &["--version"],
        version_needle: "sqlmap",
        min_version: "1.5.0",
    },
    ToolSpec {
        name: "nmap",
        package: "extra/nmap",
        group: Group::Recommended,
        stage: Stage::Ports,
        purpose: "port and service discovery in the deep profile",
        required: false,
        version_args: &["-V"],
        version_needle: "nmap",
        min_version: "7.0",
    },
    ToolSpec {
        name: "naabu",
        package: "aur/naabu",
        group: Group::Recommended,
        stage: Stage::Ports,
        purpose: "fast port discovery before nmap",
        required: false,
        version_args: &["-version"],
        version_needle: "naabu",
        min_version: "2.0.0",
    },
    ToolSpec {
        name: "findomain",
        package: "extra/findomain",
        group: Group::Recommended,
        stage: Stage::Passive,
        purpose: "second opinion on passive subdomains",
        required: false,
        version_args: &["--version"],
        version_needle: "findomain",
        min_version: "8.0.0",
    },
    ToolSpec {
        name: "interactsh-client",
        package: "aur/interactsh-client",
        group: Group::Recommended,
        stage: Stage::Active,
        purpose: "out-of-band callbacks for blind SSRF",
        required: false,
        version_args: &["-version"],
        version_needle: "interactsh",
        min_version: "1.0.0",
    },
];

pub fn spec(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|spec| spec.name == name)
}

/// Tools required for a given profile. Light and standard need the core set;
/// the deep profile additionally wants the port scanners.
pub fn required_for(profile: crate::models::Profile, deep_ports: bool) -> Vec<&'static ToolSpec> {
    use crate::models::Profile;
    let mut required: Vec<&ToolSpec> = TOOLS.iter().filter(|spec| spec.required).collect();
    if profile == Profile::Deep && deep_ports {
        if let Some(nmap) = spec("nmap") {
            required.push(nmap);
        }
    }
    required
}

/// Locate an executable on `PATH` without pulling in a dependency.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&candidate) {
                    if meta.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(candidate);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub name: &'static str,
    pub package: &'static str,
    pub group: Group,
    pub stage: Stage,
    pub purpose: &'static str,
    pub required: bool,
    pub found: bool,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    /// False when the detected binary is not the project we expect.
    pub identity_ok: bool,
    pub note: Option<String>,
}

impl ToolStatus {
    pub fn usable(&self) -> bool {
        self.found && self.identity_ok
    }
}

/// Run `--version` style commands and identify the binary.
pub async fn detect(spec: &'static ToolSpec) -> ToolStatus {
    let path = which(spec.name);
    let mut status = ToolStatus {
        name: spec.name,
        package: spec.package,
        group: spec.group,
        stage: spec.stage,
        purpose: spec.purpose,
        required: spec.required,
        found: path.is_some(),
        path,
        version: None,
        identity_ok: true,
        note: None,
    };

    let Some(binary) = status.path.clone() else {
        return status;
    };

    let output = run_version(&binary, spec.version_args).await;
    if output.is_empty() {
        status.note = Some("binary found but version probe failed".to_string());
        return status;
    }

    let lowered = output.to_ascii_lowercase();
    if !spec.version_needle.is_empty() && !lowered.contains(spec.version_needle) {
        // A few tools print nothing but a bare version number (`sqlmap` prints
        // `1.10.7#stable`). Their own help text is then the only way to tell
        // the expected binary from a namesake such as python-httpx.
        let help = run_version(&binary, &["-h"]).await.to_ascii_lowercase();
        if !help.contains(spec.version_needle) {
            status.identity_ok = false;
            status.note = Some(format!(
                "`{}` on PATH is not {} (expected version output containing \"{}\"); install {}",
                spec.name, spec.name, spec.version_needle, spec.package
            ));
        }
    }

    status.version = extract_version(&output);
    if let Some(version) = &status.version {
        if version_lt(version, spec.min_version) {
            status.note = Some(format!(
                "{} is older than the supported minimum {}",
                version, spec.min_version
            ));
            status.identity_ok = false;
        }
    }
    status
}

pub async fn detect_all() -> Vec<ToolStatus> {
    let mut statuses = Vec::with_capacity(TOOLS.len());
    for spec in TOOLS {
        statuses.push(detect(spec).await);
    }
    statuses
}

/// Human-readable summary used by `doctor` and the report header.
pub fn describe(status: &ToolStatus) -> String {
    if !status.found {
        return format!("missing ({})", status.package);
    }
    if !status.identity_ok {
        return status
            .note
            .clone()
            .unwrap_or_else(|| "incompatible".to_string());
    }
    format!(
        "{} ({})",
        status.version.as_deref().unwrap_or("unknown version"),
        status.package
    )
}

async fn run_version(binary: &PathBuf, args: &[&str]) -> String {
    let mut command = Command::new(binary);
    command.args(args).stdin(Stdio::null()).kill_on_drop(true);
    let timeout = Duration::from_secs(8);

    let output = match tokio::time::timeout(timeout, command.output()).await {
        Ok(Ok(output)) => output,
        _ => {
            // Some tools only understand the other dash convention.
            let fallback = match args {
                ["--version"] => "-version",
                ["-version"] => "--version",
                _ => return String::new(),
            };
            let mut retry = Command::new(binary);
            retry.arg(fallback).stdin(Stdio::null()).kill_on_drop(true);
            match tokio::time::timeout(timeout, retry.output()).await {
                Ok(Ok(output)) => output,
                _ => return String::new(),
            }
        }
    };

    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text.trim().to_string()
}

fn extract_version(output: &str) -> Option<String> {
    let regex = Regex::new(r"(\d+)\.(\d+)(?:\.(\d+))?").ok()?;
    regex
        .captures(output)
        .and_then(|caps| caps.get(0))
        .map(|matched| matched.as_str().to_string())
}

/// Numeric-aware version comparison, tolerant of missing components.
pub fn version_lt(actual: &str, minimum: &str) -> bool {
    fn parts(value: &str) -> Vec<u64> {
        value
            .split(|ch: char| !ch.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .take(3)
            .collect()
    }
    let left = parts(actual);
    let right = parts(minimum);
    for index in 0..3 {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        if a != b {
            return a < b;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(version_lt("1.2.3", "1.10.0"));
        assert!(version_lt("2.0", "3.0.0"));
        assert!(!version_lt("3.1.0", "3.0.0"));
        assert!(!version_lt("1.0.0", "1.0"));
    }

    #[test]
    fn version_extraction() {
        assert_eq!(
            extract_version("Nuclei Engine Version: v3.3.5").as_deref(),
            Some("3.3.5")
        );
        assert_eq!(
            extract_version("projectdiscovery/httpx v1.6.9").as_deref(),
            Some("1.6.9")
        );
        assert_eq!(extract_version("no numbers here"), None);
    }

    #[test]
    fn httpx_identity_is_guarded() {
        let spec = spec("httpx").unwrap();
        assert_eq!(spec.version_needle, "projectdiscovery");
        assert!(!spec.package.is_empty());
    }

    #[test]
    fn registry_names_are_unique() {
        let mut names: Vec<&str> = TOOLS.iter().map(|spec| spec.name).collect();
        names.sort();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn groups_parse() {
        assert_eq!(Group::parse("core"), Some(Group::Core));
        assert_eq!(Group::parse("ALL"), Some(Group::Heavy));
        assert_eq!(Group::parse("nope"), None);
    }
}
