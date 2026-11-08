//! Shared data models used by the engine, the CLI and the TUI.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Finding severity, ordered `Info < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn all() -> [Severity; 5] {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }

    pub fn weight(self) -> f32 {
        match self {
            Severity::Info => 0.5,
            Severity::Low => 2.0,
            Severity::Medium => 5.0,
            Severity::High => 8.0,
            Severity::Critical => 10.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }

    pub fn parse(value: &str) -> Option<Severity> {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "med" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" | "informational" | "unknown" => Some(Severity::Info),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much we trust a finding. Drives the triage score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Tentative,
    Firm,
    Confirmed,
}

impl Confidence {
    pub fn weight(self) -> f32 {
        match self {
            Confidence::Tentative => 0.45,
            Confidence::Firm => 0.7,
            Confidence::Confirmed => 1.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Confirmed => "confirmed",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Scan depth. Each profile is a superset of the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Light,
    Standard,
    Deep,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Light => "light",
            Profile::Standard => "standard",
            Profile::Deep => "deep",
        }
    }

    /// Ordered stage list for this profile.
    pub fn stages(self) -> Vec<Stage> {
        use Stage::*;
        let mut stages = vec![Scope, Passive, Dns, Probe, Fingerprint, VulnScan];
        if self != Profile::Light {
            stages.splice(6..6, [Urls, Content, Params]);
        }
        if self == Profile::Deep {
            stages.insert(6, Ports);
        }
        stages.extend([Active, Triage, Report]);
        stages
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Scope,
    Passive,
    Dns,
    Probe,
    Fingerprint,
    Ports,
    Urls,
    Content,
    Params,
    VulnScan,
    Active,
    Triage,
    Report,
}

impl Stage {
    pub fn all() -> Vec<Stage> {
        use Stage::*;
        vec![
            Scope,
            Passive,
            Dns,
            Probe,
            Fingerprint,
            Ports,
            Urls,
            Content,
            Params,
            VulnScan,
            Active,
            Triage,
            Report,
        ]
    }

    /// Stable identifier used in session manifests and `--only/--skip`.
    pub fn key(self) -> &'static str {
        match self {
            Stage::Scope => "scope",
            Stage::Passive => "passive",
            Stage::Dns => "dns",
            Stage::Probe => "probe",
            Stage::Fingerprint => "fingerprint",
            Stage::Ports => "ports",
            Stage::Urls => "urls",
            Stage::Content => "content",
            Stage::Params => "params",
            Stage::VulnScan => "nuclei",
            Stage::Active => "active",
            Stage::Triage => "triage",
            Stage::Report => "report",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Stage::Scope => "Scope validation",
            Stage::Passive => "Passive recon",
            Stage::Dns => "DNS resolution",
            Stage::Probe => "HTTP probing",
            Stage::Fingerprint => "Fingerprinting",
            Stage::Ports => "Port scanning",
            Stage::Urls => "URL collection",
            Stage::Content => "Content discovery",
            Stage::Params => "Parameter discovery",
            Stage::VulnScan => "Template scanning",
            Stage::Active => "Active vulnerability probes",
            Stage::Triage => "Triage & dedupe",
            Stage::Report => "Report generation",
        }
    }

    pub fn parse(value: &str) -> Option<Stage> {
        Stage::all().into_iter().find(|stage| {
            stage.key() == value.to_ascii_lowercase() || stage.label().eq_ignore_ascii_case(value)
        })
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A live HTTP endpoint discovered during probing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Host {
    pub host: String,
    pub url: String,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub webserver: String,
    #[serde(default)]
    pub tech: Vec<String>,
    #[serde(default)]
    pub cdn: Option<String>,
    #[serde(default)]
    pub content_length: u64,
}

impl Host {
    pub fn reachable(&self) -> bool {
        matches!(self.status, 200..=399)
    }
}

/// Which family a parameter name belongs to; used to route it to a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamKind {
    Url,
    Redirect,
    File,
    Id,
    Query,
    Other,
}

impl ParamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ParamKind::Url => "url",
            ParamKind::Redirect => "redirect",
            ParamKind::File => "file",
            ParamKind::Id => "id",
            ParamKind::Query => "query",
            ParamKind::Other => "other",
        }
    }

    /// Name heuristics. Deliberately generous: a false positive only costs a
    /// few extra well-behaved requests, a false negative costs a finding.
    pub fn classify(name: &str) -> ParamKind {
        let n = name.to_ascii_lowercase();
        const URL_HINTS: &[&str] = &[
            "url", "uri", "link", "src", "dest", "target", "host", "domain", "site", "feed",
            "proxy", "fetch", "load", "image", "img", "avatar", "callback", "webhook", "path",
        ];
        const REDIRECT_HINTS: &[&str] = &[
            "redirect", "redir", "return", "returnto", "next", "continue", "goto", "out", "to",
            "forward", "checkout", "success", "cancel",
        ];
        const FILE_HINTS: &[&str] = &[
            "file", "filename", "page", "template", "view", "doc", "document", "download", "dir",
            "folder", "include", "require", "read",
        ];
        const ID_HINTS: &[&str] = &[
            "id", "uid", "pid", "nid", "item", "product", "user", "account", "order", "cat",
            "category", "num", "no", "key",
        ];
        const QUERY_HINTS: &[&str] = &["q", "s", "search", "query", "keyword", "term", "filter"];

        if URL_HINTS.iter().any(|h| n == *h || n.ends_with(h)) {
            ParamKind::Url
        } else if REDIRECT_HINTS.iter().any(|h| n.contains(h)) {
            ParamKind::Redirect
        } else if FILE_HINTS.iter().any(|h| n.contains(h)) {
            ParamKind::File
        } else if ID_HINTS.iter().any(|h| n == *h || n.ends_with(h)) {
            ParamKind::Id
        } else if QUERY_HINTS.iter().any(|h| n == *h || n.contains(h)) {
            ParamKind::Query
        } else {
            ParamKind::Other
        }
    }

    /// True when an injected absolute URL is meaningful for this parameter.
    pub fn accepts_url(self) -> bool {
        matches!(self, ParamKind::Url | ParamKind::Redirect | ParamKind::File)
    }
}

impl fmt::Display for ParamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Get,
    Post,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// An injectable parameter, the unit of work for every native probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamCandidate {
    pub url: String,
    pub host: String,
    pub name: String,
    pub kind: ParamKind,
    pub method: Method,
    pub value: String,
}

impl ParamCandidate {
    pub fn new(url: impl Into<String>, name: impl Into<String>, value: impl Into<String>) -> Self {
        let url = url.into();
        let host = host_of(&url);
        let name = name.into();
        let kind = ParamKind::classify(&name);
        ParamCandidate {
            url,
            host,
            name,
            kind,
            method: Method::Get,
            value: value.into(),
        }
    }

    /// `host + path` without query string, used for dedupe keys.
    pub fn endpoint(&self) -> String {
        strip_query(&self.url)
    }
}

/// Extract the host (with port, if any) from an absolute URL.
pub fn host_of(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(parsed) => match parsed.port() {
            Some(port) if parsed.scheme() == "http" || parsed.scheme() == "https" => {
                if (parsed.scheme() == "http" && port == 80)
                    || (parsed.scheme() == "https" && port == 443)
                {
                    parsed.host_str().unwrap_or_default().to_string()
                } else {
                    format!("{}:{}", parsed.host_str().unwrap_or_default(), port)
                }
            }
            _ => parsed.host_str().unwrap_or_default().to_string(),
        },
        Err(_) => String::new(),
    }
}

fn strip_query(url: &str) -> String {
    match url.split_once('?') {
        Some((base, _)) => base.to_string(),
        None => url.to_string(),
    }
}

/// Result of a completed pipeline run, handed to the TUI and the report writer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target: String,
    pub profile: String,
    pub hosts: usize,
    pub urls: usize,
    pub params: usize,
    pub findings: usize,
    pub by_severity: Vec<(String, usize)>,
    pub elapsed_secs: f64,
    pub session_dir: String,
    pub tools: Vec<ToolVersion>,
    pub degraded: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolVersion {
    pub name: String,
    pub version: String,
}

impl ScanSummary {
    pub fn headline(&self) -> String {
        let parts: Vec<String> = self
            .by_severity
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(sev, count)| format!("{count} {sev}"))
            .collect();
        if parts.is_empty() {
            "no confirmed findings".to_string()
        } else {
            parts.join(", ")
        }
    }
}
