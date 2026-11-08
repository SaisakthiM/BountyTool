//! Report generation: Markdown for reading, JSON for tooling, HTML for
//! sharing.
//!
//! Every renderer consumes the same [`TriageResult`], so the three formats can
//! never disagree about what was found.

pub mod html;
pub mod json;
pub mod markdown;

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::findings::TriageResult;
use crate::models::{Host, ScanSummary};
use crate::scope::Scope;
use crate::session::Session;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Json,
    Html,
}

impl Format {
    pub fn all() -> [Format; 3] {
        [Format::Markdown, Format::Json, Format::Html]
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Markdown => "md",
            Format::Json => "json",
            Format::Html => "html",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Format::Markdown => "markdown",
            Format::Json => "json",
            Format::Html => "html",
        }
    }

    pub fn parse(value: &str) -> Option<Format> {
        match value.trim().to_ascii_lowercase().as_str() {
            "md" | "markdown" => Some(Format::Markdown),
            "json" => Some(Format::Json),
            "html" | "htm" => Some(Format::Html),
            _ => None,
        }
    }
}

/// Everything a renderer needs, borrowed from the finished scan.
pub struct Report<'a> {
    pub session: &'a Session,
    pub scope: &'a Scope,
    pub summary: &'a ScanSummary,
    pub triage: &'a TriageResult,
    pub hosts: &'a [Host],
}

impl Report<'_> {
    pub fn generated_at(&self) -> String {
        chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string()
    }

    pub fn primary(&self) -> &[crate::findings::Finding] {
        &self.triage.primary
    }

    pub fn observations(&self) -> &[crate::findings::Finding] {
        &self.triage.observations
    }

    pub fn total_findings(&self) -> usize {
        self.triage.primary.len() + self.triage.observations.len()
    }
}

/// Render every requested format into the session directory.
pub fn write_all(
    session: &Session,
    scope: &Scope,
    summary: &ScanSummary,
    triage: &TriageResult,
    hosts: &[Host],
    formats: &[Format],
) -> Result<Vec<PathBuf>> {
    let report = Report {
        session,
        scope,
        summary,
        triage,
        hosts,
    };

    let mut written: Vec<PathBuf> = Vec::new();
    for format in formats {
        let path = session.report_path(format.extension());
        if written.contains(&path) {
            continue;
        }
        let text = match format {
            Format::Markdown => markdown::render(&report),
            Format::Json => json::render(&report)?,
            Format::Html => html::render(&report),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
        written.push(path);
    }
    Ok(written)
}

/// `93.4` -> `1m 33s`.
pub fn human_duration(seconds: f64) -> String {
    let total = seconds.max(0.0) as u64;
    let (hours, minutes, secs) = (total / 3600, (total % 3600) / 60, total % 60);
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

/// Escape the characters that break a Markdown table cell.
pub fn md_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

/// Escape the five HTML metacharacters.
pub fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
