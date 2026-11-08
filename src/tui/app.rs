//! TUI state.
//!
//! The app is a pure function of the [`ScanEvent`] stream: it never talks to
//! the network and never spawns anything, which keeps the widget code trivial
//! and the engine the single source of truth.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::events::{LogLevel, ScanEvent};
use crate::findings::Finding;
use crate::models::{Host, ScanSummary, Severity, Stage};

/// Bounded buffers: a scan can emit hundreds of thousands of lines.
pub const LOG_LIMIT: usize = 800;
pub const HOST_LIMIT: usize = 3_000;
pub const FINDING_LIMIT: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Findings,
    Hosts,
    Log,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Overview, Tab::Findings, Tab::Hosts, Tab::Log];

    pub fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Findings => 1,
            Tab::Hosts => 2,
            Tab::Log => 3,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Findings => "Findings",
            Tab::Hosts => "Hosts",
            Tab::Log => "Log",
        }
    }

    pub fn next(self) -> Tab {
        match self {
            Tab::Overview => Tab::Findings,
            Tab::Findings => Tab::Hosts,
            Tab::Hosts => Tab::Log,
            Tab::Log => Tab::Overview,
        }
    }

    pub fn previous(self) -> Tab {
        match self {
            Tab::Overview => Tab::Log,
            Tab::Log => Tab::Hosts,
            Tab::Hosts => Tab::Findings,
            Tab::Findings => Tab::Overview,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StageStatus {
    Pending,
    Running,
    Done(Duration),
    Skipped(String),
    Failed(Duration),
}

impl StageStatus {
    pub fn symbol(&self) -> &'static str {
        match self {
            StageStatus::Pending => "·",
            StageStatus::Running => "▸",
            StageStatus::Done(_) => "✔",
            StageStatus::Skipped(_) => "–",
            StageStatus::Failed(_) => "✘",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            StageStatus::Pending => "queued".to_string(),
            StageStatus::Running => "running".to_string(),
            StageStatus::Done(elapsed) => super::format_duration(*elapsed),
            StageStatus::Skipped(reason) => format!("skipped: {reason}"),
            StageStatus::Failed(elapsed) => {
                format!("failed after {}", super::format_duration(*elapsed))
            }
        }
    }
}

pub struct StageRow {
    pub stage: Stage,
    pub status: StageStatus,
}

pub struct LogLine {
    pub level: LogLevel,
    pub source: Option<&'static str>,
    pub at: String,
    pub text: String,
}

pub struct App {
    pub target: String,
    pub profile: String,
    pub session_dir: PathBuf,
    pub stages: Vec<StageRow>,
    pub current: Option<usize>,
    pub progress: Option<(u64, Option<u64>, String)>,
    pub hosts: Vec<Host>,
    pub hosts_seen: usize,
    pub urls_seen: usize,
    pub params_seen: usize,
    pub findings: Vec<Finding>,
    pub logs: VecDeque<LogLine>,
    pub summary: Option<ScanSummary>,
    pub failed: Option<String>,
    pub finished: bool,
    pub tab: Tab,
    pub scroll: u16,
    pub started: Instant,
    pub quit_requested: bool,
}

impl App {
    pub fn new(target: String, profile: String, stages: Vec<Stage>) -> App {
        let stages = stages
            .into_iter()
            .map(|stage| StageRow {
                stage,
                status: StageStatus::Pending,
            })
            .collect();
        App {
            target,
            profile,
            session_dir: PathBuf::new(),
            stages,
            current: None,
            progress: None,
            hosts: Vec::new(),
            hosts_seen: 0,
            urls_seen: 0,
            params_seen: 0,
            findings: Vec::new(),
            logs: VecDeque::new(),
            summary: None,
            failed: None,
            finished: false,
            tab: Tab::Overview,
            scroll: 0,
            started: Instant::now(),
            quit_requested: false,
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn next_tab(&mut self) {
        self.tab = self.tab.next();
        self.scroll = 0;
    }

    pub fn previous_tab(&mut self) {
        self.tab = self.tab.previous();
        self.scroll = 0;
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll = self.scroll.saturating_add(amount);
    }

    pub fn scroll_top(&mut self) {
        self.scroll = 0;
    }

    pub fn scroll_bottom(&mut self) {
        self.scroll = self.max_scroll();
    }

    /// Rough row count of the focused pane; good enough for `G`.
    pub fn max_scroll(&self) -> u16 {
        let rows = match self.tab {
            Tab::Overview => self.stages.len(),
            Tab::Findings => self.findings.len(),
            Tab::Hosts => self.hosts.len(),
            Tab::Log => self.logs.len(),
        };
        rows.saturating_sub(1).min(u16::MAX as usize) as u16
    }

    /// Findings always sorted worst-first.
    pub fn sorted_findings(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity).then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        findings
    }

    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        Severity::all()
            .into_iter()
            .map(|severity| {
                let count = self
                    .findings
                    .iter()
                    .filter(|finding| finding.severity == severity)
                    .count();
                (severity, count)
            })
            .collect()
    }

    pub fn push_log(
        &mut self,
        level: LogLevel,
        source: Option<&'static str>,
        text: impl Into<String>,
    ) {
        self.logs.push_back(LogLine {
            level,
            source,
            at: chrono::Local::now().format("%H:%M:%S").to_string(),
            text: text.into(),
        });
        while self.logs.len() > LOG_LIMIT {
            self.logs.pop_front();
        }
    }

    /// Fold one engine event into the view state.
    pub fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started {
                target,
                profile,
                session_dir,
                stages,
            } => {
                self.target = target;
                self.profile = profile;
                self.session_dir = session_dir;
                self.stages = stages
                    .into_iter()
                    .map(|stage| StageRow {
                        stage,
                        status: StageStatus::Pending,
                    })
                    .collect();
                self.push_log(
                    LogLevel::Info,
                    None,
                    format!("scan started ({})", self.profile),
                );
            }
            ScanEvent::StageStarted {
                stage,
                index,
                total,
            } => {
                if let Some(row) = self.stages.get_mut(index) {
                    row.status = StageStatus::Running;
                }
                self.current = Some(index);
                self.progress = None;
                self.push_log(
                    LogLevel::Info,
                    None,
                    format!("[{}/{total}] {}", index + 1, stage.label()),
                );
            }
            ScanEvent::StageProgress {
                done, total, label, ..
            } => {
                self.progress = Some((done, total, label));
            }
            ScanEvent::StageSkipped { stage, reason } => {
                if let Some(row) = self.stages.iter_mut().find(|row| row.stage == stage) {
                    row.status = StageStatus::Skipped(reason.clone());
                }
                self.push_log(
                    LogLevel::Info,
                    None,
                    format!("{} skipped: {reason}", stage.label()),
                );
            }
            ScanEvent::StageFinished {
                stage, elapsed, ok, ..
            } => {
                if let Some(row) = self.stages.iter_mut().find(|row| row.stage == stage) {
                    row.status = if ok {
                        StageStatus::Done(elapsed)
                    } else {
                        StageStatus::Failed(elapsed)
                    };
                }
                self.progress = None;
            }
            ScanEvent::HostFound(host) => {
                self.hosts_seen += 1;
                if self.hosts.len() < HOST_LIMIT {
                    self.hosts.push(host);
                }
            }
            ScanEvent::UrlFound(_) => self.urls_seen += 1,
            ScanEvent::ParamFound(_) => self.params_seen += 1,
            ScanEvent::Finding(finding) => {
                let finding = *finding;
                self.push_log(
                    LogLevel::Info,
                    None,
                    format!("[{}] {}", finding.severity.label(), finding.title),
                );
                if self.findings.len() < FINDING_LIMIT
                    && !self
                        .findings
                        .iter()
                        .any(|existing| existing.id == finding.id)
                {
                    self.findings.push(finding);
                }
            }
            ScanEvent::Log { level, tool, text } => self.push_log(level, tool, text),
            ScanEvent::Finished(summary) => {
                self.finished = true;
                self.progress = None;
                self.push_log(
                    LogLevel::Info,
                    None,
                    format!("scan finished: {}", summary.headline()),
                );
                self.summary = Some(*summary);
            }
            ScanEvent::Failed(message) => {
                self.finished = true;
                self.push_log(LogLevel::Error, None, message.clone());
                self.failed = Some(message);
            }
        }
    }
}
