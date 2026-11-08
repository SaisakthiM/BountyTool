//! The single event bus shared by the CLI renderer and the TUI.
//!
//! `pipeline::run` never prints: it emits [`ScanEvent`]s on an unbounded
//! channel. The CLI drains the channel into an `indicatif` progress renderer,
//! the TUI drains it into widget state. One engine, two frontends.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::findings::Finding;
use crate::models::{Host, ParamCandidate, ScanSummary, Stage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        target: String,
        profile: String,
        session_dir: PathBuf,
        stages: Vec<Stage>,
    },
    StageStarted {
        stage: Stage,
        index: usize,
        total: usize,
    },
    StageProgress {
        stage: Stage,
        done: u64,
        total: Option<u64>,
        label: String,
    },
    StageSkipped {
        stage: Stage,
        reason: String,
    },
    StageFinished {
        stage: Stage,
        elapsed: Duration,
        artifacts: Vec<PathBuf>,
        ok: bool,
    },
    HostFound(Host),
    UrlFound(String),
    ParamFound(ParamCandidate),
    Finding(Box<Finding>),
    Log {
        level: LogLevel,
        tool: Option<&'static str>,
        text: String,
    },
    Finished(Box<ScanSummary>),
    Failed(String),
}

/// Cheap cloneable handle used all over the engine.
#[derive(Clone)]
pub struct Events {
    tx: mpsc::UnboundedSender<ScanEvent>,
}

impl Events {
    /// A sink that discards everything, for unit tests.
    pub fn silent() -> Events {
        let (tx, rx) = mpsc::unbounded_channel();
        // Keep the receiver alive but never polled; unbounded so no blocking.
        std::mem::forget(rx);
        Events { tx }
    }

    pub fn channel() -> (Events, mpsc::UnboundedReceiver<ScanEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Events { tx }, rx)
    }

    pub fn send(&self, event: ScanEvent) {
        let _ = self.tx.send(event);
    }

    pub fn started(&self, target: &str, profile: &str, session_dir: &Path, stages: &[Stage]) {
        self.send(ScanEvent::Started {
            target: target.to_string(),
            profile: profile.to_string(),
            session_dir: session_dir.to_path_buf(),
            stages: stages.to_vec(),
        });
    }

    pub fn stage_started(&self, stage: Stage, index: usize, total: usize) {
        self.send(ScanEvent::StageStarted {
            stage,
            index,
            total,
        });
    }

    pub fn progress(&self, stage: Stage, done: u64, total: Option<u64>, label: impl Into<String>) {
        self.send(ScanEvent::StageProgress {
            stage,
            done,
            total,
            label: label.into(),
        });
    }

    pub fn stage_skipped(&self, stage: Stage, reason: impl Into<String>) {
        self.send(ScanEvent::StageSkipped {
            stage,
            reason: reason.into(),
        });
    }

    pub fn stage_finished(
        &self,
        stage: Stage,
        elapsed: Duration,
        artifacts: Vec<PathBuf>,
        ok: bool,
    ) {
        self.send(ScanEvent::StageFinished {
            stage,
            elapsed,
            artifacts,
            ok,
        });
    }

    pub fn host(&self, host: Host) {
        self.send(ScanEvent::HostFound(host));
    }

    pub fn url(&self, url: impl Into<String>) {
        self.send(ScanEvent::UrlFound(url.into()));
    }

    pub fn param(&self, param: ParamCandidate) {
        self.send(ScanEvent::ParamFound(param));
    }

    pub fn finding(&self, finding: Finding) {
        self.send(ScanEvent::Finding(Box::new(finding)));
    }

    pub fn log(&self, level: LogLevel, text: impl Into<String>) {
        self.send(ScanEvent::Log {
            level,
            tool: None,
            text: text.into(),
        });
    }

    pub fn info(&self, text: impl Into<String>) {
        self.log(LogLevel::Info, text);
    }

    pub fn warn(&self, text: impl Into<String>) {
        self.log(LogLevel::Warn, text);
    }

    pub fn error(&self, text: impl Into<String>) {
        self.log(LogLevel::Error, text);
    }

    pub fn tool_log(&self, tool: &'static str, text: impl Into<String>) {
        self.send(ScanEvent::Log {
            level: LogLevel::Debug,
            tool: Some(tool),
            text: text.into(),
        });
    }

    pub fn finished(&self, summary: ScanSummary) {
        self.send(ScanEvent::Finished(Box::new(summary)));
    }

    pub fn failed(&self, message: impl Into<String>) {
        self.send(ScanEvent::Failed(message.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events_arrive_in_order() {
        let (events, mut rx) = Events::channel();
        events.stage_started(Stage::Passive, 0, 3);
        events.info("hello");
        events.stage_finished(Stage::Passive, Duration::from_millis(5), vec![], true);

        assert!(matches!(
            rx.recv().await,
            Some(ScanEvent::StageStarted { .. })
        ));
        assert!(matches!(rx.recv().await, Some(ScanEvent::Log { .. })));
        assert!(matches!(
            rx.recv().await,
            Some(ScanEvent::StageFinished { .. })
        ));
        // The channel closes only when every sender is gone.
        drop(events);
        assert!(rx.recv().await.is_none());
    }
}
