//! The ratatui frontend.
//!
//! Same engine as the CLI: this module owns the terminal and the event loop,
//! [`crate::pipeline::run`] does the work. `q` cancels the scan cooperatively
//! through a [`CancellationToken`] so no child process is left behind.

pub mod app;
pub mod ui;

use std::io::Stdout;
use std::time::Duration;

use crossterm::cursor;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::events::{Events, LogLevel};
use crate::pipeline::{self, RunOptions, RunResult};

use app::App;

/// `93s` -> `1m 33s`, `3700s` -> `1h 01m`.
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 3600 {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// Restores the terminal even when the event loop returns early.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, cursor::Show);
    }
}

type Tui = Terminal<CrosstermBackend<Stdout>>;

fn enter() -> Result<Tui> {
    enable_raw_mode().map_err(|error| Error::Other(format!("raw mode: {error}")))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)
        .map_err(|error| Error::Other(format!("alternate screen: {error}")))?;
    Terminal::new(CrosstermBackend::new(stdout))
        .map_err(|error| Error::Other(format!("terminal: {error}")))
}

fn leave(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, cursor::Show).ok();
    terminal
        .show_cursor()
        .map_err(|error| Error::Other(format!("terminal: {error}")))
}

/// Run a scan with the TUI attached and return its result.
pub async fn run(options: RunOptions) -> Result<RunResult> {
    let (events, mut receiver) = Events::channel();
    let cancel = CancellationToken::new();

    let stages = options.stages.clone();
    let mut app = App::new(
        options.target.clone(),
        options.profile.as_str().to_string(),
        stages,
    );

    let mut terminal = enter()?;
    let _guard = TerminalGuard;

    let scan_cancel = cancel.clone();
    let mut scan = tokio::spawn(async move { pipeline::run(options, events, scan_cancel).await });

    let mut input = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut outcome: Option<Result<RunResult>> = None;

    loop {
        tokio::select! {
            biased;

            event = receiver.recv() => {
                if let Some(event) = event {
                    app.apply(event);
                }
            }
            incoming = input.next() => {
                if let Some(Ok(Event::Key(key))) = incoming {
                    if key.kind == KeyEventKind::Press {
                        handle_key(&mut app, key, &cancel);
                    }
                }
            }
            _ = ticker.tick() => {}
            result = &mut scan, if outcome.is_none() => {
                outcome = Some(match result {
                    Ok(inner) => inner,
                    Err(error) => Err(Error::Other(format!("scan task failed: {error}"))),
                });
                // The task is done, so the channel is closed: drain what is left
                // before the final frame.
                while let Ok(event) = receiver.try_recv() {
                    app.apply(event);
                }
                app.finished = true;
                if let Some(Err(error)) = &outcome {
                    app.failed = Some(error.to_string());
                    app.push_log(LogLevel::Error, None, error.to_string());
                }
            }
        }

        terminal
            .draw(|frame| ui::draw(frame, &app))
            .map_err(|error| Error::Other(format!("render: {error}")))?;

        if app.quit_requested && outcome.is_some() {
            break;
        }
    }

    leave(&mut terminal)?;
    outcome.unwrap_or(Err(Error::Cancelled))
}

fn handle_key(app: &mut App, key: KeyEvent, cancel: &CancellationToken) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.quit_requested = true;
            if !app.finished {
                cancel.cancel();
                app.push_log(LogLevel::Warn, None, "cancelling scan…");
            }
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.quit_requested = true;
            cancel.cancel();
        }
        KeyCode::Tab | KeyCode::Right => app.next_tab(),
        KeyCode::BackTab | KeyCode::Left => app.previous_tab(),
        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(1),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(1),
        KeyCode::PageUp => app.scroll_up(10),
        KeyCode::PageDown => app.scroll_down(10),
        KeyCode::Home | KeyCode::Char('g') => app.scroll_top(),
        KeyCode::End | KeyCode::Char('G') => app.scroll_bottom(),
        _ => {}
    }
}
