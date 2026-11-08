//! Widgets. Read-only: everything here is derived from [`App`].

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table, Tabs, Wrap};

use crate::models::Severity;

use super::app::{App, StageStatus, Tab};

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(2),
    ])
    .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_tabs(frame, app, chunks[1]);

    match app.tab {
        Tab::Overview => draw_overview(frame, app, chunks[2]),
        Tab::Findings => draw_findings(frame, app, chunks[2]),
        Tab::Hosts => draw_hosts(frame, app, chunks[2]),
        Tab::Log => draw_log(frame, app, chunks[2]),
    }

    draw_footer(frame, app, chunks[3]);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let state = if let Some(message) = &app.failed {
        Span::styled(
            format!(" failed: {message} "),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else if app.quit_requested {
        Span::styled(" cancelling ", Style::default().fg(Color::Yellow))
    } else if app.finished {
        Span::styled(" finished ", Style::default().fg(Color::Green))
    } else {
        Span::styled(" scanning ", Style::default().fg(Color::Yellow))
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", app.target),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} · ", app.profile),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            format!("{} ", super::format_duration(app.elapsed())),
            Style::default().fg(Color::Gray),
        ),
        state,
    ]);

    let block = Block::bordered().title(format!(" {} {} ", crate::APP_NAME, crate::APP_VERSION));
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|tab| {
            let count = match tab {
                Tab::Overview => None,
                Tab::Findings => Some(app.findings.len()),
                Tab::Hosts => Some(app.hosts.len()),
                Tab::Log => Some(app.logs.len()),
            };
            match count {
                Some(count) if count > 0 => Line::from(format!("{} ({count})", tab.title())),
                _ => Line::from(tab.title()),
            }
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");
    frame.render_widget(tabs, area);
}

fn draw_overview(frame: &mut Frame, app: &App, area: Rect) {
    let columns =
        Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)]).split(area);

    let rows: Vec<Row> = app
        .stages
        .iter()
        .map(|row| {
            let style = match row.status {
                StageStatus::Pending => Style::default().fg(Color::DarkGray),
                StageStatus::Running => Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                StageStatus::Done(_) => Style::default().fg(Color::Green),
                StageStatus::Skipped(_) => Style::default().fg(Color::DarkGray),
                StageStatus::Failed(_) => Style::default().fg(Color::Red),
            };
            Row::new(vec![
                Cell::from(row.status.symbol()),
                Cell::from(row.stage.label()),
                Cell::from(row.status.detail()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Min(16),
            Constraint::Length(18),
        ],
    )
    .header(
        Row::new(vec!["", "Stage", "Status"]).style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .column_spacing(1)
    .block(Block::bordered().title(" pipeline "));
    frame.render_widget(table, columns[0]);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Hosts       ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{}", app.hosts_seen)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("URLs        ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{}", app.urls_seen)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Parameters  ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{}", app.params_seen)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Findings    ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{}", app.findings.len())),
    ]));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled(
        "Severity",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    for (severity, count) in app.severity_counts() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<9}", severity.label()),
                severity_style(severity),
            ),
            Span::raw(format!(" {count}")),
        ]));
    }

    if let Some(summary) = &app.summary {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Result",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!("  {}", summary.headline())));
        lines.push(Line::from(format!(
            "  {} hosts · {} urls · {} parameters",
            summary.hosts, summary.urls, summary.params
        )));
        lines.push(Line::from(format!("  session {}", summary.session_dir)));
    }

    if !app.findings.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Top signals",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for finding in app.sorted_findings().into_iter().take(6) {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<5}", finding.severity.label()),
                    severity_style(finding.severity),
                ),
                Span::raw(" "),
                Span::raw(truncate(&finding.title, 44)),
            ]));
        }
    }

    let block = Block::bordered().title(" summary ");
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false }),
        columns[1],
    );
}

fn draw_findings(frame: &mut Frame, app: &App, area: Rect) {
    let findings = app.sorted_findings();
    if findings.is_empty() {
        frame.render_widget(
            Paragraph::new("Nothing yet. Findings appear here as the probes confirm them.")
                .block(Block::bordered().title(" findings "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows: Vec<Row> = findings
        .iter()
        .skip(app.scroll as usize)
        .map(|finding| {
            Row::new(vec![
                Cell::from(finding.severity.label()).style(severity_style(finding.severity)),
                Cell::from(truncate(&finding.title, 52)),
                Cell::from(truncate(&finding.endpoint, 48)),
                Cell::from(format!("{:.1}", finding.score)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Min(24),
            Constraint::Min(20),
            Constraint::Length(5),
        ],
    )
    .header(
        Row::new(vec!["Sev", "Finding", "Endpoint", "Score"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .column_spacing(1)
    .block(Block::bordered().title(" findings "));
    frame.render_widget(table, area);
}

fn draw_hosts(frame: &mut Frame, app: &App, area: Rect) {
    if app.hosts.is_empty() {
        frame.render_widget(
            Paragraph::new("No live endpoints yet.")
                .block(Block::bordered().title(" hosts "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows: Vec<Row> = app
        .hosts
        .iter()
        .skip(app.scroll as usize)
        .map(|host| {
            let style = if host.reachable() {
                Style::default()
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Row::new(vec![
                Cell::from(host.status.to_string()),
                Cell::from(truncate(&host.url, 56)),
                Cell::from(truncate(&host.title, 40)),
                Cell::from(truncate(&host.webserver, 18)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Min(30),
            Constraint::Min(20),
            Constraint::Length(18),
        ],
    )
    .header(
        Row::new(vec!["Code", "URL", "Title", "Server"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .column_spacing(1)
    .block(Block::bordered().title(" hosts "));
    frame.render_widget(table, area);
}

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = app
        .logs
        .iter()
        .map(|entry| {
            let color = match entry.level {
                crate::events::LogLevel::Debug => Color::DarkGray,
                crate::events::LogLevel::Info => Color::Gray,
                crate::events::LogLevel::Warn => Color::Yellow,
                crate::events::LogLevel::Error => Color::Red,
            };
            Line::from(vec![
                Span::styled(
                    format!("{} ", entry.at),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:<5} ", entry.level.as_str()),
                    Style::default().fg(color),
                ),
                match entry.source {
                    Some(tool) => {
                        Span::styled(format!("{tool}: "), Style::default().fg(Color::Magenta))
                    }
                    None => Span::raw(""),
                },
                Span::raw(truncate(&entry.text, 160)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::bordered().title(" log "))
        .scroll((app.scroll, 0));
    frame.render_widget(paragraph, area);
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);

    let hint = Line::from(Span::styled(
        " tab/←/→ switch · ↑/↓ scroll · g/G top/bottom · q quit ",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(Paragraph::new(hint), rows[0]);

    match (&app.progress, app.finished) {
        (Some((done, Some(total), _)), false) if *total > 0 => {
            let ratio = (*done as f64 / *total as f64).clamp(0.0, 1.0);
            let gauge = Gauge::default()
                .ratio(ratio)
                .label(format!("{done}/{total}"))
                .gauge_style(Style::default().fg(Color::Cyan))
                .use_unicode(true);
            frame.render_widget(gauge, rows[1]);
        }
        (Some((_, _, label)), false) => {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!(" {label}"),
                    Style::default().fg(Color::Gray),
                ))),
                rows[1],
            );
        }
        _ => {
            let text = match (&app.summary, &app.failed) {
                (_, Some(message)) => {
                    Span::styled(format!(" {message}"), Style::default().fg(Color::Red))
                }
                (Some(summary), None) => Span::styled(
                    format!(" {} — press q to exit", summary.headline()),
                    Style::default().fg(Color::Green),
                ),
                (None, None) => Span::styled(
                    " working…".to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
            };
            frame.render_widget(Paragraph::new(Line::from(text)), rows[1]);
        }
    }
}

fn severity_style(severity: Severity) -> Style {
    let color = match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::Gray,
    };
    Style::default().fg(color)
}

fn truncate(value: &str, max: usize) -> String {
    crate::util::text::truncate(value, max)
}
