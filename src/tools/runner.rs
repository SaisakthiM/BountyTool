//! Subprocess execution for external scanners.
//!
//! Everything goes through [`ToolRunner`]: PATH resolution, wall-clock
//! timeouts, `kill_on_drop`, stderr capture, raw log persistence and
//! `--dry-run` echoing. Stages never spawn processes directly.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::error::{Error, Result};
use crate::events::Events;
use crate::tools::registry;

#[derive(Debug, Clone, Default)]
pub struct ToolOutput {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub status: Option<i32>,
    pub timed_out: bool,
    /// True when `--dry-run` prevented execution.
    pub skipped: bool,
}

impl ToolOutput {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.status.unwrap_or(0) == 0
    }

    pub fn first_error_line(&self) -> Option<String> {
        self.stderr
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| crate::util::text::truncate(line, 240))
    }
}

pub struct ToolRunner {
    dry_run: bool,
    timeout: Duration,
    raw_dir: PathBuf,
    events: Events,
}

impl ToolRunner {
    pub fn new(raw_dir: PathBuf, timeout: Duration, dry_run: bool, events: Events) -> ToolRunner {
        ToolRunner {
            dry_run,
            timeout,
            raw_dir,
            events,
        }
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    pub fn raw_dir(&self) -> &PathBuf {
        &self.raw_dir
    }

    /// Shell-rendered command line, used for `--dry-run`, logs and the report.
    pub fn command_line(tool: &str, args: &[String]) -> String {
        let mut parts = vec![tool.to_string()];
        parts.extend(args.iter().cloned());
        shell_words::join(parts)
    }

    /// Run a tool and discard stdout (after handing each line to `on_line`).
    pub async fn stream<F>(
        &self,
        tool: &'static str,
        args: &[String],
        mut on_line: F,
    ) -> Result<ToolOutput>
    where
        F: FnMut(&str),
    {
        let command_line = Self::command_line(tool, args);
        let mut output = ToolOutput {
            command: command_line.clone(),
            ..Default::default()
        };

        if self.dry_run {
            self.events.info(format!("dry-run: {command_line}"));
            output.skipped = true;
            return Ok(output);
        }

        let binary = registry::which(tool).ok_or_else(|| match registry::spec(tool) {
            Some(spec) => Error::MissingTool {
                tool: spec.name,
                package: spec.package,
            },
            None => Error::Other(format!("unknown tool `{tool}`")),
        })?;

        self.events.info(format!("$ {command_line}"));

        let mut command = Command::new(&binary);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|error| Error::io(binary.clone(), error))?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stderr_task = stderr.map(|stderr| {
            let events = self.events.clone();
            tokio::spawn(async move {
                let mut collected = String::new();
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if collected.len() < 128 * 1024 {
                        collected.push_str(&line);
                        collected.push('\n');
                    }
                    events.tool_log(tool, crate::util::text::truncate(&line, 300));
                }
                collected
            })
        });

        let reading = async {
            if let Some(stdout) = stdout {
                let mut lines = BufReader::new(stdout).lines();
                while let Some(line) = lines.next_line().await? {
                    if output.stdout.len() < 16 * 1024 * 1024 {
                        output.stdout.push_str(&line);
                        output.stdout.push('\n');
                    }
                    on_line(&line);
                }
            }
            Ok::<(), std::io::Error>(())
        };

        match tokio::time::timeout(self.timeout, reading).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = child.kill().await;
                return Err(Error::io(binary, error));
            }
            Err(_) => {
                output.timed_out = true;
                let _ = child.kill().await;
                self.events.warn(format!(
                    "{tool} hit the {:?} timeout and was terminated",
                    self.timeout
                ));
            }
        }

        output.status = child.wait().await.ok().and_then(|status| status.code());
        if let Some(task) = stderr_task {
            output.stderr = task.await.unwrap_or_default();
        }

        self.persist(tool, &output);
        Ok(output)
    }

    /// Run a tool and return its captured output.
    pub async fn capture(&self, tool: &'static str, args: &[String]) -> Result<ToolOutput> {
        self.stream(tool, args, |_| {}).await
    }

    fn persist(&self, tool: &'static str, output: &ToolOutput) {
        let path = self.raw_dir.join(format!("{tool}.log"));
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut block = String::new();
        block.push_str(&format!("### {}\n", output.command));
        block.push_str(&format!(
            "### exit={:?} timed_out={} bytes={}\n",
            output.status,
            output.timed_out,
            output.stdout.len()
        ));
        if !output.stderr.trim().is_empty() {
            block.push_str("### stderr\n");
            block.push_str(&crate::util::text::truncate(&output.stderr, 4_000));
            block.push('\n');
        }
        block.push_str("### stdout\n");
        block.push_str(&crate::util::text::truncate(&output.stdout, 8_000));
        block.push_str("\n\n");

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            use std::io::Write;
            let _ = file.write_all(block.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_shell_rendered() {
        let args = vec!["-l".to_string(), "/tmp/with space.txt".to_string()];
        assert_eq!(
            ToolRunner::command_line("nuclei", &args),
            "nuclei -l '/tmp/with space.txt'"
        );
    }

    #[tokio::test]
    async fn dry_run_does_not_spawn() {
        let runner = ToolRunner::new(
            std::env::temp_dir(),
            Duration::from_secs(5),
            true,
            Events::silent(),
        );
        let output = runner
            .capture("definitely-not-a-binary-xyz", &[])
            .await
            .unwrap();
        assert!(output.skipped);
        assert!(output.stdout.is_empty());
    }

    #[tokio::test]
    async fn missing_tool_is_reported_with_its_package() {
        let runner = ToolRunner::new(
            std::env::temp_dir(),
            Duration::from_secs(5),
            false,
            Events::silent(),
        );
        // `interactsh-client` is frequently absent in CI images; if present,
        // the call simply succeeds and the assertion below is skipped.
        if registry::which("interactsh-client").is_none() {
            let error = runner.capture("interactsh-client", &[]).await.unwrap_err();
            assert!(matches!(error, Error::MissingTool { .. }));
            assert_eq!(error.exit_code(), 2);
        }
    }
}
