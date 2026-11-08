//! Out-of-band (OAST) support for blind SSRF, built on `interactsh-client`.
//!
//! Best effort by design: if the tool is missing, fails to start or prints no
//! domain, the active stage simply continues without out-of-band coverage and
//! the report records the degradation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use regex::Regex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::events::Events;
use crate::models::ParamCandidate;
use crate::tools::which;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OastHit {
    pub label: String,
    pub protocol: String,
    pub remote_address: String,
    pub full_id: String,
}

pub struct Oast {
    child: tokio::process::Child,
    domain: String,
    output: PathBuf,
    events: Events,
    registrations: Mutex<HashMap<String, ParamCandidate>>,
}

impl Oast {
    /// Start `interactsh-client` and wait (bounded) for its callback domain.
    pub async fn start(dir: &Path, events: &Events) -> Option<Oast> {
        let binary = which("interactsh-client")?;
        let output = dir.join("oast.jsonl");
        let _ = std::fs::remove_file(&output);

        let mut child = Command::new(binary)
            .arg("-json")
            .arg("-o")
            .arg(&output)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .ok()?;

        let stdout = child.stdout.take()?;
        let mut lines = BufReader::new(stdout).lines();
        let events_clone = events.clone();

        let domain = tokio::time::timeout(Duration::from_secs(20), async {
            while let Ok(Some(line)) = lines.next_line().await {
                events_clone.tool_log("interactsh-client", line.clone());
                if let Some(domain) = extract_domain(&line) {
                    return Some(domain);
                }
            }
            None
        })
        .await
        .ok()
        .flatten();

        match domain {
            Some(domain) => {
                events.info(format!("OOB callbacks enabled via {domain}"));
                Some(Oast {
                    child,
                    domain,
                    output,
                    events: events.clone(),
                    registrations: Mutex::new(HashMap::new()),
                })
            }
            None => {
                events.warn("interactsh-client started but no callback domain was published");
                let _ = child.kill().await;
                None
            }
        }
    }

    /// Payload URL that will fire a callback tagged with `label`.
    pub fn url(&self, label: &str) -> String {
        format!("http://{label}.{}", self.domain)
    }

    /// Remember which candidate a label belongs to so callbacks can be mapped
    /// back to a concrete parameter.
    pub fn register(&self, label: &str, candidate: &ParamCandidate) {
        if let Ok(mut registrations) = self.registrations.lock() {
            registrations.insert(label.to_string(), candidate.clone());
        }
    }

    pub fn candidate_for(&self, label: &str) -> Option<ParamCandidate> {
        self.registrations
            .lock()
            .ok()
            .and_then(|registrations| registrations.get(label).cloned())
    }

    /// Every registration, taken before [`Oast::collect`] consumes the client.
    pub fn registrations(&self) -> Vec<(String, ParamCandidate)> {
        self.registrations
            .lock()
            .map(|registrations| {
                registrations
                    .iter()
                    .map(|(label, candidate)| (label.clone(), candidate.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Stop the client and return every interaction recorded on disk.
    pub async fn collect(mut self) -> Vec<OastHit> {
        let _ = self.child.kill().await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let Ok(text) = std::fs::read_to_string(&self.output) else {
            return Vec::new();
        };

        let mut hits = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with('{') {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let full_id = value
                .get("full-id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            if full_id.is_empty() {
                continue;
            }
            let label = title_label(&full_id);
            hits.push(OastHit {
                protocol: value
                    .get("protocol")
                    .and_then(|value| value.as_str())
                    .unwrap_or("dns")
                    .to_string(),
                remote_address: value
                    .get("remote-address")
                    .and_then(|value| value.as_str())
                    .unwrap_or("-")
                    .to_string(),
                label,
                full_id,
            });
        }
        if !hits.is_empty() {
            self.events
                .info(format!("{} out-of-band callback(s) observed", hits.len()));
        }
        hits
    }
}

/// First dot-separated label of a callback id (`s1.abc123.oast.fun` -> `s1`).
fn title_label(full_id: &str) -> String {
    full_id.split('.').next().unwrap_or_default().to_string()
}

fn extract_domain(line: &str) -> Option<String> {
    // interactsh prints the correlation domain either in a banner line or as a
    // bare token; accept anything that looks like `<20 alnum>.<zone>.<tld>`.
    let regex = Regex::new(r"([a-z0-9]{15,32}\.[a-z0-9-]+(?:\.[a-z0-9-]+)+)").ok()?;
    regex
        .captures(&line.to_ascii_lowercase())
        .and_then(|captures| captures.get(1))
        .map(|matched| matched.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_extracted_from_noisy_lines() {
        let line = "[INF] abcdefghij0123456789.oast.fun";
        assert_eq!(
            extract_domain(line).as_deref(),
            Some("abcdefghij0123456789.oast.fun")
        );
        assert!(extract_domain("[INF] Listing 1 payload").is_none());
    }

    #[test]
    fn labels_are_the_first_segment() {
        assert_eq!(title_label("s1.abc.oast.fun"), "s1");
    }
}
