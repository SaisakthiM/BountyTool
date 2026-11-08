//! Session persistence: every scan lives in its own directory with a manifest,
//! raw tool logs, stage artifacts and findings. Stage records double as the
//! resume cache.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::models::{Profile, Stage, ToolVersion};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageRecord {
    pub finished_at: String,
    pub elapsed_secs: f64,
    pub artifacts: Vec<String>,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub target: String,
    pub profile: Profile,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub stages: BTreeMap<String, StageRecord>,
    #[serde(default)]
    pub tools: Vec<ToolVersion>,
    #[serde(default)]
    pub degraded: Vec<String>,
    #[serde(default)]
    pub scope: Option<crate::scope::Scope>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub dir: PathBuf,
    pub target: String,
    pub profile: Profile,
    pub manifest: Manifest,
}

impl Session {
    /// Create a fresh session directory under the configured sessions root.
    pub fn create(target: &str, profile: Profile, config: &Config) -> Result<Session> {
        let root = config.sessions_root();
        std::fs::create_dir_all(&root).map_err(|e| Error::io(&root, e))?;

        let now = chrono::Utc::now();
        let slug = slugify(target);
        let id = format!("{}-{}", now.format("%Y%m%d-%H%M%S"), slug);
        let dir = root.join(&id);
        std::fs::create_dir_all(dir.join("artifacts")).map_err(|e| Error::io(&dir, e))?;
        std::fs::create_dir_all(dir.join("raw")).map_err(|e| Error::io(&dir, e))?;

        let manifest = Manifest {
            id: id.clone(),
            target: target.to_string(),
            profile,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
            status: "running".to_string(),
            stages: BTreeMap::new(),
            tools: Vec::new(),
            degraded: Vec::new(),
            scope: None,
        };

        let session = Session {
            id,
            dir,
            target: target.to_string(),
            profile,
            manifest,
        };
        session.save()?;
        Ok(session)
    }

    pub fn open(dir: &Path) -> Result<Session> {
        let manifest_path = dir.join("session.json");
        if !manifest_path.exists() {
            return Err(Error::NoSession(dir.to_path_buf()));
        }
        let text =
            std::fs::read_to_string(&manifest_path).map_err(|e| Error::io(&manifest_path, e))?;
        let manifest: Manifest = serde_json::from_str(&text)?;
        Ok(Session {
            id: manifest.id.clone(),
            dir: dir.to_path_buf(),
            target: manifest.target.clone(),
            profile: manifest.profile,
            manifest,
        })
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(self.dir.join("artifacts")).map_err(|e| Error::io(&self.dir, e))?;
        std::fs::create_dir_all(self.dir.join("raw")).map_err(|e| Error::io(&self.dir, e))?;
        let path = self.dir.join("session.json");
        let text = serde_json::to_string_pretty(&self.manifest)?;
        std::fs::write(&path, text).map_err(|e| Error::io(&path, e))
    }

    pub fn artifacts_dir(&self) -> PathBuf {
        self.dir.join("artifacts")
    }

    pub fn raw_dir(&self) -> PathBuf {
        self.dir.join("raw")
    }

    pub fn artifact(&self, name: &str) -> PathBuf {
        self.artifacts_dir().join(name)
    }

    pub fn stage_done(&self, stage: Stage) -> bool {
        self.manifest
            .stages
            .get(stage.key())
            .map(|record| record.ok)
            .unwrap_or(false)
    }

    pub fn record_stage(
        &mut self,
        stage: Stage,
        elapsed: Duration,
        artifacts: &[PathBuf],
        ok: bool,
    ) {
        self.manifest.stages.insert(
            stage.key().to_string(),
            StageRecord {
                finished_at: chrono::Utc::now().to_rfc3339(),
                elapsed_secs: elapsed.as_secs_f64(),
                artifacts: artifacts
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                ok,
            },
        );
        self.manifest.updated_at = chrono::Utc::now().to_rfc3339();
        let _ = self.save();
    }

    pub fn set_status(&mut self, status: &str) {
        self.manifest.status = status.to_string();
        self.manifest.updated_at = chrono::Utc::now().to_rfc3339();
        let _ = self.save();
    }

    pub fn set_scope(&mut self, scope: &crate::scope::Scope) {
        self.manifest.scope = Some(scope.clone());
        let _ = self.save();
    }

    pub fn report_path(&self, extension: &str) -> PathBuf {
        self.dir.join(format!("report.{extension}"))
    }

    /// All sessions, newest first.
    pub fn list(root: &Path) -> Result<Vec<Manifest>> {
        if !root.exists() {
            return Ok(Vec::new());
        }
        let entries = std::fs::read_dir(root).map_err(|e| Error::io(root, e))?;
        let mut manifests = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path().join("session.json");
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(manifest) = serde_json::from_str::<Manifest>(&text) {
                    manifests.push(manifest);
                }
            }
        }
        manifests.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(manifests)
    }
}

fn slugify(target: &str) -> String {
    let mut slug = String::with_capacity(target.len());
    for ch in target.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            // Collapse runs of separators so `https://` becomes one dash.
            slug.push('-');
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed
            .chars()
            .take(48)
            .collect::<String>()
            .trim_end_matches('-')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_filesystem_safe() {
        assert_eq!(
            slugify("https://App.Example.com/x"),
            "https-app-example-com-x"
        );
        assert_eq!(slugify("***"), "target");
    }

    #[test]
    fn session_roundtrip_records_stage() {
        let temp = std::env::temp_dir().join(format!("bountytool-session-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        let config = Config {
            output_dir: temp.display().to_string(),
            ..Config::default()
        };

        let mut session = Session::create("example.com", Profile::Light, &config).unwrap();
        assert!(!session.stage_done(Stage::Passive));
        session.record_stage(Stage::Passive, Duration::from_millis(120), &[], true);
        assert!(session.stage_done(Stage::Passive));

        let reopened = Session::open(&session.dir).unwrap();
        assert!(reopened.stage_done(Stage::Passive));
        assert_eq!(reopened.target, "example.com");

        let _ = std::fs::remove_dir_all(&temp);
    }
}
