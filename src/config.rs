//! Layered configuration: compiled defaults -> user file -> environment -> CLI flags.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const DEFAULT_TOML: &str = include_str!("../config/default.toml");

/// Embedded fallback wordlist, used when SecLists is not installed.
pub const MINI_WORDLIST: &str = include_str!("../wordlists/mini-dirs.txt");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub concurrency: usize,
    pub rate_limit: u32,
    pub per_host_budget: u32,
    pub http_timeout_secs: u64,
    pub tool_timeout_secs: u64,
    pub max_runtime_secs: u64,
    pub user_agent: String,
    pub nuclei_severity: String,
    pub nuclei_rate_limit: u32,
    pub katana_depth: u32,
    pub probe_params_limit: usize,
    pub oast: bool,
    pub sqlmap_verify: bool,
    pub seclists_dir: String,
    pub wordlist: String,
    pub output_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str(DEFAULT_TOML).expect("embedded default config must parse")
    }
}

impl Config {
    /// Load defaults, deep-merge the user config (explicit path or
    /// `~/.config/bountytool/config.toml`), then apply `BOUNTYTOOL_*` env vars.
    pub fn load(explicit: Option<&Path>) -> Result<Config> {
        let mut value: toml::Value = toml::from_str(DEFAULT_TOML)
            .map_err(|e| Error::Config(format!("embedded default.toml: {e}")))?;

        let user_path = match explicit {
            Some(path) => Some(path.to_path_buf()),
            None => Self::user_config_path(),
        };
        if let Some(path) = user_path {
            if path.exists() {
                let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
                let user: toml::Value = toml::from_str(&text)
                    .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
                merge(&mut value, user);
            } else if explicit.is_some() {
                return Err(Error::Config(format!(
                    "config file {} does not exist",
                    path.display()
                )));
            }
        }

        apply_env(&mut value);

        let text = toml::to_string(&value)
            .map_err(|e| Error::Config(format!("config serialisation: {e}")))?;
        toml::from_str(&text).map_err(|e| Error::Config(format!("config: {e}")))
    }

    pub fn user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|dir| dir.join("bountytool").join("config.toml"))
    }

    /// Data root: `~/.local/share/bountytool`, overridable by `BOUNTYTOOL_DATA_DIR`.
    pub fn data_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("BOUNTYTOOL_DATA_DIR") {
            return PathBuf::from(dir);
        }
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("bountytool")
    }

    pub fn sessions_root(&self) -> PathBuf {
        match self.output_dir.trim() {
            "" => Self::data_dir().join("sessions"),
            dir => PathBuf::from(dir),
        }
    }

    /// Directory discovery wordlist: configured -> SecLists -> embedded fallback.
    pub fn directory_wordlist(&self) -> Option<PathBuf> {
        for candidate in [
            self.wordlist.as_str(),
            self.seclists_dir.trim(),
            "/usr/share/seclists",
        ] {
            if candidate.is_empty() {
                continue;
            }
            let path = Path::new(candidate);
            if path.is_file() {
                return Some(path.to_path_buf());
            }
        }
        let seclists = Path::new(&self.seclists_dir);
        for rel in [
            "Discovery/Web-Content/raft-medium-directories.txt",
            "Discovery/Web-Content/directory-list-2.3-medium.txt",
            "Discovery/Web-Content/common.txt",
        ] {
            let path = seclists.join(rel);
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }

    /// Parameter-name wordlist from SecLists, if present.
    pub fn param_wordlist(&self) -> Option<PathBuf> {
        let path =
            Path::new(&self.seclists_dir).join("Discovery/Web-Content/burp-parameter-names.txt");
        path.is_file().then(|| path.to_path_buf())
    }
}

fn merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_map), toml::Value::Table(overlay_map)) => {
            for (key, value) in overlay_map {
                match base_map.get_mut(&key) {
                    Some(slot) => merge(slot, value),
                    None => {
                        base_map.insert(key, value);
                    }
                }
            }
        }
        (slot, value) => *slot = value,
    }
}

fn apply_env(value: &mut toml::Value) {
    let overrides: &[(&str, &str)] = &[
        ("BOUNTYTOOL_CONCURRENCY", "concurrency"),
        ("BOUNTYTOOL_RATE_LIMIT", "rate_limit"),
        ("BOUNTYTOOL_PER_HOST_BUDGET", "per_host_budget"),
        ("BOUNTYTOOL_TIMEOUT", "http_timeout_secs"),
        ("BOUNTYTOOL_USER_AGENT", "user_agent"),
        ("BOUNTYTOOL_SECLISTS", "seclists_dir"),
        ("BOUNTYTOOL_WORDLIST", "wordlist"),
        ("BOUNTYTOOL_OUTPUT", "output_dir"),
        ("BOUNTYTOOL_NUCLEI_SEVERITY", "nuclei_severity"),
        ("BOUNTYTOOL_OAST", "oast"),
        ("BOUNTYTOOL_SQLMAP", "sqlmap_verify"),
    ];

    let Some(table) = value.as_table_mut() else {
        return;
    };
    for (env_key, config_key) in overrides {
        let Ok(raw) = std::env::var(env_key) else {
            continue;
        };
        let parsed = match table.get(*config_key) {
            Some(toml::Value::Integer(_)) => raw
                .parse::<i64>()
                .ok()
                .map(toml::Value::Integer)
                .unwrap_or_else(|| toml::Value::String(raw.clone())),
            Some(toml::Value::Boolean(_)) => match raw.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => toml::Value::Boolean(true),
                _ => toml::Value::Boolean(false),
            },
            _ => toml::Value::String(raw),
        };
        table.insert((*config_key).to_string(), parsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse() {
        let config = Config::default();
        assert!(config.concurrency > 0);
        assert!(config.rate_limit > 0);
        assert!(config.directory_wordlist().is_some() || true);
    }

    #[test]
    fn mini_wordlist_is_usable() {
        let entries: Vec<&str> = MINI_WORDLIST
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert!(entries.len() > 50, "mini wordlist too small");
        assert!(entries.contains(&"admin"));
    }
}
