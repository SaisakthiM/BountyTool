//! Scope and authorization gate.
//!
//! Every network-touching stage funnels through [`Scope::allows`]. The gate is
//! deliberate: without an explicit scope file and `--i-have-authorization`
//! the engine refuses to send a single active request.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// TLDs that are never touched unless the operator lists them explicitly.
const DENY_TLDS: &[&str] = &["gov", "mil"];

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Scope {
    /// In-scope roots. `example.com` also implies `*.example.com`.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Explicit out-of-scope entries, checked before `targets`.
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub program: Option<String>,
    /// Lab/test escape hatch for loopback and RFC1918 targets.
    #[serde(default)]
    pub allow_private_ips: bool,
    /// Optional per-scope rate cap, overrides the global config value.
    #[serde(default)]
    pub max_rps: Option<u32>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl Scope {
    pub fn load(path: &Path) -> Result<Scope> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let scope: Scope =
            toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        scope.validate()?;
        Ok(scope)
    }

    /// Build a scope from inline `--in-scope` values plus the positional target.
    pub fn from_inline(target: Option<&str>, in_scope: &[String]) -> Result<Scope> {
        let mut targets: Vec<String> = in_scope
            .iter()
            .map(|entry| normalize(entry))
            .filter(|entry| !entry.is_empty())
            .collect();
        if let Some(target) = target {
            let normalized = normalize(target);
            if !normalized.is_empty() && !targets.contains(&normalized) {
                targets.insert(0, normalized);
            }
        }
        let scope = Scope {
            targets,
            ..Default::default()
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(Error::Config(
                "scope has no targets; provide --scope <file> or --in-scope <domain>".to_string(),
            ));
        }
        for target in &self.targets {
            if target.is_empty() {
                return Err(Error::Config("scope contains an empty target".to_string()));
            }
            if target.contains("://") {
                return Err(Error::Config(format!(
                    "scope target `{target}` must not contain a scheme"
                )));
            }
            if target.contains('/') {
                return Err(Error::Config(format!(
                    "scope target `{target}` must be a host or domain, not a URL"
                )));
            }
        }
        Ok(())
    }

    /// The registrable domains the passive stages should enumerate.
    pub fn root_domains(&self) -> Vec<String> {
        let mut roots: Vec<String> = self
            .targets
            .iter()
            .map(|target| normalize(target))
            .filter(|target| !target.is_empty())
            .filter(|target| IpAddr::from_str(strip_port(target)).is_err())
            .filter_map(|target| match target.strip_prefix("*.") {
                // `*.example.com` names a domain to enumerate; whether the apex
                // itself may be contacted is still decided by `allows`.
                Some(suffix) => Some(suffix.to_string()),
                None if target.contains('*') => None,
                None => Some(target),
            })
            .collect();
        roots.sort();
        roots.dedup();
        roots
    }

    pub fn ips(&self) -> Vec<String> {
        self.targets
            .iter()
            .map(|target| strip_port(&normalize(target)).to_string())
            .filter(|host| IpAddr::from_str(host).is_ok())
            .collect()
    }

    /// True when `host` may be contacted.
    pub fn allows(&self, host: &str) -> bool {
        self.deny_reason(host).is_none()
    }

    /// `None` means allowed, `Some(reason)` means refused.
    pub fn deny_reason(&self, host: &str) -> Option<String> {
        let host = normalize(host);
        if host.is_empty() {
            return Some("empty host".to_string());
        }
        let bare = strip_port(&host).to_string();

        if self
            .exclude
            .iter()
            .any(|entry| entry_matches(entry, &host, &bare))
        {
            return Some(format!("{host} matches an out-of-scope exclusion"));
        }

        let allowed = self
            .targets
            .iter()
            .any(|entry| entry_matches(entry, &host, &bare));
        if !allowed {
            return Some(format!("{host} is not in the declared scope"));
        }

        let is_private = match IpAddr::from_str(&bare) {
            Ok(ip) => is_private_ip(ip),
            Err(_) => bare == "localhost" || bare.ends_with(".localhost"),
        };
        if is_private && !self.allow_private_ips {
            return Some(format!(
                "{host} resolves to a private/loopback address (set allow_private_ips = true in the scope file for labs)"
            ));
        }

        let explicitly_listed = self.targets.iter().any(|entry| {
            let entry = normalize(entry);
            entry == bare || entry == host
        });
        if !explicitly_listed {
            if let Some(tld) = bare.rsplit('.').next() {
                if DENY_TLDS.contains(&tld.to_ascii_lowercase().as_str()) {
                    return Some(format!(
                        "{host} is under a restricted TLD (.{tld}); list it explicitly to override"
                    ));
                }
            }
        }

        None
    }

    /// Hard authorization gate for active stages.
    pub fn check_authorization(&self, authorized_flag: bool) -> Result<()> {
        if !authorized_flag {
            return Err(Error::Authorization(
                "active scanning requires -y/--i-have-authorization confirming you are permitted to test this target"
                    .to_string(),
            ));
        }
        if self.targets.is_empty() {
            return Err(Error::Authorization(
                "an explicit scope is required before any active scanning".to_string(),
            ));
        }
        Ok(())
    }

    /// Human-readable scope block echoed into the report.
    pub fn describe(&self) -> String {
        let mut lines = vec![format!("Targets: {}", self.targets.join(", "))];
        if !self.exclude.is_empty() {
            lines.push(format!("Excluded: {}", self.exclude.join(", ")));
        }
        if let Some(platform) = &self.platform {
            lines.push(format!("Platform: {platform}"));
        }
        if let Some(program) = &self.program {
            lines.push(format!("Program: {program}"));
        }
        lines.join("\n")
    }

    pub fn scope_path() -> Option<PathBuf> {
        std::env::current_dir()
            .ok()
            .map(|dir| dir.join("scope.toml"))
    }
}

fn entry_matches(entry: &str, host: &str, bare: &str) -> bool {
    let entry = normalize(entry);
    if entry.is_empty() {
        return false;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        // `*.lab.test` is the wildcard, not the apex: a listed root already
        // covers its own subdomains without one.
        return bare.ends_with(&format!(".{suffix}"));
    }
    if entry.contains('*') {
        return wildcard_match(&entry, bare);
    }
    entry == host || entry == bare || bare.ends_with(&format!(".{entry}"))
}

/// Minimal `*` glob matcher for scope entries like `api-*.example.com`.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    if !value.starts_with(parts[0]) {
        return false;
    }
    let mut cursor = parts[0].len();
    for part in &parts[1..parts.len() - 1] {
        match value[cursor..].find(part) {
            Some(idx) => cursor += idx + part.len(),
            None => return false,
        }
    }
    let tail = parts[parts.len() - 1];
    tail.is_empty() || value[cursor..].ends_with(tail)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Lowercase, strip scheme/userinfo/path/port-less normalisation for matching.
pub fn normalize(host: &str) -> String {
    let mut value = host.trim().to_ascii_lowercase();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    }
    if let Some((_, rest)) = value.split_once('@') {
        value = rest.to_string();
    }
    value = value
        .split('/')
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_string();
    value
}

pub fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((head, tail)) if tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            targets: vec![
                "example.com".into(),
                "*.lab.test".into(),
                "api-*.corp.test".into(),
            ],
            exclude: vec!["admin.example.com".into()],
            allow_private_ips: false,
            ..Default::default()
        }
    }

    #[test]
    fn apex_and_subdomains_are_in_scope() {
        let scope = scope();
        assert!(scope.allows("example.com"));
        assert!(scope.allows("app.example.com"));
        assert!(scope.allows("deep.app.example.com:8443"));
        assert!(scope.allows("https://example.com/path?q=1"));
    }

    #[test]
    fn exclusions_win() {
        let scope = scope();
        assert!(!scope.allows("admin.example.com"));
        assert!(scope.deny_reason("admin.example.com").is_some());
    }

    #[test]
    fn wildcards_match() {
        let scope = scope();
        assert!(scope.allows("a.lab.test"));
        assert!(!scope.allows("lab.test"));
        assert!(scope.allows("api-1.corp.test"));
        assert!(!scope.allows("web-1.corp.test"));
    }

    #[test]
    fn outside_scope_is_refused() {
        assert!(!scope().allows("evil.com"));
        assert!(!scope().allows("example.com.evil.com"));
    }

    #[test]
    fn private_ips_need_opt_in() {
        let mut scope = scope();
        scope.targets.push("127.0.0.1".into());
        assert!(!scope.allows("127.0.0.1:8080"));
        scope.allow_private_ips = true;
        assert!(scope.allows("127.0.0.1:8080"));
    }

    #[test]
    fn restricted_tlds_require_explicit_listing() {
        let mut scope = scope();
        scope.targets.push("*.gov".into());
        assert!(!scope.allows("agency.gov"));
        scope.targets.push("agency.gov".into());
        assert!(scope.allows("agency.gov"));
    }

    #[test]
    fn authorization_flag_is_mandatory() {
        let scope = scope();
        assert!(scope.check_authorization(false).is_err());
        assert!(scope.check_authorization(true).is_ok());
    }

    #[test]
    fn root_domains_skip_ips_and_wildcards() {
        let mut scope = scope();
        scope.targets.push("127.0.0.1".into());
        let roots = scope.root_domains();
        assert!(roots.contains(&"example.com".to_string()));
        assert!(!roots.iter().any(|root| root.contains('*')));
        assert!(!roots.contains(&"127.0.0.1".to_string()));
    }
}
