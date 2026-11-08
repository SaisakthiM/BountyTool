//! Finding model, dedupe keys and triage scoring.

mod score;

pub use score::{PRIMARY_THRESHOLD, TriageResult, triage};

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::models::{Confidence, Severity};

/// Vulnerability families BountyTool can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    SqlInjection,
    Ssrf,
    OpenRedirect,
    CorsMisconfig,
    CrlfInjection,
    PathTraversal,
    Ssti,
    Xss,
    ReflectedInput,
    Exposure,
    Misconfiguration,
    Cve,
    SubdomainTakeover,
    SecurityHeader,
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::SqlInjection => "sql_injection",
            Category::Ssrf => "ssrf",
            Category::OpenRedirect => "open_redirect",
            Category::CorsMisconfig => "cors_misconfig",
            Category::CrlfInjection => "crlf_injection",
            Category::PathTraversal => "path_traversal",
            Category::Ssti => "ssti",
            Category::Xss => "xss",
            Category::ReflectedInput => "reflected_input",
            Category::Exposure => "exposure",
            Category::Misconfiguration => "misconfiguration",
            Category::Cve => "cve",
            Category::SubdomainTakeover => "subdomain_takeover",
            Category::SecurityHeader => "security_header",
            Category::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::SqlInjection => "SQL Injection",
            Category::Ssrf => "Server-Side Request Forgery",
            Category::OpenRedirect => "Open Redirect",
            Category::CorsMisconfig => "CORS Misconfiguration",
            Category::CrlfInjection => "CRLF / Header Injection",
            Category::PathTraversal => "Path Traversal",
            Category::Ssti => "Server-Side Template Injection",
            Category::Xss => "Cross-Site Scripting",
            Category::ReflectedInput => "Reflected Input",
            Category::Exposure => "Information Exposure",
            Category::Misconfiguration => "Security Misconfiguration",
            Category::Cve => "Known CVE",
            Category::SubdomainTakeover => "Subdomain Takeover",
            Category::SecurityHeader => "Missing Security Header",
            Category::Other => "Other",
        }
    }

    pub fn cwe(self) -> Option<u32> {
        match self {
            Category::SqlInjection => Some(89),
            Category::Ssrf => Some(918),
            Category::OpenRedirect => Some(601),
            Category::CorsMisconfig => Some(942),
            Category::CrlfInjection => Some(113),
            Category::PathTraversal => Some(22),
            Category::Ssti => Some(1336),
            Category::Xss => Some(79),
            Category::ReflectedInput => Some(79),
            Category::Exposure => Some(200),
            Category::Misconfiguration => Some(16),
            Category::SubdomainTakeover => Some(350),
            Category::SecurityHeader => Some(693),
            _ => None,
        }
    }

    pub fn impact(self) -> &'static str {
        match self {
            Category::SqlInjection => {
                "An attacker can alter database queries, which typically leads to authentication bypass, data disclosure or full database takeover."
            }
            Category::Ssrf => {
                "An attacker can make the server issue requests to internal services, cloud metadata endpoints or otherwise unreachable networks."
            }
            Category::OpenRedirect => {
                "Attackers can craft trusted-looking links that bounce users to attacker infrastructure, which is heavily used in phishing and OAuth token theft."
            }
            Category::CorsMisconfig => {
                "A malicious origin can read authenticated responses from the victim's browser, exposing account data and tokens."
            }
            Category::CrlfInjection => {
                "Injected CRLF sequences can split responses, set arbitrary headers and, in the worst case, enable response splitting or cache poisoning."
            }
            Category::PathTraversal => {
                "An attacker may read files outside the intended directory, including configuration, credentials and source code."
            }
            Category::Ssti => {
                "Template injection frequently escalates to remote code execution on the application server."
            }
            Category::Xss => {
                "Script execution in the victim's session allows session theft, action forgery and credential harvesting."
            }
            Category::ReflectedInput => {
                "Reflected input indicates an unsanitised data path; combined with a suitable context it frequently becomes cross-site scripting."
            }
            Category::Exposure => {
                "Exposed files or endpoints leak implementation details that shorten the path to a full compromise."
            }
            Category::Misconfiguration => {
                "Weak configuration removes defence-in-depth and often enables follow-up attacks."
            }
            Category::Cve => {
                "A known public vulnerability affects this component; exploits are usually available."
            }
            Category::SubdomainTakeover => {
                "An attacker can register the dangling resource and serve content from a trusted subdomain."
            }
            Category::SecurityHeader => {
                "Missing browser security controls increase the blast radius of any content injection issue."
            }
            Category::Other => "Impact depends on the affected functionality.",
        }
    }

    pub fn remediation(self) -> &'static str {
        match self {
            Category::SqlInjection => {
                "Use parameterised queries or prepared statements for every query, and reject dynamic SQL built by string concatenation. Add least-privilege database accounts."
            }
            Category::Ssrf => {
                "Allowlist outbound destinations, resolve and validate the final IP after redirects, block link-local and metadata ranges, and disable unused URL schemes."
            }
            Category::OpenRedirect => {
                "Do not redirect to user-supplied absolute URLs. Accept only relative paths or validate against a server-side allowlist of destinations."
            }
            Category::CorsMisconfig => {
                "Reflect only origins from a strict allowlist, never combine a wildcard or reflected origin with `Access-Control-Allow-Credentials: true`."
            }
            Category::CrlfInjection => {
                "Strip or encode CR/LF characters from any value written into response headers and reject them at the framework level."
            }
            Category::PathTraversal => {
                "Canonicalise the resolved path and verify it stays inside the intended base directory; avoid passing user input to filesystem APIs directly."
            }
            Category::Ssti => {
                "Do not build templates from user input. If templating user data is required, use logic-less templates and pass data as context only."
            }
            Category::Xss => {
                "Apply contextual output encoding, use a strict Content-Security-Policy, and prefer framework auto-escaping over manual string building."
            }
            Category::ReflectedInput => {
                "Encode reflected values for the surrounding context (HTML, attribute, JavaScript, URL) before rendering them."
            }
            Category::Exposure => {
                "Remove the exposed resource from production or restrict it with authentication and network controls."
            }
            Category::Misconfiguration => {
                "Harden the component according to its production checklist and remove debug or administrative interfaces from public exposure."
            }
            Category::Cve => {
                "Upgrade the affected component to a patched release and apply the vendor advisory mitigations in the meantime."
            }
            Category::SubdomainTakeover => {
                "Remove the dangling DNS record or re-claim the cloud resource it points to, then add a monitoring check for unclaimed records."
            }
            Category::SecurityHeader => {
                "Add the missing headers at the edge or application layer and roll them out in report-only mode first."
            }
            Category::Other => {
                "Review the affected functionality and apply the principle of least privilege and input validation."
            }
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Which engine produced the finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "lowercase")]
pub enum Source {
    Tool(String),
    Native(String),
}

impl Source {
    pub fn tool(name: &str) -> Source {
        Source::Tool(name.to_string())
    }

    pub fn native(name: &str) -> Source {
        Source::Native(name.to_string())
    }

    pub fn label(&self) -> String {
        match self {
            Source::Tool(name) => format!("{name} (external)"),
            Source::Native(name) => format!("{name} (native probe)"),
        }
    }

    pub fn is_native(&self) -> bool {
        matches!(self, Source::Native(_))
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// A single reported issue with enough evidence to reproduce it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host: String,
    pub endpoint: String,
    #[serde(default)]
    pub parameter: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub request: String,
    #[serde(default)]
    pub response_snippet: String,
    #[serde(default)]
    pub curl: String,
    #[serde(default)]
    pub cwe: Option<u32>,
    #[serde(default)]
    pub references: Vec<String>,
    pub source: Source,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub ts: String,
}

impl Finding {
    pub fn new(
        category: Category,
        severity: Severity,
        confidence: Confidence,
        host: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Finding {
        let mut finding = Finding {
            id: String::new(),
            title: category.label().to_string(),
            category,
            severity,
            confidence,
            host: host.into(),
            endpoint: endpoint.into(),
            parameter: None,
            payload: None,
            request: String::new(),
            response_snippet: String::new(),
            curl: String::new(),
            cwe: category.cwe(),
            references: Vec::new(),
            source: Source::native("engine"),
            status: None,
            score: 0.0,
            ts: chrono::Utc::now().to_rfc3339(),
        };
        finding.id = finding.compute_id();
        finding.score = score::compute(&finding);
        finding
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_param(mut self, name: impl Into<String>) -> Self {
        self.parameter = Some(name.into());
        self
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    pub fn with_evidence(
        mut self,
        request: impl Into<String>,
        response: impl Into<String>,
        curl: impl Into<String>,
    ) -> Self {
        self.request = request.into();
        self.response_snippet = response.into();
        self.curl = curl.into();
        self
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_source(mut self, source: Source) -> Self {
        self.source = source;
        self
    }

    pub fn with_references(mut self, refs: &[&str]) -> Self {
        self.references = refs.iter().map(|r| r.to_string()).collect();
        self
    }

    /// Finalise identity and score. Call once the finding is complete.
    pub fn seal(mut self) -> Finding {
        self.id = self.compute_id();
        self.score = score::compute(&self);
        self
    }

    /// Stable identity: same bug on the same endpoint never reports twice.
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.category.as_str(),
            self.host.to_ascii_lowercase(),
            normalize_endpoint(&self.endpoint),
            self.parameter
                .as_deref()
                .unwrap_or("-")
                .to_ascii_lowercase(),
            self.payload_class()
        )
    }

    fn compute_id(&self) -> String {
        // Masked to 48 bits so `{:012x}` is the exact width, not a minimum:
        // ids stay short in reports and URLs while collisions remain unlikely.
        format!("{:012x}", fnv1a(&self.dedupe_key()) & 0x0000_ffff_ffff_ffff)
    }

    /// Payload families collapse together: we report a class, not every string.
    pub fn payload_class(&self) -> &'static str {
        let payload = self
            .payload
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if payload.contains("sleep") || payload.contains("pg_sleep") || payload.contains("waitfor")
        {
            "time"
        } else if payload.contains("and 1=1") || payload.contains("and 1=2") {
            "boolean"
        } else if payload.contains('\u{27}') || payload.contains('"') {
            "quote"
        } else if payload.contains("../") || payload.contains("%2e%2e") {
            "traversal"
        } else if payload.contains("{{") || payload.contains("${") {
            "ssti"
        } else if payload.contains("x-bt-inject")
            || payload.contains("%0d")
            || payload.contains("%0a")
        {
            "crlf"
        } else if payload.contains("://") {
            "url"
        } else {
            self.category.as_str()
        }
    }
}

/// Strip query string and trailing slash, lowercase for stable comparison.
fn normalize_endpoint(endpoint: &str) -> String {
    let without_query = endpoint.split('?').next().unwrap_or(endpoint);
    let trimmed = without_query.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

/// Tiny FNV-1a so ids stay deterministic across runs and machines.
fn fnv1a(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Finding {
        Finding::new(
            Category::SqlInjection,
            Severity::High,
            Confidence::Firm,
            "app.example.com",
            "https://app.example.com/item?id=1",
        )
        .with_param("id")
        .with_payload("1'")
        .seal()
    }

    #[test]
    fn ids_are_deterministic() {
        assert_eq!(sample().id, sample().id);
        assert_eq!(sample().id.len(), 12);
    }

    #[test]
    fn query_strings_collapse_in_dedupe_key() {
        let a = sample();
        let mut b = sample();
        b.endpoint = "https://app.example.com/item?id=99".to_string();
        assert_eq!(a.dedupe_key(), b.dedupe_key());
    }

    #[test]
    fn different_channels_do_not_collapse() {
        let mut b = sample();
        b.parameter = Some("name".to_string());
        assert_ne!(sample().dedupe_key(), b.dedupe_key());
    }

    #[test]
    fn payload_classes() {
        let mut finding = sample();
        finding.payload = Some("kO' OR SLEEP(5)-- -".to_string());
        assert_eq!(finding.payload_class(), "time");
        finding.payload = Some("1 AND 1=1".to_string());
        assert_eq!(finding.payload_class(), "boolean");
        finding.payload = Some("../../etc/passwd".to_string());
        assert_eq!(finding.payload_class(), "traversal");
    }

    #[test]
    fn scores_reflect_severity_and_confidence() {
        assert!(sample().score > 0.0);
        let tentative = Finding::new(
            Category::SqlInjection,
            Severity::High,
            Confidence::Tentative,
            "app.example.com",
            "/item",
        );
        assert!(sample().score > tentative.score);
    }
}
