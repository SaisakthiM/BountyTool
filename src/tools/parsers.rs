//! Parsers for external tool output.
//!
//! Everything is parsed defensively from `serde_json::Value` (or plain text)
//! rather than rigid structs: ProjectDiscovery occasionally renames or drops
//! fields and a version bump must not break a scan.

use serde_json::Value;

use crate::findings::{Category, Finding, Source};
use crate::models::{Confidence, Host, Severity};

/// `subfinder -json` (or plain `-silent` output).
pub fn parse_subdomains(output: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('{') {
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                if let Some(host) = value.get("host").and_then(Value::as_str) {
                    hosts.push(host.trim().to_ascii_lowercase());
                }
            }
        } else if !line.starts_with('[') {
            hosts.push(line.trim().to_ascii_lowercase());
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// `httpx -json`.
pub fn parse_httpx(output: &str) -> Vec<Host> {
    let mut hosts: Vec<Host> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let url = get_str(&value, "url").unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        let host_name = get_str(&value, "host")
            .or_else(|| get_str(&value, "input"))
            .unwrap_or_default();

        let mut tech = get_str_array(&value, "tech");
        if tech.is_empty() {
            tech = get_str_array(&value, "technologies");
        }

        // Keep the tool's order: `httpx` prints in scan order, and downstream
        // stages report hosts in discovery order. A URL seen twice keeps its
        // first (richest) record.
        if hosts.iter().any(|existing| existing.url == url) {
            continue;
        }

        hosts.push(Host {
            host: host_name,
            url,
            status: value
                .get("status_code")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u16,
            title: get_str(&value, "title").unwrap_or_default(),
            webserver: get_str(&value, "webserver").unwrap_or_default(),
            tech,
            cdn: get_str(&value, "cdn_name").filter(|name| !name.is_empty()),
            content_length: value
                .get("content_length")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        });
    }
    hosts
}

/// `nuclei -jsonl`.
pub fn parse_nuclei(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let template_id = get_str(&value, "template-id").unwrap_or_default();
        let info = value.get("info").cloned().unwrap_or(Value::Null);
        let name = get_str(&info, "name").unwrap_or_else(|| template_id.clone());
        let severity = get_str(&info, "severity")
            .and_then(|raw| Severity::parse(&raw))
            .unwrap_or(Severity::Info);

        let tags = get_str_array(&info, "tags");
        let references = {
            let mut refs = get_str_array(&info, "reference");
            if refs.is_empty() {
                refs.push(format!(
                    "https://www.google.com/search?q=nuclei+{}",
                    template_id
                ));
            }
            refs
        };
        let cwe = get_str_array(&info, "cwe-id")
            .first()
            .and_then(|value| value.trim_start_matches("CWE-").parse::<u32>().ok())
            .or_else(|| {
                info.get("classification")
                    .and_then(|c| c.get("cwe-id"))
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .and_then(Value::as_str)
                    .and_then(|value| value.trim_start_matches("CWE-").parse::<u32>().ok())
            });

        let matched_at = get_str(&value, "matched-at")
            .or_else(|| get_str(&value, "host"))
            .unwrap_or_default();
        if matched_at.is_empty() {
            continue;
        }
        let host = crate::models::host_of(&matched_at);

        let curl = get_str(&value, "curl-command").unwrap_or_default();
        let request = get_str(&value, "request").unwrap_or_default();
        let response = get_str(&value, "response").unwrap_or_default();
        let extracted = get_str_array(&value, "extracted-results");

        let mut evidence_response = crate::util::text::truncate(&response, 1_200);
        if !extracted.is_empty() {
            evidence_response = format!(
                "extracted: {}\n\n{}",
                extracted.join(", "),
                evidence_response
            );
        }

        let category = categorize(&template_id, &tags);
        let mut confidence = Confidence::Firm;
        if category == Category::ReflectedInput || template_id.contains("detect") {
            confidence = Confidence::Tentative;
        }

        let finding = Finding::new(
            category,
            severity,
            confidence,
            host.clone(),
            matched_at.clone(),
        )
        .with_title(format!("{} [{}]", name, template_id))
        .with_evidence(request, evidence_response, curl)
        .with_source(Source::tool("nuclei"))
        .with_references(&references.iter().map(String::as_str).collect::<Vec<_>>());
        let mut finding = finding;
        finding.cwe = cwe;
        if let Some(status) = value
            .get("response")
            .and_then(Value::as_str)
            .and_then(|text| text.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
        {
            finding = finding.with_status(status);
        }
        findings.push(finding.seal());
    }
    findings
}

/// Plain URL-per-line output (`katana -silent`, `waybackurls`, ...).
pub fn parse_urls(output: &str) -> Vec<String> {
    let mut urls: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("http://") || line.starts_with("https://"))
        .map(ToString::to_string)
        .collect();
    urls.sort();
    urls.dedup();
    urls
}

/// `ffuf -o out.json -of json`.
pub fn parse_ffuf(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    if let Some(results) = value.get("results").and_then(Value::as_array) {
        for result in results {
            let status = result.get("status").and_then(Value::as_u64).unwrap_or(0);
            if !(200..400).contains(&status) {
                continue;
            }
            if let Some(url) = result.get("url").and_then(Value::as_str) {
                urls.push(url.to_string());
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

/// `gobuster dir` human output: `admin                (Status: 301) [Size: 0]`.
pub fn parse_gobuster(output: &str, base: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('/') {
            continue;
        }
        let path = trimmed.split_whitespace().next().unwrap_or_default();
        if !trimmed.contains("Status: 2") && !trimmed.contains("Status: 3") {
            continue;
        }
        urls.push(format!("{}{}", base.trim_end_matches('/'), path));
    }
    urls.sort();
    urls.dedup();
    urls
}

/// `nmap -oG -` greppable output.
pub fn parse_nmap_grep(output: &str) -> Vec<(String, u16)> {
    let mut ports = Vec::new();
    let mut current_host: Option<String> = None;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Host: ") {
            current_host = rest.split_whitespace().next().map(ToString::to_string);
        }
        if let (Some(host), Some(rest)) = (&current_host, line.split("Ports: ").nth(1)) {
            for entry in rest.split(',') {
                let mut fields = entry.trim().split('/');
                let port = fields.next().unwrap_or_default();
                let state = fields.next().unwrap_or_default();
                if state != "open" {
                    continue;
                }
                if let Ok(port) = port.parse::<u16>() {
                    ports.push((host.clone(), port));
                }
            }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

/// `naabu` output: `host:port`.
pub fn parse_naabu(output: &str) -> Vec<(String, u16)> {
    let mut ports = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        let Some((host, port)) = line.rsplit_once(':') else {
            continue;
        };
        if let Ok(port) = port.parse::<u16>() {
            ports.push((host.trim_matches(['[', ']']).to_string(), port));
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlmapHit {
    pub parameter: String,
    pub technique: String,
    pub payload: String,
}

/// sqlmap console output, reduced to the `Parameter/Type/Payload` triples.
pub fn parse_sqlmap(output: &str) -> Vec<SqlmapHit> {
    let mut hits = Vec::new();
    let mut parameter: Option<String> = None;
    let mut technique: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Parameter: ") {
            // `id (GET)` -> `id`
            parameter = Some(
                rest.split(" (")
                    .next()
                    .unwrap_or(rest)
                    .trim_matches('\'')
                    .to_string(),
            );
            technique = None;
        } else if let Some(rest) = trimmed.strip_prefix("Type: ") {
            technique = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("Payload: ") {
            if let (Some(param), Some(kind)) = (parameter.clone(), technique.clone()) {
                hits.push(SqlmapHit {
                    parameter: param,
                    technique: kind,
                    payload: rest.trim().to_string(),
                });
                technique = None;
            }
        }
    }
    hits
}

fn get_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|inner| match inner {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    })
}

fn get_str_array(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(ToString::to_string))
            .collect(),
        Some(Value::String(text)) => text
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Map a nuclei template to our category model using id + tags.
fn categorize(template_id: &str, tags: &[String]) -> Category {
    let haystack = format!(
        "{} {}",
        template_id.to_ascii_lowercase(),
        tags.join(" ").to_ascii_lowercase()
    );
    let contains = |needle: &str| haystack.contains(needle);

    if contains("sqli") || contains("sql-injection") || contains("sql_injection") {
        Category::SqlInjection
    } else if contains("ssrf") {
        Category::Ssrf
    } else if contains("open-redirect") || contains("redirect") {
        Category::OpenRedirect
    } else if contains("cors") {
        Category::CorsMisconfig
    } else if contains("crlf") || contains("response-splitting") {
        Category::CrlfInjection
    } else if contains("lfi") || contains("traversal") || contains("file-inclusion") {
        Category::PathTraversal
    } else if contains("ssti") || contains("template-injection") {
        Category::Ssti
    } else if contains("xss") || contains("cross-site-scripting") {
        Category::Xss
    } else if contains("takeover") {
        Category::SubdomainTakeover
    } else if contains("cve") {
        Category::Cve
    } else if contains("exposure")
        || contains("backup")
        || contains("config")
        || contains("disclosure")
        || contains("listing")
    {
        Category::Exposure
    } else if contains("header") {
        Category::SecurityHeader
    } else if contains("misconfig") || contains("default-login") || contains("panel") {
        Category::Misconfiguration
    } else {
        Category::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomains_from_json_and_plain() {
        let output = "{\"host\":\"a.example.com\",\"input\":\"example.com\"}\n\
                      {\"host\":\"b.example.com\"}\nb.example.com\n";
        assert_eq!(
            parse_subdomains(output),
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }

    #[test]
    fn httpx_json_becomes_hosts() {
        let output = r#"{"url":"https://app.example.com","host":"app.example.com","status_code":200,"title":"App","tech":["nginx","React"],"webserver":"nginx","content_length":1234}
{"url":"https://api.example.com","host":"api.example.com","status_code":403}"#;
        let hosts = parse_httpx(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].status, 200);
        assert_eq!(hosts[0].tech, vec!["nginx", "React"]);
        assert!(hosts[0].reachable());
        assert!(!hosts[1].reachable());
    }

    #[test]
    fn nuclei_jsonl_becomes_findings() {
        let output = r#"{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical","tags":["cve","rce"],"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"classification":{"cwe-id":["CWE-502"]}},"host":"https://app.example.com","matched-at":"https://app.example.com/api","curl-command":"curl -X GET https://app.example.com/api","request":"GET /api","response":"HTTP/1.1 200 OK"}"#;
        let findings = parse_nuclei(output);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.category, Category::Cve);
        assert_eq!(finding.host, "app.example.com");
        assert_eq!(finding.cwe, Some(502));
        assert_eq!(finding.status, Some(200));
        assert_eq!(finding.source, Source::tool("nuclei"));
        assert!(!finding.curl.is_empty());
    }

    #[test]
    fn nuclei_ssrf_template_maps_to_ssrf() {
        let output = r#"{"template-id":"ssrf-internal","info":{"name":"SSRF","severity":"high","tags":["ssrf"]},"host":"https://x.test","matched-at":"https://x.test/fetch?url=1"}"#;
        let findings = parse_nuclei(output);
        assert_eq!(findings[0].category, Category::Ssrf);
    }

    #[test]
    fn junk_lines_are_ignored() {
        let output = "[INF] something\nnot json\n{\"broken\":";
        assert!(parse_nuclei(output).is_empty());
        assert!(parse_httpx(output).is_empty());
        assert!(parse_subdomains("[INF] noise").is_empty());
    }

    #[test]
    fn urls_are_filtered_and_deduped() {
        let output = "https://a.test/x\nhttps://a.test/x\n[INF] noise\nhttp://b.test/y\n";
        assert_eq!(
            parse_urls(output),
            vec![
                "http://b.test/y".to_string(),
                "https://a.test/x".to_string()
            ]
        );
    }

    #[test]
    fn ffuf_results_skip_errors() {
        let json = r#"{"results":[{"url":"https://a.test/admin","status":200},{"url":"https://a.test/no","status":404}]}"#;
        assert_eq!(parse_ffuf(json), vec!["https://a.test/admin".to_string()]);
    }

    #[test]
    fn gobuster_results() {
        let output = "/admin                (Status: 301) [Size: 0]\n/secret (Status: 403)\n";
        assert_eq!(
            parse_gobuster(output, "https://a.test"),
            vec!["https://a.test/admin".to_string()]
        );
    }

    #[test]
    fn nmap_grep_output() {
        let output = "Host: 10.0.0.5 (a.test)\tPorts: 80/open/tcp//http///, 443/open/tcp//ssl|http///, 22/closed/tcp//ssh///\n";
        let ports = parse_nmap_grep(output);
        assert_eq!(ports.len(), 2);
        assert!(ports.contains(&("10.0.0.5".to_string(), 80)));
        assert!(ports.contains(&("10.0.0.5".to_string(), 443)));
    }

    #[test]
    fn naabu_output() {
        let ports = parse_naabu("1.2.3.4:80\n1.2.3.4:443\nbogus\n");
        assert_eq!(ports.len(), 2);
    }

    #[test]
    fn sqlmap_triples() {
        let output = "sqlmap identified the following injection point(s):\n\
                      Parameter: id (GET)\n\
                          Type: boolean-based blind\n\
                          Title: AND boolean-based blind\n\
                          Payload: id=1 AND 9049=9049\n";
        let hits = parse_sqlmap(output);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].parameter, "id");
        assert!(hits[0].payload.contains("AND 9049=9049"));
    }
}
