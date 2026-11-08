//! HTTP client used by every native probe.
//!
//! Two clients are built: one that follows redirects (recon) and one that does
//! not (redirect and CRLF detection need the raw response).

use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Method};

use crate::config::Config;
use crate::error::{Error, Result};

/// Responses are truncated here; probes only need signatures and structure.
pub const MAX_BODY: usize = 256 * 1024;

pub struct Http {
    follow: Client,
    no_follow: Client,
    pub user_agent: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed: Duration,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn header_count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .count()
    }

    pub fn content_type(&self) -> &str {
        self.header("content-type").unwrap_or_default()
    }

    pub fn is_html(&self) -> bool {
        self.content_type().contains("html") || self.body.trim_start().starts_with('<')
    }

    pub fn title(&self) -> Option<String> {
        let lower = self.body.to_ascii_lowercase();
        let start = lower.find("<title")?;
        let after_tag = self.body[start..].find('>')? + start + 1;
        let end = lower[after_tag..].find("</title")? + after_tag;
        let title = self.body[after_tag..end].trim();
        (!title.is_empty()).then(|| sanitize(title, 120))
    }

    pub fn snippet(&self, max: usize) -> String {
        sanitize(&self.body, max)
    }

    pub fn set_cookie_count(&self) -> usize {
        self.header_count("set-cookie")
    }
}

fn sanitize(value: &str, max: usize) -> String {
    let cleaned = crate::util::text::one_line(value);
    crate::util::text::truncate(&cleaned, max)
}

impl Http {
    pub fn new(config: &Config) -> Result<Http> {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert(
            reqwest::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );

        let build = |policy: Policy| {
            Client::builder()
                .user_agent(config.user_agent.clone())
                .timeout(Duration::from_secs(config.http_timeout_secs.max(5)))
                .connect_timeout(Duration::from_secs(10))
                // Bounty targets routinely have incomplete chains; a TLS
                // warning must not hide a vulnerability.
                .danger_accept_invalid_certs(true)
                .default_headers(headers.clone())
                .gzip(true)
                .brotli(true)
                .redirect(policy)
                .build()
        };

        let follow =
            build(Policy::limited(5)).map_err(|e| Error::Other(format!("http client: {e}")))?;
        let no_follow =
            build(Policy::none()).map_err(|e| Error::Other(format!("http client: {e}")))?;

        Ok(Http {
            follow,
            no_follow,
            user_agent: config.user_agent.clone(),
            timeout: Duration::from_secs(config.http_timeout_secs.max(5)),
        })
    }

    pub async fn get(
        &self,
        url: &str,
        headers: &[(&str, String)],
        follow: bool,
    ) -> Result<HttpResponse> {
        self.send(Method::GET, url, headers, None, follow).await
    }

    pub async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(&str, String)],
    ) -> Result<HttpResponse> {
        let body = form
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}={}",
                    crate::util::text::percent_encode(key),
                    crate::util::text::percent_encode(value)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let mut all_headers = headers.to_vec();
        all_headers.push((
            "Content-Type",
            "application/x-www-form-urlencoded".to_string(),
        ));
        self.send(Method::POST, url, &all_headers, Some(body), true)
            .await
    }

    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, String)],
        body: Option<String>,
        follow: bool,
    ) -> Result<HttpResponse> {
        let client = if follow {
            &self.follow
        } else {
            &self.no_follow
        };
        let mut request = client.request(method, url);

        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes());
            let value = HeaderValue::from_str(value);
            if let (Ok(name), Ok(value)) = (name, value) {
                request = request.header(name, value);
            }
        }
        if let Some(body) = body {
            request = request.body(body);
        }

        let started = Instant::now();
        let mut response = request.send().await?;
        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();

        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() >= MAX_BODY {
                break;
            }
        }
        bytes.truncate(MAX_BODY);

        Ok(HttpResponse {
            status,
            url: final_url,
            headers,
            body: String::from_utf8_lossy(&bytes).to_string(),
            elapsed: started.elapsed(),
        })
    }
}

/// Request/response evidence block written into findings.
pub fn describe_exchange(
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    response: &HttpResponse,
) -> (String, String) {
    let mut request = format!("{method} {url}\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(&crate::util::text::redact_value(name, value));
        request.push('\n');
    }
    let mut reply = format!("HTTP {}\n", response.status);
    for (name, value) in response.headers.iter().take(20) {
        reply.push_str(name);
        reply.push_str(": ");
        reply.push_str(&crate::util::text::redact_value(name, value));
        reply.push('\n');
    }
    reply.push('\n');
    reply.push_str(&response.snippet(600));
    (request, reply)
}
