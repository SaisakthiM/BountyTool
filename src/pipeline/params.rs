//! Parameter discovery: the input to every native probe.
//!
//! Two sources, both cheap: query strings already in the URL set, and `GET`
//! forms found on the crawled pages. POST-only forms are recorded as
//! observations but not probed, because the probes only replay GET requests.

use std::collections::HashSet;
use std::path::PathBuf;

use regex::Regex;
use url::Url;

use crate::models::{ParamCandidate, Stage};
use crate::util::fs as files;
use crate::util::{Http, Limiter};

use super::{Ctx, ScanState};

/// Pages inspected for forms.
const FORM_PAGES: usize = 30;
/// Ceiling on the candidate list; the active stage trims further.
const MAX_PARAMS: usize = 600;

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<ParamCandidate> = Vec::new();

    for url in &state.urls {
        let Ok(parsed) = Url::parse(url) else {
            continue;
        };
        if parsed.query().is_none() {
            continue;
        }
        for (name, value) in parsed.query_pairs() {
            if name.is_empty() {
                continue;
            }
            let candidate = ParamCandidate::new(url.clone(), name.as_ref(), value.as_ref());
            add(&mut candidates, &mut seen, candidate);
        }
    }
    ctx.events.progress(
        Stage::Params,
        candidates.len() as u64,
        None,
        "query string parameters",
    );

    let pages: Vec<String> = state
        .urls
        .iter()
        .filter(|url| !url.contains('?'))
        .take(FORM_PAGES)
        .cloned()
        .collect();
    let form_count = harvest_forms(ctx, &pages, &mut candidates, &mut seen).await;

    if candidates.len() > MAX_PARAMS {
        ctx.events.warn(format!(
            "{} parameters found; keeping the first {MAX_PARAMS}",
            candidates.len()
        ));
        state.degrade(format!(
            "params: truncated {} candidates to {MAX_PARAMS}",
            candidates.len()
        ));
        candidates.truncate(MAX_PARAMS);
    }

    let artifact = ctx.artifact("params.jsonl");
    files::write_jsonl(&artifact, &candidates)?;
    for candidate in &candidates {
        ctx.events.param(candidate.clone());
    }
    state.params = candidates;

    ctx.events.progress(
        Stage::Params,
        state.params.len() as u64,
        Some(state.params.len() as u64),
        format!(
            "{} parameters from {} forms",
            state.params.len(),
            form_count
        ),
    );
    Ok(vec![artifact])
}

fn add(
    candidates: &mut Vec<ParamCandidate>,
    seen: &mut HashSet<String>,
    candidate: ParamCandidate,
) {
    let key = format!(
        "{}|{}",
        candidate.endpoint(),
        candidate.name.to_ascii_lowercase()
    );
    if seen.insert(key) {
        candidates.push(candidate);
    }
}

/// Returns the number of forms that produced candidates.
async fn harvest_forms(
    ctx: &Ctx<'_>,
    pages: &[String],
    candidates: &mut Vec<ParamCandidate>,
    seen: &mut HashSet<String>,
) -> usize {
    let Ok(http) = Http::new(ctx.config) else {
        return 0;
    };
    let limiter = Limiter::new(
        ctx.scope.max_rps.unwrap_or(ctx.config.rate_limit),
        ctx.config.per_host_budget,
    );
    let headers = [("User-Agent", http.user_agent.clone())];

    let Ok(form_pattern) = Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>") else {
        return 0;
    };
    let Ok(attr_pattern) =
        Regex::new(r#"(?is)\b(?:action|method)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
    else {
        return 0;
    };
    let Ok(input_pattern) = Regex::new(
        r#"(?is)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))"#,
    ) else {
        return 0;
    };

    let mut forms = 0usize;
    for page in pages {
        if ctx.cancel.is_cancelled() {
            break;
        }
        let host = crate::models::host_of(page);
        if !limiter.acquire(&host).await {
            continue;
        }
        let Ok(response) = http.get(page, &headers, true).await else {
            continue;
        };
        if !response.is_html() {
            continue;
        }
        let Ok(base) = Url::parse(&response.url) else {
            continue;
        };

        for form in form_pattern.captures_iter(&response.body) {
            let attrs = form.get(1).map(|m| m.as_str()).unwrap_or_default();
            let body = form.get(2).map(|m| m.as_str()).unwrap_or_default();

            let mut action = String::new();
            let mut method = String::from("get");
            for capture in attr_pattern.captures_iter(attrs) {
                let value = first_group(&capture).unwrap_or_default();
                let raw = capture
                    .get(0)
                    .map(|m| m.as_str().to_ascii_lowercase())
                    .unwrap_or_default();
                if raw.starts_with("action") {
                    action = value;
                } else {
                    method = value.to_ascii_lowercase();
                }
            }
            if method != "get" {
                continue;
            }

            let names: Vec<String> = input_pattern
                .captures_iter(body)
                .filter_map(|capture| first_group(&capture))
                .filter(|name| {
                    let name = name.to_ascii_lowercase();
                    !name.is_empty()
                        && !name.contains("csrf")
                        && !name.contains("token")
                        && !name.contains("captcha")
                })
                .take(10)
                .collect();
            if names.is_empty() {
                continue;
            }

            let Ok(mut target) = base.join(if action.trim().is_empty() {
                page
            } else {
                &action
            }) else {
                continue;
            };
            {
                let mut pairs = target.query_pairs_mut();
                for name in &names {
                    pairs.append_pair(name, "");
                }
            }
            let target = target.to_string();
            let before = candidates.len();
            for name in &names {
                add(
                    candidates,
                    seen,
                    ParamCandidate::new(target.clone(), name.clone(), ""),
                );
            }
            if candidates.len() > before {
                forms += 1;
            }
        }
    }
    forms
}

fn first_group(capture: &regex::Captures<'_>) -> Option<String> {
    (1..=3)
        .find_map(|index| capture.get(index))
        .map(|matched| matched.as_str().to_string())
}
