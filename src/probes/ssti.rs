//! Server-side template injection detection (deep profile only).
//!
//! Uses paired arithmetic payloads so a coincidental page number cannot be
//! mistaken for evaluation.

use crate::findings::Category;
use crate::models::{Confidence, ParamCandidate, Severity};

use super::{ProbeCtx, finding, inject};

/// (payload template, expected result) pairs per engine family.
const PAIRS: &[(&str, &str, &str)] = &[
    ("{{7*7}}", "49", "{{7*8}}"),
    ("${7*7}", "49", "${7*8}"),
    ("<%= 7*7 %>", "49", "<%= 7*8 %>"),
    ("#{7*7}", "49", "#{7*8}"),
];

pub async fn run(ctx: &ProbeCtx, candidates: &[ParamCandidate]) -> Vec<crate::findings::Finding> {
    if !ctx.deep() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for candidate in candidates.iter().take(30) {
        let headers = ctx.auth_headers();

        let Some(baseline) = ctx
            .get(&candidate.host, &candidate.url, &headers, true)
            .await
        else {
            continue;
        };

        for (first, first_expect, second) in PAIRS {
            let Some(first_url) = inject(&candidate.url, &candidate.name, first) else {
                continue;
            };
            let Some(second_url) = inject(&candidate.url, &candidate.name, second) else {
                continue;
            };
            // 7*8 == 56; requiring both results rules out page numbers.
            let Some(first_response) = ctx.get(&candidate.host, &first_url, &headers, true).await
            else {
                continue;
            };
            let Some(second_response) = ctx.get(&candidate.host, &second_url, &headers, true).await
            else {
                continue;
            };

            let baseline_had_first = baseline.body.contains(first_expect);
            let evaluated_first = first_response.body.contains(first_expect) && !baseline_had_first;
            let evaluated_second =
                second_response.body.contains("56") && !baseline.body.contains("56");

            if evaluated_first && evaluated_second {
                ctx.events.info(format!(
                    "template evaluation on {} ({}) payload {}",
                    candidate.endpoint(),
                    candidate.name,
                    first
                ));
                findings.push(finding(
                    ctx,
                    candidate,
                    Category::Ssti,
                    Severity::High,
                    Confidence::Firm,
                    "ssti",
                    first,
                    &first_url,
                    &first_response,
                    format!(
                        "Server-side template injection via `{}` parameter",
                        candidate.name
                    ),
                ));
                break;
            }
        }
    }
    findings
}
