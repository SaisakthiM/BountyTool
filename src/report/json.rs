//! Machine readable report.
//!
//! The JSON shape is versioned: additive changes bump nothing, breaking
//! changes bump `schema`.

use super::Report;
use crate::error::Result;

/// Bumped only when the top-level shape changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// Hosts embedded in the document; the full list is always in `hosts.jsonl`.
const HOST_LIMIT: usize = 500;

pub fn render(report: &Report<'_>) -> Result<String> {
    let summary = report.summary;
    let payload = serde_json::json!({
        "schema": SCHEMA_VERSION,
        "tool": {
            "name": crate::APP_NAME,
            "version": crate::APP_VERSION,
            "repo": crate::APP_REPO,
        },
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "target": summary.target,
        "profile": summary.profile,
        "duration_secs": summary.elapsed_secs,
        "session_dir": summary.session_dir,
        "scope": {
            "targets": report.scope.targets,
            "exclude": report.scope.exclude,
            "platform": report.scope.platform,
            "program": report.scope.program,
            "allow_private_ips": report.scope.allow_private_ips,
            "description": report.scope.describe(),
        },
        "stats": {
            "hosts": summary.hosts,
            "urls": summary.urls,
            "params": summary.params,
            "findings": report.primary().len(),
            "observations": report.observations().len(),
            "by_severity": summary.by_severity,
        },
        "tools": summary.tools,
        "degraded": summary.degraded,
        "findings": report.primary(),
        "observations": report.observations(),
        "hosts": report.hosts.iter().take(HOST_LIMIT).collect::<Vec<_>>(),
    });
    Ok(serde_json::to_string_pretty(&payload)?)
}
