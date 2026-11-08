//! Triage: collapse duplicates, rank by suspicion score and split the result
//! into findings (worth a report) and observations (context).
//!
//! Everything downstream — the report and the TUI summary — reads this split,
//! so it happens exactly once, here.

use std::path::PathBuf;

use crate::findings::{PRIMARY_THRESHOLD, triage};
use crate::models::Stage;
use crate::util::fs as files;

use super::{Ctx, ScanState};

pub async fn run(
    ctx: &Ctx<'_>,
    state: &mut ScanState,
) -> Result<Vec<PathBuf>, crate::error::Error> {
    let collected = std::mem::take(&mut state.findings);
    let result = triage(collected, PRIMARY_THRESHOLD);

    for finding in &result.primary {
        ctx.events.info(format!(
            "[{}] {} — {}",
            finding.severity.label(),
            finding.title,
            finding.endpoint
        ));
    }

    state.findings = result
        .primary
        .iter()
        .chain(result.observations.iter())
        .cloned()
        .collect();
    state.triage = Some(result.clone());

    let artifact = ctx.artifact("findings.jsonl");
    files::write_jsonl(&artifact, &state.findings)?;

    if result.primary.is_empty() {
        ctx.events
            .warn("no findings above the confidence threshold; see observations");
        state.degrade("triage: no primary findings".to_string());
    }

    ctx.events.progress(
        Stage::Triage,
        result.primary.len() as u64,
        Some((result.primary.len() + result.observations.len()) as u64),
        format!(
            "{} findings, {} observations",
            result.primary.len(),
            result.observations.len()
        ),
    );
    Ok(vec![artifact])
}
