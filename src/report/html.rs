//! Self-contained HTML report: one file, no external assets, readable offline
//! and safe to attach to a bug bounty submission.

use std::fmt::Write;

use super::{Report, html_escape, human_duration};
use crate::findings::Finding;
use crate::util::text::truncate;

const HOST_ROWS: usize = 100;

pub fn render(report: &Report<'_>) -> String {
    let summary = report.summary;
    let mut out = String::with_capacity(16 * 1024);

    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(
        out,
        "<title>BountyTool — {}</title>",
        html_escape(&summary.target)
    );
    out.push_str("<style>\n");
    out.push_str(CSS);
    out.push_str("</style>\n</head>\n<body>\n<main>\n");

    let _ = writeln!(
        out,
        "<header><h1>{}<span class=\"muted\"> — security assessment</span></h1>",
        html_escape(&summary.target)
    );
    let _ = writeln!(
        out,
        "<p class=\"meta\">Generated {} · profile <code>{}</code> · {} · session <code>{}</code></p></header>",
        html_escape(&report.generated_at()),
        html_escape(&summary.profile),
        human_duration(summary.elapsed_secs),
        html_escape(&summary.session_dir)
    );

    // Counters
    out.push_str("<section class=\"cards\">\n");
    card(&mut out, "Hosts", &summary.hosts.to_string(), "hosts");
    card(&mut out, "URLs", &summary.urls.to_string(), "urls");
    card(
        &mut out,
        "Parameters",
        &summary.params.to_string(),
        "params",
    );
    card(
        &mut out,
        "Findings",
        &report.primary().len().to_string(),
        "findings",
    );
    card(
        &mut out,
        "Observations",
        &report.observations().len().to_string(),
        "observations",
    );
    out.push_str("</section>\n");

    out.push_str("<section>\n<h2>Scope</h2>\n<pre class=\"scope\">");
    out.push_str(&html_escape(&report.scope.describe()));
    out.push_str("</pre>\n<p class=\"note\">Scanning was limited to the scope above. ");
    out.push_str("Reproduce these results only within the programme's rules.</p>\n</section>\n");

    out.push_str("<section>\n<h2>Findings</h2>\n");
    if report.primary().is_empty() {
        out.push_str("<p class=\"note\">No finding passed the confidence threshold. The observations below are still worth reviewing.</p>\n");
    } else {
        for (index, finding) in report.primary().iter().enumerate() {
            render_finding(&mut out, index + 1, finding);
        }
    }
    out.push_str("</section>\n");

    if !report.observations().is_empty() {
        out.push_str("<section>\n<h2>Observations</h2>\n<table>\n");
        out.push_str("<thead><tr><th>Severity</th><th>Category</th><th>Endpoint</th><th>Note</th></tr></thead>\n<tbody>\n");
        for finding in report.observations() {
            let _ = writeln!(
                out,
                "<tr><td><span class=\"sev sev-{}\">{}</span></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                finding.severity.as_str(),
                finding.severity.label(),
                html_escape(finding.category.label()),
                html_escape(&finding.endpoint),
                html_escape(&truncate(&finding.title, 140))
            );
        }
        out.push_str("</tbody>\n</table>\n</section>\n");
    }

    if !report.hosts.is_empty() {
        out.push_str("<section>\n<h2>Attack surface</h2>\n<table>\n");
        out.push_str("<thead><tr><th>Status</th><th>URL</th><th>Title</th><th>Server</th><th>Tech</th></tr></thead>\n<tbody>\n");
        for host in report.hosts.iter().take(HOST_ROWS) {
            let _ = writeln!(
                out,
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                host.status,
                html_escape(&host.url),
                html_escape(&truncate(&host.title, 70)),
                html_escape(&host.webserver),
                html_escape(&truncate(&host.tech.join(", "), 70))
            );
        }
        out.push_str("</tbody>\n</table>\n");
        if report.hosts.len() > HOST_ROWS {
            let _ = writeln!(
                out,
                "<p class=\"note\">{} more hosts are listed in <code>artifacts/hosts.jsonl</code>.</p>",
                report.hosts.len() - HOST_ROWS
            );
        }
        out.push_str("</section>\n");
    }

    out.push_str("<section>\n<h2>Tooling</h2>\n");
    if summary.tools.is_empty() {
        out.push_str(
            "<p class=\"note\">Native engine only; no external tools were recorded.</p>\n",
        );
    } else {
        out.push_str("<ul class=\"tools\">\n");
        for tool in &summary.tools {
            let _ = writeln!(
                out,
                "<li><code>{}</code> {}</li>",
                html_escape(&tool.name),
                html_escape(&tool.version)
            );
        }
        out.push_str("</ul>\n");
    }
    if !summary.degraded.is_empty() {
        out.push_str("<h3>Degraded coverage</h3>\n<ul class=\"warn\">\n");
        for note in &summary.degraded {
            let _ = writeln!(out, "<li>{}</li>", html_escape(note));
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</section>\n");

    let _ = writeln!(
        out,
        "<footer><p>{} {} · findings are detection-only, verify manually before reporting.</p></footer>",
        crate::APP_NAME,
        crate::APP_VERSION
    );
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

fn card(out: &mut String, label: &str, value: &str, class: &str) {
    let _ = writeln!(
        out,
        "<div class=\"card {class}\"><span class=\"value\">{}</span><span class=\"label\">{}</span></div>",
        html_escape(value),
        html_escape(label)
    );
}

fn render_finding(out: &mut String, index: usize, finding: &Finding) {
    let _ = writeln!(
        out,
        "<article class=\"finding sev-border-{}\">",
        finding.severity.as_str()
    );
    let _ = writeln!(
        out,
        "<h3><span class=\"sev sev-{}\">{}</span> {}. {}</h3>",
        finding.severity.as_str(),
        finding.severity.label(),
        index,
        html_escape(&finding.title)
    );

    out.push_str("<dl class=\"facts\">\n");
    fact(
        out,
        "Category",
        &match finding.cwe {
            Some(cwe) => format!("{} (CWE-{cwe})", finding.category.label()),
            None => finding.category.label().to_string(),
        },
    );
    fact(out, "Host", &finding.host);
    fact(out, "Endpoint", &finding.endpoint);
    if let Some(parameter) = &finding.parameter {
        fact(out, "Parameter", parameter);
    }
    if let Some(payload) = &finding.payload {
        fact(out, "Payload", &truncate(payload, 160));
    }
    fact(
        out,
        "Confidence",
        &format!("{} (score {:.2})", finding.confidence, finding.score),
    );
    if let Some(status) = finding.status {
        fact(out, "Response", &status.to_string());
    }
    fact(out, "Source", &finding.source.label());
    out.push_str("</dl>\n");

    let _ = writeln!(
        out,
        "<h4>Impact</h4><p>{}</p>",
        html_escape(finding.category.impact())
    );
    let _ = writeln!(
        out,
        "<h4>Remediation</h4><p>{}</p>",
        html_escape(finding.category.remediation())
    );

    if !finding.request.trim().is_empty() || !finding.response_snippet.trim().is_empty() {
        out.push_str("<h4>Evidence</h4>\n<pre class=\"evidence\">");
        if !finding.request.trim().is_empty() {
            out.push_str(&html_escape(&truncate(&finding.request, 1_500)));
            out.push('\n');
        }
        if !finding.response_snippet.trim().is_empty() {
            out.push('\n');
            out.push_str(&html_escape(&truncate(&finding.response_snippet, 1_500)));
        }
        out.push_str("</pre>\n");
    }
    if !finding.curl.trim().is_empty() {
        let _ = writeln!(
            out,
            "<h4>Reproduce</h4><pre class=\"evidence\">{}</pre>",
            html_escape(&truncate(&finding.curl, 1_500))
        );
    }
    if !finding.references.is_empty() {
        out.push_str("<h4>References</h4>\n<ul>\n");
        for reference in &finding.references {
            let _ = writeln!(
                out,
                "<li><a href=\"{}\" rel=\"noreferrer noopener\">{}</a></li>",
                html_escape(reference),
                html_escape(reference)
            );
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</article>\n");
}

fn fact(out: &mut String, key: &str, value: &str) {
    let _ = writeln!(
        out,
        "<dt>{}</dt><dd><code>{}</code></dd>",
        html_escape(key),
        html_escape(value)
    );
}

const CSS: &str = r#"
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 24px 96px}
h1{font-size:26px;margin:0 0 8px}
h2{font-size:19px;margin:40px 0 12px;padding-bottom:8px;border-bottom:1px solid #21262d}
h3{font-size:17px;margin:0 0 14px}
h4{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin:20px 0 6px}
code,pre{font-family:ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,monospace;font-size:13px}
code{background:#161b22;border:1px solid #21262d;border-radius:4px;padding:1px 5px}
pre{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8b949e;font-weight:400}
.meta{color:#8b949e;font-size:13px;margin:0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:28px 0 0}
.card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 16px;display:flex;flex-direction:column}
.card .value{font-size:24px;font-weight:600;color:#f0f6fc}
.card .label{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#8b949e}
.finding{background:#161b22;border:1px solid #21262d;border-left-width:4px;border-radius:10px;padding:20px;margin:16px 0}
.sev{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;padding:2px 8px;border-radius:999px;vertical-align:middle}
.sev-critical{background:#4b1113;color:#ff7b72}
.sev-high{background:#4a1c0d;color:#ffa657}
.sev-medium{background:#473a10;color:#e3b341}
.sev-low{background:#0f2d4a;color:#79c0ff}
.sev-info{background:#21262d;color:#8b949e}
.sev-border-critical{border-left-color:#f85149}
.sev-border-high{border-left-color:#ffa657}
.sev-border-medium{border-left-color:#e3b341}
.sev-border-low{border-left-color:#58a6ff}
.sev-border-info{border-left-color:#484f58}
.facts{display:grid;grid-template-columns:130px 1fr;gap:4px 14px;margin:0}
.facts dt{color:#8b949e;font-size:13px}
.facts dd{margin:0;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
a{color:#58a6ff}
.note{color:#8b949e;font-size:14px}
.warn li{color:#e3b341}
.tools li{color:#c9d1d9}
footer{margin-top:56px;color:#484f58;font-size:13px;border-top:1px solid #21262d;padding-top:16px}
"#;
