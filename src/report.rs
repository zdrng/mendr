//! Report output.
//!
//! # JSON shape (`schema_version` 1)
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "mendr_version": "0.1.0",
//!   "mode": "plan",                       // "plan" (--plan-only) | "full"
//!   "projects": [{
//!     "path": ".",                        // relative to the config dir
//!     "ecosystem": "cargo",               // null if detection failed
//!     "error": null,                      // string if the project could not be processed
//!     "findings": [{
//!       "advisory": {"id": "GHSA-...", "aliases": ["CVE-..."], "summary": "...",
//!                    "severity": {"level": "high", "score": 7.5}},   // severity may be null, score may be null
//!       "package": "smallvec", "version": "1.6.0",
//!       "via": {"name": "smallvec", "version": "1.6.0"},
//!       "paths": [["app@0.1.0", "smallvec@1.6.0"]],
//!       "strategy": "relock",             // null when there is no change
//!       "change": {"kind": "relock", "package": "smallvec", "from": "1.6.0", "to": "1.6.1"},
//!       "outcome": {"kind": "planned", "strategy": "relock", "change": {...}}
//!     }],
//!     "changes": [{"kind": "relock", ...}] // distinct planned changes
//!   }],
//!   "summary": {"findings": 1, "planned": 1, "fixed": 0, "skipped": 0, "failed": 0,
//!               "unresolved": 0, "errors": 0}
//! }
//! ```
//!
//! Outcome/Change/reason shapes are documented in `model.rs`. Stable fields
//! for comparisons: advisory id/aliases, package, version, via, strategy,
//! change, outcome kind + reason kind. Not stable: summary text, severity
//! scores, paths order beyond the first, `log_tail`, timestamps.
//!
//! # Markdown (`--format markdown`)
//!
//! Meant to be pasted as a PR description: a summary table (one row per
//! project), then per project a table of distinct changes with their result,
//! a findings table (advisory, severity, package@version, via, fix, outcome)
//! and a "Details" section explaining every failed change and every
//! skipped/failed finding without a change, with log tails in collapsible
//! `<details>` blocks. Not machine-readable; use JSON for that.

use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{BumpKind, Change, FailReason, Outcome, SkipReason, Step};
use crate::plan::Finding;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Plan,
    Full,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectReport {
    pub path: String,
    pub ecosystem: Option<String>,
    pub error: Option<String>,
    pub findings: Vec<Finding>,
    pub changes: Vec<Change>,
}

impl ProjectReport {
    pub fn new(path: &Path, base_dir: &Path) -> Self {
        let rel = path.strip_prefix(base_dir).unwrap_or(path);
        let path = if rel.as_os_str().is_empty() {
            ".".to_string()
        } else {
            rel.display().to_string()
        };
        ProjectReport {
            path,
            ecosystem: None,
            error: None,
            findings: Vec::new(),
            changes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub findings: usize,
    pub planned: usize,
    pub fixed: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Findings whose outcome is not resolved (see `Outcome::is_resolved`).
    pub unresolved: usize,
    /// Projects with an `error`.
    pub errors: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub mendr_version: String,
    pub mode: Mode,
    pub projects: Vec<ProjectReport>,
    pub summary: Summary,
}

impl Report {
    pub fn new(mode: Mode, projects: Vec<ProjectReport>) -> Report {
        let mut s = Summary::default();
        for p in &projects {
            if p.error.is_some() {
                s.errors += 1;
            }
            for f in &p.findings {
                s.findings += 1;
                match f.outcome {
                    Outcome::Planned { .. } => s.planned += 1,
                    Outcome::Fixed { .. } => s.fixed += 1,
                    Outcome::Skipped { .. } => s.skipped += 1,
                    Outcome::Failed { .. } => s.failed += 1,
                }
                if !f.outcome.is_resolved() {
                    s.unresolved += 1;
                }
            }
        }
        Report {
            schema_version: SCHEMA_VERSION,
            mendr_version: env!("CARGO_PKG_VERSION").to_string(),
            mode,
            projects,
            summary: s,
        }
    }

    /// 2 if any project errored, 1 if any finding is unresolved, else 0.
    pub fn exit_code(&self) -> i32 {
        if self.summary.errors > 0 {
            2
        } else if self.summary.unresolved > 0 {
            1
        } else {
            0
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report is always serializable") + "\n"
    }

    /// Markdown rendering (see the module docs).
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("# mendr report\n\n");
        out.push_str(match self.mode {
            Mode::Plan => {
                "Plan only (`--plan-only`): fixes are planned but were not built or tested.\n\n"
            }
            Mode::Full => {
                "Every fix was applied in a temporary copy of the project and verified with \
                 build and test.\n\n"
            }
        });
        out.push_str(
            "| Project | Ecosystem | Findings | Fixed | Planned | Skipped | Failed | Unresolved |\n\
             |---|---|--:|--:|--:|--:|--:|--:|\n",
        );
        for p in &self.projects {
            let count =
                |pred: fn(&Outcome) -> bool| p.findings.iter().filter(|f| pred(&f.outcome)).count();
            let _ = writeln!(
                out,
                "| {}{} | {} | {} | {} | {} | {} | {} | {} |",
                code(&p.path),
                if p.error.is_some() { " (error)" } else { "" },
                p.ecosystem.as_deref().unwrap_or("?"),
                p.findings.len(),
                count(|o| matches!(o, Outcome::Fixed { .. })),
                count(|o| matches!(o, Outcome::Planned { .. })),
                count(|o| matches!(o, Outcome::Skipped { .. })),
                count(|o| matches!(o, Outcome::Failed { .. })),
                count(|o| !o.is_resolved()),
            );
        }
        if self.projects.len() > 1 {
            let s = &self.summary;
            let _ = writeln!(
                out,
                "| **Total** | | {} | {} | {} | {} | {} | {} |",
                s.findings, s.fixed, s.planned, s.skipped, s.failed, s.unresolved
            );
        }
        out.push('\n');
        for p in &self.projects {
            project_markdown(&mut out, p);
        }
        out
    }
}

// ---- Markdown helpers ---------------------------------------------------------------

fn project_markdown(out: &mut String, p: &ProjectReport) {
    let _ = writeln!(
        out,
        "## {} ({})\n",
        code(&p.path),
        p.ecosystem.as_deref().unwrap_or("unknown ecosystem")
    );
    if let Some(e) = &p.error {
        let _ = writeln!(out, "**Error:** {}\n", one_line(e));
    }
    if p.findings.is_empty() {
        if p.error.is_none() {
            out.push_str("No known vulnerabilities found.\n\n");
        }
        return;
    }

    if !p.changes.is_empty() {
        out.push_str("### Changes\n\n| Change | Fixes | Result |\n|---|---|---|\n");
        for c in &p.changes {
            let findings: Vec<&Finding> = p
                .findings
                .iter()
                .filter(|f| f.change.as_ref() == Some(c))
                .collect();
            let mut ids: Vec<&str> = findings.iter().map(|f| f.advisory.id.as_str()).collect();
            ids.sort();
            ids.dedup();
            let result = findings
                .first()
                .map_or("-".to_string(), |f| outcome_short(&f.outcome));
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                change_text(c),
                cell(&ids.join(", ")),
                result
            );
        }
        out.push('\n');
    }

    out.push_str(
        "### Findings\n\n| Advisory | Severity | Package | Via | Fix | Outcome |\n\
         |---|---|---|---|---|---|\n",
    );
    for f in &p.findings {
        let a = &f.advisory;
        let title = a
            .summary
            .as_deref()
            .map(|s| format!(" \"{}\"", cell(&s.replace('"', "'"))))
            .unwrap_or_default();
        let severity = match &a.severity {
            Some(s) => match s.score {
                Some(score) => format!("{} ({score:.1})", level_name(s.level)),
                None => level_name(s.level).to_string(),
            },
            None => "unknown".into(),
        };
        let _ = writeln!(
            out,
            "| [{id}](https://osv.dev/vulnerability/{id}{title}) | {severity} | {} | {} | {} | {} |",
            code(&format!("{}@{}", f.package, f.version)),
            code(&f.via.name),
            f.change.as_ref().map_or("-".into(), change_text),
            outcome_short(&f.outcome),
            id = a.id,
        );
    }
    out.push('\n');

    // Details: one entry per distinct failure of a change (a baseline failure
    // is shared by all changes), plus findings without a change.
    let mut entries: Vec<(Vec<String>, String, Option<(&str, &str)>)> = Vec::new();
    for f in &p.findings {
        let (subject, text, log) = match (&f.outcome, &f.change) {
            (Outcome::Failed { reason }, Some(c)) => {
                (change_text(c), fail_text(reason), fail_log(reason))
            }
            (Outcome::Failed { reason }, None) => {
                (finding_subject(f), fail_text(reason), fail_log(reason))
            }
            (Outcome::Skipped { reason }, _) => (finding_subject(f), skip_text(reason), None),
            _ => continue,
        };
        match entries.iter_mut().find(|(_, t, l)| *t == text && *l == log) {
            Some((subjects, _, _)) => {
                if !subjects.contains(&subject) {
                    subjects.push(subject);
                }
            }
            None => entries.push((vec![subject], text, log)),
        }
    }
    if entries.is_empty() {
        return;
    }
    out.push_str("### Details\n\n");
    for (subjects, text, log) in entries {
        let _ = writeln!(out, "- {}: {text}", subjects.join(", "));
        if let Some((command, tail)) = log.filter(|(_, t)| !t.trim().is_empty()) {
            let fence = fence_for(tail);
            let _ = writeln!(
                out,
                "\n  <details><summary>Log tail of <code>{}</code></summary>\n\n  {fence}text\n{}\n  {fence}\n\n  </details>\n",
                html_escape(command),
                tail.lines()
                    .map(|l| format!("  {l}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    }
    out.push('\n');
}

fn finding_subject(f: &Finding) -> String {
    format!(
        "{} in {}",
        f.advisory.id,
        code(&format!("{}@{}", f.package, f.version))
    )
}

fn change_text(c: &Change) -> String {
    match c {
        Change::Relock { package, from, to } => format!("relock {} {from} → {to}", code(package)),
        Change::DirectBump {
            package,
            from,
            to,
            bump,
        } => format!(
            "bump {} {from} → {to} ({})",
            code(package),
            match bump {
                BumpKind::Patch => "patch",
                BumpKind::Minor => "minor",
                BumpKind::Major => "major",
            }
        ),
        Change::Override { package, from, to } => {
            format!("override {} {from} → {to}", code(package))
        }
    }
}

/// `fixed`, `planned`, `failed: build failed`, `skipped: no patched version`.
fn outcome_short(o: &Outcome) -> String {
    match o {
        Outcome::Planned { .. } => "planned".into(),
        Outcome::Fixed { .. } => "**fixed**".into(),
        Outcome::Skipped { reason } => format!("skipped: {}", reason.kind().replace('_', " ")),
        Outcome::Failed { reason } => format!("**failed**: {}", reason.kind().replace('_', " ")),
    }
}

fn level_name(l: crate::osv::SeverityLevel) -> &'static str {
    use crate::osv::SeverityLevel::*;
    match l {
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

fn step_name(s: Step) -> &'static str {
    match s {
        Step::Apply => "apply",
        Step::Install => "install",
        Step::Build => "build",
        Step::Test => "test",
    }
}

fn exit_text(exit_code: &Option<i32>) -> String {
    match exit_code {
        Some(c) => format!("exited with code {c}"),
        None => "was killed or could not be started".into(),
    }
}

/// `7d`, `12h`, `20m`, `30s`.
fn duration_text(secs: u64) -> String {
    match secs {
        0 => "0s".into(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn published_text(at: &Option<jiff::Timestamp>) -> String {
    match at {
        Some(t) => format!("published {}", t.strftime("%Y-%m-%d %H:%M UTC")),
        None => "with no known publish date".into(),
    }
}

fn skip_text(r: &SkipReason) -> String {
    match r {
        SkipReason::NoPatchedVersion { package } => {
            format!(
                "no released version of {} fixes this advisory.",
                code(package)
            )
        }
        SkipReason::NoParentVersionFixes {
            package,
            vulnerable,
        } => format!(
            "no version of {} pulls in a fixed {}, and no other strategy applies.",
            code(package),
            code(vulnerable)
        ),
        SkipReason::MajorBumpBlocked { package, from, to } => format!(
            "the fix needs a major bump of {} ({from} → {to}); allow it with `--allow-major`.",
            code(package)
        ),
        SkipReason::StrategyUnsupported { strategy } => {
            format!("the only fix needs `{strategy}`, which this ecosystem does not support.")
        }
        SkipReason::ReleaseTooRecent {
            package,
            version,
            published_at,
            min_release_age_secs,
        } => format!(
            "the fix {} is {}, younger than `min-release-age` ({}).",
            code(&format!("{package}@{version}")),
            published_text(published_at),
            duration_text(*min_release_age_secs)
        ),
        SkipReason::Ignored { reason, expires } => match expires {
            Some(d) => format!("ignored until {d}: {}", one_line(reason)),
            None => format!("ignored: {}", one_line(reason)),
        },
        SkipReason::BelowMinSeverity {
            severity,
            min_severity,
        } => format!(
            "severity {} is below `min-severity` ({}).",
            level_name(*severity),
            level_name(*min_severity)
        ),
    }
}

fn fail_text(r: &FailReason) -> String {
    match r {
        FailReason::BaselineFailed {
            step,
            command,
            exit_code,
            ..
        } => format!(
            "the unmodified project already fails ({}: `{command}` {}); nothing was attempted.",
            step_name(*step),
            exit_text(exit_code)
        ),
        FailReason::ResolutionConflict { detail } => {
            format!(
                "the package manager could not resolve the change: {}",
                one_line(detail)
            )
        }
        FailReason::ReleaseAgePolicyViolated {
            package,
            version,
            published_at,
        } => format!(
            "the change pulls in {}, {}, younger than `min-release-age`.",
            code(&format!("{package}@{version}")),
            published_text(published_at)
        ),
        FailReason::InstallFailed {
            command, exit_code, ..
        } => format!("install failed: `{command}` {}.", exit_text(exit_code)),
        FailReason::BuildFailed {
            command, exit_code, ..
        } => format!("build failed: `{command}` {}.", exit_text(exit_code)),
        FailReason::TestFailed {
            command, exit_code, ..
        } => format!("tests failed: `{command}` {}.", exit_text(exit_code)),
        FailReason::Timeout {
            step,
            command,
            after_secs,
        } => format!(
            "{}: `{command}` timed out after {}.",
            step_name(*step),
            duration_text(*after_secs)
        ),
        FailReason::NewVulnerabilityIntroduced {
            advisory,
            package,
            version,
        } => format!(
            "the change introduces {}, affected by {advisory}.",
            code(&format!("{package}@{version}"))
        ),
        FailReason::StillVulnerable { package, version } => format!(
            "{} is still in the dependency graph after the change.",
            code(&format!("{package}@{version}"))
        ),
        FailReason::ManifestNotEditable { detail } => {
            format!("the manifest could not be edited: {}", one_line(detail))
        }
        FailReason::Error { message } => format!("error: {}", one_line(message)),
    }
}

/// `(command, log tail)` of reasons that carry command output.
fn fail_log(r: &FailReason) -> Option<(&str, &str)> {
    match r {
        FailReason::BaselineFailed {
            command, log_tail, ..
        }
        | FailReason::InstallFailed {
            command, log_tail, ..
        }
        | FailReason::BuildFailed {
            command, log_tail, ..
        }
        | FailReason::TestFailed {
            command, log_tail, ..
        } => Some((command, log_tail)),
        _ => None,
    }
}

/// Inline code span that survives backticks in `s`, safe in table cells.
fn code(s: &str) -> String {
    let s = cell(s);
    if s.contains('`') {
        format!("`` {s} ``")
    } else {
        format!("`{s}`")
    }
}

/// Text safe inside a table cell: one line, `|` escaped.
fn cell(s: &str) -> String {
    one_line(s).replace('|', "\\|")
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A code fence longer than any backtick run in `text`.
fn fence_for(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    "`".repeat(longest.max(2) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FailReason, SkipReason, Version};
    use crate::plan::{AdvisoryRef, PackageRef};

    fn finding(outcome: Outcome) -> Finding {
        Finding {
            advisory: AdvisoryRef {
                id: "GHSA-1".into(),
                aliases: vec![],
                summary: None,
                severity: None,
            },
            package: "p".into(),
            version: Version::new("1.0.0"),
            via: PackageRef {
                name: "p".into(),
                version: Version::new("1.0.0"),
            },
            paths: vec![],
            strategy: None,
            change: None,
            outcome,
        }
    }

    #[test]
    fn exit_codes_and_summary() {
        let mut p = ProjectReport::new(Path::new("/r"), Path::new("/r"));
        assert_eq!(p.path, ".");
        p.findings.push(finding(Outcome::Skipped {
            reason: SkipReason::Ignored {
                reason: "x".into(),
                expires: None,
            },
        }));
        let r = Report::new(Mode::Plan, vec![p.clone()]);
        assert_eq!(r.exit_code(), 0);

        p.findings.push(finding(Outcome::Failed {
            reason: FailReason::Error {
                message: "x".into(),
            },
        }));
        let r = Report::new(Mode::Full, vec![p.clone()]);
        assert_eq!(r.exit_code(), 1);
        assert_eq!(r.summary.unresolved, 1);
        assert_eq!(r.summary.skipped, 1);

        let mut broken = ProjectReport::new(Path::new("/r/sub"), Path::new("/r"));
        assert_eq!(broken.path, "sub");
        broken.error = Some("boom".into());
        let r = Report::new(Mode::Full, vec![p, broken]);
        assert_eq!(r.exit_code(), 2);

        let json: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["mode"], "full");
        assert_eq!(
            json["projects"][0]["findings"][1]["outcome"]["reason"]["kind"],
            "error"
        );
        assert!(r.to_markdown().contains("**failed**: error"));
    }

    #[test]
    fn markdown_report() {
        use crate::model::{BumpKind, Strategy};
        use crate::osv::{Severity, SeverityLevel};

        let relock = Change::Relock {
            package: "p".into(),
            from: Version::new("1.0.0"),
            to: Version::new("1.0.1"),
        };
        let bump = Change::DirectBump {
            package: "a".into(),
            from: Version::new("1.0.0"),
            to: Version::new("1.2.0"),
            bump: BumpKind::Minor,
        };
        let mut fixed = finding(Outcome::Fixed {
            strategy: Strategy::Relock,
            change: relock.clone(),
        });
        fixed.advisory.summary = Some("Bad \"thing\" | worse".into());
        fixed.advisory.severity = Some(Severity {
            level: SeverityLevel::High,
            score: Some(7.5),
        });
        fixed.change = Some(relock.clone());
        let build_failed = FailReason::BuildFailed {
            command: "cargo build".into(),
            exit_code: Some(101),
            log_tail: "error[E0425]: oops\n```\nnested fence".into(),
        };
        let mut failed = finding(Outcome::Failed {
            reason: build_failed.clone(),
        });
        failed.advisory.id = "GHSA-2".into();
        failed.package = "q".into();
        failed.via.name = "a".into();
        failed.change = Some(bump.clone());
        let mut failed2 = failed.clone();
        failed2.advisory.id = "GHSA-3".into();
        let skipped = finding(Outcome::Skipped {
            reason: SkipReason::MajorBumpBlocked {
                package: "z".into(),
                from: Version::new("1.0.0"),
                to: Version::new("2.0.0"),
            },
        });

        let mut p = ProjectReport::new(Path::new("/r"), Path::new("/r"));
        p.ecosystem = Some("cargo".into());
        p.findings = vec![fixed, failed, failed2, skipped];
        p.changes = vec![relock, bump];
        let mut empty = ProjectReport::new(Path::new("/r/b"), Path::new("/r"));
        empty.ecosystem = Some("npm".into());
        let md = Report::new(Mode::Full, vec![p, empty]).to_markdown();

        for expected in [
            "| `.` | cargo | 4 | 1 | 0 | 1 | 2 | 3 |",
            "| `b` | npm | 0 | 0 | 0 | 0 | 0 | 0 |",
            "| **Total** | | 4 | 1 | 0 | 1 | 2 | 3 |",
            "| relock `p` 1.0.0 → 1.0.1 | GHSA-1 | **fixed** |",
            "| bump `a` 1.0.0 → 1.2.0 (minor) | GHSA-2, GHSA-3 | **failed**: build failed |",
            "| [GHSA-1](https://osv.dev/vulnerability/GHSA-1 \"Bad 'thing' \\| worse\") | high (7.5) | `p@1.0.0` | `p` | relock `p` 1.0.0 → 1.0.1 | **fixed** |",
            "- bump `a` 1.0.0 → 1.2.0 (minor): build failed: `cargo build` exited with code 101.",
            "<summary>Log tail of <code>cargo build</code></summary>",
            "  ````text\n  error[E0425]: oops\n  ```\n  nested fence\n  ````",
            "- GHSA-1 in `p@1.0.0`: the fix needs a major bump of `z` (1.0.0 → 2.0.0); allow it with `--allow-major`.",
            "## `b` (npm)\n\nNo known vulnerabilities found.",
        ] {
            assert!(md.contains(expected), "missing {expected:?} in:\n{md}");
        }
        // The shared build failure is explained once.
        assert_eq!(md.matches("<details>").count(), 1, "{md}");
    }
}
