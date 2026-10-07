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

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{Change, Outcome};
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

    /// Minimal Markdown rendering.
    // TODO(M3): proper Markdown report (summary table, per-project sections,
    // collapsible paths and log tails).
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("# mendr report\n\n");
        for p in &self.projects {
            out.push_str(&format!(
                "## {} ({})\n\n",
                p.path,
                p.ecosystem.as_deref().unwrap_or("unknown")
            ));
            if let Some(e) = &p.error {
                out.push_str(&format!("Error: {e}\n\n"));
            }
            for f in &p.findings {
                let change = f
                    .change
                    .as_ref()
                    .map(|c| format!(" — {c}"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "- {} in {}@{} via {}: {}{}\n",
                    f.advisory.id,
                    f.package,
                    f.version,
                    f.via.name,
                    f.outcome.label(),
                    change
                ));
            }
            out.push('\n');
        }
        out
    }
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
        assert!(r.to_markdown().contains("failed:error"));
    }
}
