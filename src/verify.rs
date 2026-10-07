//! Verification of planned changes (M3).
//!
//! TODO(M3): implement [`verify`] and [`write_back`]. Intended algorithm:
//!
//! 1. Copy `project.path` to a temp dir, skipping `eco.copy_excludes()`.
//! 2. Baseline: run `commands.install`, `build`, `test` (`sh -c`, cwd = copy,
//!    `project.timeout` per command). If anything fails, mark every finding
//!    that has a change as `Failed { BaselineFailed }` and stop.
//! 3. For each change in `plan.changes` (in order):
//!    snapshot the copy -> `eco.apply(copy, change)` (error ->
//!    `AdapterError::to_fail_reason`) -> `eco.resolve_graph(copy)` ->
//!    release-age check on every package version new in the graph diff
//!    (`ReleaseAgePolicyViolated`) -> rescan with `osv.advisories` +
//!    `osv::vulnerabilities_for` (vulnerable version still present ->
//!    `StillVulnerable`, new advisory -> `NewVulnerabilityIntroduced`) ->
//!    install/build/test (`InstallFailed`/`BuildFailed`/`TestFailed`/`Timeout`).
//!    Keep on success, otherwise restore the snapshot.
//! 4. Apply all kept changes together once more and re-run build + test; if
//!    that fails, fall back to verifying them one by one (or mark failed).
//! 5. Findings whose `change` was kept become `Outcome::Fixed { strategy,
//!    change }`; others become `Outcome::Failed { reason }` with the reason of
//!    their change. Skipped findings are left untouched.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use jiff::Timestamp;

use crate::config::{IgnoreRule, Policy, ProjectConfig};
use crate::ecosystem::{Commands, Ecosystem};
use crate::model::Change;
use crate::osv::Osv;
use crate::plan::ProjectPlan;

/// Everything `verify` needs for one project.
pub struct VerifyContext<'a> {
    pub eco: &'a dyn Ecosystem,
    pub project: &'a ProjectConfig,
    /// `project.commands(eco.default_commands(&project.path))`.
    pub commands: Commands,
    /// Per-command timeout (`project.timeout`).
    pub timeout: Option<Duration>,
    pub policy: &'a Policy,
    pub ignores: &'a [IgnoreRule],
    pub now: Timestamp,
}

/// Result of verifying one project.
#[derive(Debug, Default)]
pub struct Verified {
    /// The temp copy holding all kept changes (kept alive for `write_back`).
    pub workdir: Option<tempfile::TempDir>,
    /// Changes that passed verification, in application order.
    pub kept: Vec<Change>,
}

/// Verify `plan.changes` in a temporary copy and update every finding's
/// `outcome` in place (`Planned` -> `Fixed` / `Failed`). Never touches
/// `ctx.project.path`. An `Err` means verification could not run at all
/// (e.g. the copy failed); per-change problems are recorded as outcomes.
// TODO(M3): implement. The stub leaves outcomes as `planned`.
pub fn verify(ctx: &VerifyContext, _osv: &mut Osv, _plan: &mut ProjectPlan) -> Result<Verified> {
    eprintln!(
        "warning: verification is not implemented yet; reporting planned changes for {}",
        ctx.project.path.display()
    );
    Ok(Verified::default())
}

/// `--write`: copy the files changed by the kept changes (manifests and
/// lockfiles; any file that differs between `verified.workdir` and the
/// project, excluding `eco.copy_excludes()`) back into the project.
// TODO(M3): implement.
pub fn write_back(ctx: &VerifyContext, verified: &Verified) -> Result<Vec<PathBuf>> {
    if !verified.kept.is_empty() {
        eprintln!(
            "warning: --write is not implemented yet; {} unchanged",
            ctx.project.path.display()
        );
    }
    Ok(Vec::new())
}
