//! Verification of planned changes.
//!
//! 1. Copy `project.path` to a temp dir: top-level `eco.copy_excludes()` are
//!    skipped; symlinks are recreated only when they resolve inside the
//!    project (absolute ones are re-pointed into the copy), all others are
//!    skipped, so nothing outside the tree is reachable through the copy.
//! 2. Baseline: run `commands.install`, `build`, `test` (`sh -c`, cwd = copy,
//!    `project.timeout` per command). If anything fails, every finding that
//!    has a change becomes `Failed { BaselineFailed }` and nothing else runs.
//!    Then resolve the graph and scan it (the "current" state).
//! 3. For each change in `plan.changes` (in order), on top of the changes
//!    kept so far: snapshot the copy -> `eco.apply(copy, change,
//!    &ApplyOptions { release_cutoff })` (error -> `AdapterError::to_fail_reason`)
//!    -> record the files `apply` changed -> `eco.resolve_graph(copy)` ->
//!    release-age check on every registry package version that is new in the
//!    graph (`ReleaseAgePolicyViolated`; unknown publish date fails closed)
//!    -> rescan with `osv.advisories` + `osv::vulnerabilities_for` (a finding
//!    of this change still reachable through its `via` -> `StillVulnerable`;
//!    an advisory/package pair that was not there before and is neither
//!    ignored nor below `min-severity` -> `NewVulnerabilityIntroduced`) ->
//!    install/build/test (`InstallFailed`/`BuildFailed`/`TestFailed`/`Timeout`).
//!    Keep on success, otherwise restore the snapshot. A failing change never
//!    stops the others. A change whose `package@from` is no longer in the
//!    graph (moved by an earlier kept change) is not applied: it is kept if
//!    the rescan shows its findings fixed, else `StillVulnerable`.
//! 4. Because changes are applied cumulatively, the last kept change was
//!    already built and tested together with all earlier kept ones. Only if
//!    a later attempt was reverted (its install/build may have left state in
//!    excluded dirs such as `node_modules`) are install/build/test run once
//!    more on the combined state; if that fails, every kept change fails
//!    with that reason and nothing is written back.
//! 5. Findings whose `change` was kept become `Outcome::Fixed { strategy,
//!    change }`; others become `Outcome::Failed { reason }` with the reason of
//!    their change. Skipped/failed findings from planning are left untouched.
//!
//! `--write` ([`write_back`]) copies back exactly the files `apply` changed
//! for the kept changes, with their content captured right after `apply`
//! (before any build ran), so build and test output never reaches the user's
//! project.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use jiff::Timestamp;

use crate::config::{IgnoreRule, Policy, ProjectConfig};
use crate::ecosystem::{ApplyOptions, Commands, Ecosystem};
use crate::model::{Change, DepGraph, FailReason, NodeId, Outcome, Step, log_tail};
use crate::osv::{self, Advisory, Osv};
use crate::plan::{Finding, ProjectPlan};
use crate::progress;
use crate::rules::{self, IgnoreMatch};

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
    /// Files (relative to the project) changed by the kept changes, with their
    /// content right after `apply`; `None` = deleted.
    pub files: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

/// Verify `plan.changes` in a temporary copy and update every finding's
/// `outcome` in place (`Planned` -> `Fixed` / `Failed`). Never touches
/// `ctx.project.path`. An `Err` means verification could not run at all
/// (e.g. the copy failed); per-change problems are recorded as outcomes.
pub fn verify(ctx: &VerifyContext, osv: &mut Osv, plan: &mut ProjectPlan) -> Result<Verified> {
    let excludes = ctx.eco.copy_excludes();
    let root = ctx
        .project
        .path
        .canonicalize()
        .with_context(|| format!("resolving {}", ctx.project.path.display()))?;
    let tmp = tempfile::Builder::new().prefix("mendr-").tempdir()?;
    // Keep the directory name: some tools derive defaults from it.
    let work = tmp
        .path()
        .join("copy")
        .join(root.file_name().unwrap_or("project".as_ref()));
    let snap = tmp.path().join("snapshot");
    copy_tree(&root, &work, excludes, true)
        .with_context(|| format!("copying {} to {}", root.display(), work.display()))?;

    let step = progress::begin("Baseline", "install, build and test in a temporary copy");
    if let Err(reason) = run_steps(ctx, &work, true) {
        step.failed("Baseline", describe_reason(&reason));
        set_outcomes(plan, &[], &HashMap::new(), Some(&reason));
        return Ok(Verified::default());
    }
    let mut current = scan(ctx, osv, &work)
        .map_err(|r| anyhow::anyhow!("scanning the baseline: {}", describe_reason(&r)))?;
    step.done("Baseline", "passed");

    let mut kept = Vec::new();
    let mut failed: HashMap<Change, FailReason> = HashMap::new();
    let mut files = BTreeMap::new();
    // A reverted attempt ran commands after the last kept change.
    let mut dirty = false;
    for change in &plan.changes {
        let step = progress::begin("Trying", change);
        let findings: Vec<&Finding> = plan
            .findings
            .iter()
            .filter(|f| matches!(&f.outcome, Outcome::Planned { change: c, .. } if c == change))
            .collect();
        if current
            .graph
            .find(change.package(), change.from())
            .is_none()
        {
            // An earlier kept change already moved `package@from` (same
            // vulnerable node, or a bump that also moved it): nothing to apply.
            match check_still_vulnerable(ctx.eco, &findings, &current) {
                Ok(()) => {
                    step.done("Kept", format!("{change} (done by an earlier change)"));
                    kept.push(change.clone());
                }
                Err(reason) => {
                    step.failed("Failed", format!("{change}: {}", describe_reason(&reason)));
                    failed.insert(change.clone(), reason);
                }
            }
            continue;
        }
        copy_tree(&work, &snap, excludes, false).context("snapshotting the project copy")?;
        match try_change(ctx, osv, &work, &snap, change, &findings, &current) {
            Ok((after, changed)) => {
                step.done("Kept", change);
                current = after;
                files.extend(changed);
                kept.push(change.clone());
                dirty = false;
            }
            Err(reason) => {
                step.failed(
                    "Reverted",
                    format!("{change}: {}", describe_reason(&reason)),
                );
                restore(&snap, &work, excludes).context("restoring the project copy")?;
                failed.insert(change.clone(), reason);
                dirty = true;
            }
        }
        fs::remove_dir_all(&snap).context("removing snapshot")?;
    }

    if dirty && !kept.is_empty() {
        let what = progress::count(kept.len(), "kept change", "kept changes");
        let step = progress::begin("Verifying", format!("{what} together"));
        if let Err(reason) = run_steps(ctx, &work, false) {
            step.failed(
                "Failed",
                format!("{what} together: {}", describe_reason(&reason)),
            );
            for change in kept.drain(..) {
                failed.insert(change, reason.clone());
            }
            files.clear();
        } else {
            step.done("Verified", format!("{what} together"));
        }
    }

    set_outcomes(plan, &kept, &failed, None);
    Ok(Verified { files })
}

/// `--write`: write the files changed by the kept changes (manifests and
/// lockfiles, as captured right after `apply`) into the project. Returns the
/// paths written or removed.
pub fn write_back(ctx: &VerifyContext, verified: &Verified) -> Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    for (rel, content) in &verified.files {
        let path = ctx.project.path.join(rel);
        match content {
            Some(bytes) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
            }
            None if path.exists() => {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?
            }
            None => continue,
        }
        written.push(path);
    }
    Ok(written)
}

// ---- One change ------------------------------------------------------------------

/// The graph of the project copy and the advisories for its packages.
struct Scan {
    graph: DepGraph,
    advisories: Vec<Advisory>,
}

type ChangedFiles = Vec<(PathBuf, Option<Vec<u8>>)>;

fn try_change(
    ctx: &VerifyContext,
    osv: &mut Osv,
    work: &Path,
    snap: &Path,
    change: &Change,
    findings: &[&Finding],
    before: &Scan,
) -> Result<(Scan, ChangedFiles), FailReason> {
    let opts = ApplyOptions {
        release_cutoff: release_cutoff(ctx),
    };
    ctx.eco
        .apply(work, change, &opts)
        .map_err(|e| e.to_fail_reason())?;
    let changed = changed_files(snap, work, ctx.eco.copy_excludes())
        .map_err(|e| error(format!("comparing the project copy: {e}")))?
        .into_iter()
        .map(|rel| {
            let content = fs::read(work.join(&rel)).ok();
            (rel, content)
        })
        .collect();
    let after = scan(ctx, osv, work)?;
    check_release_age(ctx, &before.graph, &after.graph)?;
    check_still_vulnerable(ctx.eco, findings, &after)?;
    check_new_vulnerabilities(ctx, before, &after)?;
    run_steps(ctx, work, false)?;
    Ok((after, changed))
}

fn release_cutoff(ctx: &VerifyContext) -> Option<Timestamp> {
    let age = ctx.policy.min_release_age;
    if age.is_zero() {
        return None;
    }
    let secs = i64::try_from(age.as_secs()).unwrap_or(i64::MAX);
    ctx.now
        .checked_sub(jiff::SignedDuration::from_secs(secs))
        .ok()
}

fn error(message: String) -> FailReason {
    FailReason::Error { message }
}

fn scan(ctx: &VerifyContext, osv: &mut Osv, dir: &Path) -> Result<Scan, FailReason> {
    let graph = ctx.eco.resolve_graph(dir).map_err(|e| e.to_fail_reason())?;
    let advisories = osv
        .advisories(ctx.eco, &osv::package_names(&graph))
        .map_err(|e| error(format!("looking up advisories: {e:#}")))?;
    Ok(Scan { graph, advisories })
}

/// Every registry package version new in `after` must pass `min-release-age`.
fn check_release_age(
    ctx: &VerifyContext,
    before: &DepGraph,
    after: &DepGraph,
) -> Result<(), FailReason> {
    let min_age = ctx.policy.min_release_age;
    if min_age.is_zero() {
        return Ok(());
    }
    let old: HashSet<(&str, &str)> = before
        .nodes
        .iter()
        .map(|n| (n.name.as_str(), n.version.as_str()))
        .collect();
    for n in after
        .nodes
        .iter()
        .filter(|n| n.registry && !old.contains(&(n.name.as_str(), n.version.as_str())))
    {
        let releases = ctx
            .eco
            .releases(&n.name)
            .map_err(|e| error(format!("fetching releases of {}: {e}", n.name)))?;
        let published_at = releases
            .iter()
            .find(|r| ctx.eco.compare(&r.version, &n.version).is_eq())
            .and_then(|r| r.published_at);
        if !rules::release_age_ok(published_at, min_age, ctx.now) {
            return Err(FailReason::ReleaseAgePolicyViolated {
                package: n.name.clone(),
                version: n.version.clone(),
                published_at,
            });
        }
    }
    Ok(())
}

/// Whether `node` is reachable from a direct dependency named `via`.
fn reached_via(graph: &DepGraph, node: NodeId, via: &str) -> bool {
    graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.direct && n.name == via)
        .any(|(id, _)| graph.reachable_from(id).contains(&node))
}

/// A finding of this change is still present: its package, at the old
/// version or any version its advisory affects, is reachable through its via.
fn check_still_vulnerable(
    eco: &dyn Ecosystem,
    findings: &[&Finding],
    after: &Scan,
) -> Result<(), FailReason> {
    for f in findings {
        let advisory = after.advisories.iter().find(|a| a.has_id(&f.advisory.id));
        for (id, n) in after.graph.nodes.iter().enumerate() {
            if n.name != f.package {
                continue;
            }
            let affected = n.version == f.version
                || advisory.is_some_and(|a| a.affects(eco, &n.name, &n.version));
            if affected && reached_via(&after.graph, id, &f.via.name) {
                return Err(FailReason::StillVulnerable {
                    package: n.name.clone(),
                    version: n.version.clone(),
                });
            }
        }
    }
    Ok(())
}

/// `(advisory id or alias, package)` for every vulnerable node of a scan.
fn vulnerable_pairs(eco: &dyn Ecosystem, scan: &Scan) -> HashSet<(String, String)> {
    let mut out = HashSet::new();
    for v in osv::vulnerabilities_for(&scan.graph, eco, &scan.advisories) {
        let package = &scan.graph.node(v.node).name;
        for &i in &v.advisories {
            let a = &scan.advisories[i];
            for id in std::iter::once(&a.id).chain(&a.aliases) {
                out.insert((id.clone(), package.clone()));
            }
        }
    }
    out
}

fn check_new_vulnerabilities(
    ctx: &VerifyContext,
    before: &Scan,
    after: &Scan,
) -> Result<(), FailReason> {
    let old = vulnerable_pairs(ctx.eco, before);
    let today = rules::today(ctx.now);
    for v in osv::vulnerabilities_for(&after.graph, ctx.eco, &after.advisories) {
        let node = after.graph.node(v.node);
        for &i in &v.advisories {
            let a = &after.advisories[i];
            let known = std::iter::once(&a.id)
                .chain(&a.aliases)
                .any(|id| old.contains(&(id.clone(), node.name.clone())));
            let ignored = matches!(
                rules::ignore_match(a, ctx.ignores, today),
                IgnoreMatch::Active(_)
            );
            if known || ignored || !rules::severity_ok(a.severity, ctx.policy.min_severity) {
                continue;
            }
            return Err(FailReason::NewVulnerabilityIntroduced {
                advisory: a.id.clone(),
                package: node.name.clone(),
                version: node.version.clone(),
            });
        }
    }
    Ok(())
}

/// Update outcomes of findings that are still `Planned`. With `baseline`
/// set, all of them fail with it.
fn set_outcomes(
    plan: &mut ProjectPlan,
    kept: &[Change],
    failed: &HashMap<Change, FailReason>,
    baseline: Option<&FailReason>,
) {
    for f in &mut plan.findings {
        let Outcome::Planned { strategy, change } = &f.outcome else {
            continue;
        };
        let reason = baseline.or_else(|| failed.get(change));
        if let Some(reason) = reason {
            f.outcome = Outcome::Failed {
                reason: reason.clone(),
            };
        } else if kept.contains(change) {
            f.outcome = Outcome::Fixed {
                strategy: *strategy,
                change: change.clone(),
            };
        }
    }
}

/// Short human description for progress output.
fn describe_reason(r: &FailReason) -> String {
    match r {
        FailReason::BaselineFailed { step, command, .. } => {
            format!("baseline {} failed: `{command}`", step_name(*step))
        }
        FailReason::Timeout {
            command,
            after_secs,
            ..
        } => format!("`{command}` timed out after {after_secs}s"),
        FailReason::InstallFailed { command, .. }
        | FailReason::BuildFailed { command, .. }
        | FailReason::TestFailed { command, .. } => format!("{}: `{command}`", r.kind()),
        FailReason::Error { message } => format!("error: {message}"),
        other => format!("{other:?}"),
    }
}

fn step_name(step: Step) -> &'static str {
    match step {
        Step::Apply => "apply",
        Step::Install => "install",
        Step::Build => "build",
        Step::Test => "test",
    }
}

// ---- Commands ------------------------------------------------------------------------

/// Outcome of one shell command.
enum Run {
    Ok,
    Failed {
        exit_code: Option<i32>,
        log_tail: String,
    },
    TimedOut {
        after_secs: u64,
        log_tail: String,
    },
}

/// Run install, build and test in `dir`. `baseline` selects the failure
/// reason (`BaselineFailed` vs `InstallFailed`/`BuildFailed`/...).
fn run_steps(ctx: &VerifyContext, dir: &Path, baseline: bool) -> Result<(), FailReason> {
    let c = &ctx.commands;
    let steps = [
        (Step::Install, &c.install),
        (Step::Build, &c.build),
        (Step::Test, &c.test),
    ];
    for (step, command) in steps {
        let Some(command) = command else { continue };
        let command = command.clone();
        let (exit_code, log_tail) = match run_shell(dir, &command, ctx.timeout) {
            Run::Ok => continue,
            Run::Failed {
                exit_code,
                log_tail,
            } => (exit_code, log_tail),
            Run::TimedOut {
                after_secs,
                log_tail,
            } => {
                if !baseline {
                    return Err(FailReason::Timeout {
                        step,
                        command,
                        after_secs,
                    });
                }
                (
                    None,
                    format!("{log_tail}\n[mendr] timed out after {after_secs}s"),
                )
            }
        };
        return Err(match (baseline, step) {
            (true, _) => FailReason::BaselineFailed {
                step,
                command,
                exit_code,
                log_tail,
            },
            (false, Step::Install) => FailReason::InstallFailed {
                command,
                exit_code,
                log_tail,
            },
            (false, Step::Build) => FailReason::BuildFailed {
                command,
                exit_code,
                log_tail,
            },
            (false, _) => FailReason::TestFailed {
                command,
                exit_code,
                log_tail,
            },
        });
    }
    Ok(())
}

/// `sh -c command` in `dir` with stdin closed and stdout+stderr captured
/// together. On timeout the whole process group is killed.
fn run_shell(dir: &Path, command: &str, timeout: Option<Duration>) -> Run {
    use std::io::{Read, Seek};
    use std::os::unix::process::CommandExt;

    progress::detail(&format!("$ {command}"));
    let failed = |e: io::Error| Run::Failed {
        exit_code: None,
        log_tail: format!("could not run `sh -c {command}`: {e}"),
    };
    // A file (not a pipe): the command can write any amount while we poll.
    let mut log = match tempfile::tempfile() {
        Ok(f) => f,
        Err(e) => return failed(e),
    };
    let (out, err) = match (log.try_clone(), log.try_clone()) {
        (Ok(o), Ok(e)) => (o, e),
        (Err(e), _) | (_, Err(e)) => return failed(e),
    };
    let child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        // Own process group, so a timeout can kill everything it started.
        .process_group(0)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return failed(e),
    };
    let status = match timeout {
        Some(limit) => wait_with_timeout(&mut child, limit),
        None => child.wait().map(Some),
    };
    let mut text = Vec::new();
    let _ = log.rewind().and_then(|_| log.read_to_end(&mut text));
    let tail = log_tail(&String::from_utf8_lossy(&text));
    match status {
        Ok(Some(s)) if s.success() => Run::Ok,
        Ok(Some(s)) => Run::Failed {
            exit_code: s.code(),
            log_tail: tail,
        },
        Ok(None) => Run::TimedOut {
            after_secs: timeout.map_or(0, |t| t.as_secs()),
            log_tail: tail,
        },
        Err(e) => failed(e),
    }
}

/// Poll until the child exits (`Some(status)`) or `limit` passes (`None`,
/// after killing its process group).
fn wait_with_timeout(child: &mut Child, limit: Duration) -> io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if start.elapsed() >= limit {
            // SAFETY: plain syscall; the child leads its own process group.
            unsafe {
                libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = child.kill();
            child.wait()?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---- Files -----------------------------------------------------------------------------

/// Copy the directory `from` to `to` (created), skipping the top-level
/// `excludes`. With `vet_links`, a symlink is recreated only if it resolves
/// inside `from` (absolute targets are re-pointed into `to`) and skipped
/// otherwise; without it symlinks are copied verbatim (for snapshots of an
/// already vetted copy). Other special files are skipped.
fn copy_tree(from: &Path, to: &Path, excludes: &[&str], vet_links: bool) -> io::Result<()> {
    let root = from.canonicalize()?;
    copy_dir(&root, &root, to, to, excludes, vet_links)
}

fn copy_dir(
    root: &Path,
    src: &Path,
    dst_root: &Path,
    dst: &Path,
    excludes: &[&str],
    vet_links: bool,
) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if excludes.iter().any(|e| name == *e) {
            continue;
        }
        let (s, d) = (entry.path(), dst.join(&name));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir(root, &s, dst_root, &d, &[], vet_links)?;
        } else if kind.is_file() {
            fs::copy(&s, &d)?;
        } else if kind.is_symlink() {
            let target = fs::read_link(&s)?;
            if !vet_links {
                std::os::unix::fs::symlink(&target, &d)?;
                continue;
            }
            match s.canonicalize() {
                Ok(resolved) if resolved.starts_with(root) => {
                    let link = if target.is_absolute() {
                        dst_root.join(resolved.strip_prefix(root).expect("checked above"))
                    } else {
                        target
                    };
                    std::os::unix::fs::symlink(link, &d)?;
                }
                _ => progress::warn(format!(
                    "not copying symlink {} -> {} (it does not resolve inside the project)",
                    s.display(),
                    target.display()
                )),
            }
        }
    }
    Ok(())
}

/// Make `dir` equal to `snapshot` again. Top-level `excludes` in `dir` are
/// left alone (the snapshot does not contain them).
fn restore(snapshot: &Path, dir: &Path, excludes: &[&str]) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if excludes.iter().any(|e| entry.file_name() == *e) {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    copy_tree(snapshot, dir, &[], false)
}

/// Relative paths of regular files (symlinks are not followed) below `root`,
/// skipping the top-level `excludes`.
fn list_files(root: &Path, excludes: &[&str]) -> io::Result<BTreeSet<PathBuf>> {
    fn walk(
        root: &Path,
        dir: &Path,
        excludes: &[&str],
        out: &mut BTreeSet<PathBuf>,
    ) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if dir == root && excludes.iter().any(|e| entry.file_name() == *e) {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(root, &entry.path(), excludes, out)?;
            } else if kind.is_file() {
                let path = entry.path();
                out.insert(path.strip_prefix(root).expect("below root").to_path_buf());
            }
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    walk(root, root, excludes, &mut out)?;
    Ok(out)
}

/// Regular files added, removed or modified between `a` and `b` (relative
/// paths, sorted), ignoring the top-level `excludes`.
fn changed_files(a: &Path, b: &Path, excludes: &[&str]) -> io::Result<Vec<PathBuf>> {
    let (fa, fb) = (list_files(a, excludes)?, list_files(b, excludes)?);
    let mut out = Vec::new();
    for rel in fa.union(&fb) {
        if !(fa.contains(rel) && fb.contains(rel))
            || fs::read(a.join(rel))? != fs::read(b.join(rel))?
        {
            out.push(rel.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::fake::{Fake, LOCKFILE};
    use crate::model::{BumpKind, Version};
    use crate::osv::OsvRecord;
    use crate::plan::{self, PlanInput};

    fn now() -> Timestamp {
        "2026-10-07T00:00:00Z".parse().unwrap()
    }

    /// OSV record `id` on `pkg`: affected from 0 up to `fixed` (or all versions).
    fn record(id: &str, pkg: &str, fixed: Option<&str>) -> OsvRecord {
        let mut events = vec![serde_json::json!({"introduced": "0"})];
        if let Some(f) = fixed {
            events.push(serde_json::json!({"fixed": f}));
        }
        serde_json::from_value(serde_json::json!({
            "id": id,
            "affected": [{
                "package": {"ecosystem": "Fake", "name": pkg},
                "ranges": [{"type": "SEMVER", "events": events}]
            }]
        }))
        .unwrap()
    }

    struct Setup {
        fake: Fake,
        records: Vec<OsvRecord>,
        policy: Policy,
        ignores: Vec<IgnoreRule>,
        commands: Commands,
        timeout: Option<Duration>,
    }

    /// app -> p@1.0.0 (^1) and app -> q@1.0.0 (^1); advisories P-1 (fixed in
    /// p 1.0.1) and Q-1 (fixed in q 1.0.2). Plan: relock p -> 1.0.1, then
    /// relock q -> 1.0.2.
    fn setup() -> Setup {
        let mut fake = Fake::new();
        let root = fake.root("app", "0.1.0");
        fake.dep(root, "p", "1.0.0", "^1");
        fake.dep(root, "q", "1.0.0", "^1");
        fake.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        fake.publish("q", "1.0.0", &[]).publish("q", "1.0.2", &[]);
        Setup {
            fake,
            records: vec![
                record("P-1", "p", Some("1.0.1")),
                record("Q-1", "q", Some("1.0.2")),
            ],
            policy: Policy::default(),
            ignores: Vec::new(),
            commands: Commands {
                install: None,
                build: Some("true".into()),
                test: Some("true".into()),
            },
            timeout: None,
        }
    }

    /// A command that fails when the copy's lockfile mentions `version`.
    fn unless_locked(version: &str) -> Option<String> {
        Some(format!(r#"! grep -q '"{version}"' {LOCKFILE}"#))
    }

    struct Ran {
        project: tempfile::TempDir,
        plan: ProjectPlan,
        verified: Verified,
    }

    impl Ran {
        fn labels(&self) -> Vec<(String, String)> {
            self.plan
                .findings
                .iter()
                .map(|f| (f.package.clone(), f.outcome.label()))
                .collect()
        }

        fn reason(&self, package: &str) -> &FailReason {
            let f = self.plan.findings.iter().find(|f| f.package == package);
            match f.map(|f| &f.outcome) {
                Some(Outcome::Failed { reason }) => reason,
                other => panic!("{package}: expected failed, got {other:?}"),
            }
        }

        fn write_back(&self, s: &Setup) -> Vec<PathBuf> {
            let project = ProjectConfig::at(self.project.path().to_path_buf());
            write_back(&ctx(s, &project), &self.verified).unwrap()
        }
    }

    fn ctx<'a>(s: &'a Setup, project: &'a ProjectConfig) -> VerifyContext<'a> {
        VerifyContext {
            eco: &s.fake,
            project,
            commands: s.commands.clone(),
            timeout: s.timeout,
            policy: &s.policy,
            ignores: &s.ignores,
            now: now(),
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    /// Plan against the fake's graph, then verify in a fresh project dir.
    fn run(s: &Setup) -> Ran {
        let project = tempfile::tempdir().unwrap();
        s.fake.write_lock(project.path());
        fs::create_dir_all(project.path().join("src")).unwrap();
        fs::write(project.path().join("src/main.txt"), "code").unwrap();
        let mut osv = Osv::Snapshot(s.records.clone());
        let advisories = osv
            .advisories(&s.fake, &osv::package_names(&s.fake.graph))
            .unwrap();
        let mut plan = plan::plan(&PlanInput {
            eco: &s.fake,
            graph: &s.fake.graph,
            advisories: &advisories,
            policy: &s.policy,
            ignores: &s.ignores,
            now: now(),
        });
        let config = ProjectConfig::at(project.path().to_path_buf());
        let verified = verify(&ctx(s, &config), &mut osv, &mut plan).unwrap();
        Ran {
            project,
            plan,
            verified,
        }
    }

    /// `name@version` of every non-root node in a fake lockfile.
    fn locked(lock: &[u8]) -> Vec<String> {
        let graph: DepGraph = serde_json::from_slice(lock).unwrap();
        graph
            .nodes
            .iter()
            .filter(|n| n.registry)
            .map(|n| format!("{}@{}", n.name, n.version))
            .collect()
    }

    fn kept_lock(r: &Ran) -> Vec<String> {
        locked(r.verified.files[Path::new(LOCKFILE)].as_ref().unwrap())
    }

    #[test]
    fn all_good_is_fixed_and_original_untouched() {
        let mut s = setup();
        s.commands.build = Some("echo built > out.txt".into());
        let r = run(&s);
        assert_eq!(r.labels(), labels(&[("p", "fixed"), ("q", "fixed")]));
        let Outcome::Fixed { strategy, change } = &r.plan.findings[0].outcome else {
            panic!("{:?}", r.plan.findings[0].outcome)
        };
        assert_eq!(*strategy, crate::model::Strategy::Relock);
        assert_eq!(change.to(), &Version::new("1.0.1"));

        // Release cutoff = now - 7d is passed to every apply.
        let cutoff = now()
            .checked_sub(jiff::SignedDuration::from_hours(7 * 24))
            .unwrap();
        assert_eq!(*s.fake.cutoffs.borrow(), vec![Some(cutoff), Some(cutoff)]);

        // Only the lockfile changed; the project itself was not modified.
        assert_eq!(
            r.verified.files.keys().collect::<Vec<_>>(),
            vec![Path::new(LOCKFILE)]
        );
        assert_eq!(kept_lock(&r), vec!["p@1.0.1", "q@1.0.2"]);
        let original = fs::read(r.project.path().join(LOCKFILE)).unwrap();
        assert_eq!(locked(&original), vec!["p@1.0.0", "q@1.0.0"]);
        assert!(!r.project.path().join("out.txt").exists());
    }

    #[test]
    fn write_back_copies_only_changed_files() {
        let mut s = setup();
        s.commands.build = Some("echo built > out.txt && mkdir -p dist && echo x > dist/a".into());
        let r = run(&s);
        let written = r.write_back(&s);
        assert_eq!(written, vec![r.project.path().join(LOCKFILE)]);
        let lock = fs::read(r.project.path().join(LOCKFILE)).unwrap();
        assert_eq!(locked(&lock), vec!["p@1.0.1", "q@1.0.2"]);
        assert!(!r.project.path().join("out.txt").exists());
        assert!(!r.project.path().join("dist").exists());
        assert_eq!(
            fs::read_to_string(r.project.path().join("src/main.txt")).unwrap(),
            "code"
        );
    }

    #[test]
    fn baseline_failure_fails_every_planned_finding() {
        let mut s = setup();
        s.commands.build = Some("echo broken; exit 3".into());
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[
                ("p", "failed:baseline_failed"),
                ("q", "failed:baseline_failed")
            ])
        );
        assert_eq!(
            r.reason("p"),
            &FailReason::BaselineFailed {
                step: Step::Build,
                command: "echo broken; exit 3".into(),
                exit_code: Some(3),
                log_tail: "broken".into(),
            }
        );
        assert!(s.fake.applied.borrow().is_empty(), "nothing attempted");
        assert!(r.verified.files.is_empty());
    }

    #[test]
    fn build_failure_reverts_and_others_continue() {
        let mut s = setup();
        s.commands.build = unless_locked("1.0.1"); // breaks with p@1.0.1
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "failed:build_failed"), ("q", "fixed")])
        );
        assert!(matches!(
            r.reason("p"),
            FailReason::BuildFailed {
                exit_code: Some(1),
                ..
            }
        ));
        // q was applied on the restored state: p is back at 1.0.0.
        assert_eq!(kept_lock(&r), vec!["p@1.0.0", "q@1.0.2"]);
    }

    #[test]
    fn test_failure_reverts_and_kept_changes_are_reverified() {
        let mut s = setup();
        let counter = tempfile::tempdir().unwrap();
        let count = counter.path().join("builds");
        s.commands.build = Some(format!("echo . >> '{}'", count.display()));
        s.commands.test = unless_locked("1.0.2"); // breaks with q@1.0.2
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "fixed"), ("q", "failed:test_failed")])
        );
        // Baseline, p, q, then once more for the kept p after q was reverted.
        assert_eq!(fs::read_to_string(&count).unwrap().lines().count(), 4);
        assert_eq!(kept_lock(&r), vec!["p@1.0.1", "q@1.0.0"]);
    }

    #[test]
    fn failed_combined_verification_fails_kept_changes() {
        let mut s = setup();
        let marker = tempfile::tempdir().unwrap();
        let seen_q = marker.path().join("seen-q");
        // The q attempt leaves something behind that breaks every later run.
        s.commands.test = Some(format!(
            r#"test ! -e '{m}' || exit 1; if grep -q '"1.0.2"' {LOCKFILE}; then touch '{m}'; exit 1; fi"#,
            m = seen_q.display()
        ));
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "failed:test_failed"), ("q", "failed:test_failed")])
        );
        assert!(r.verified.files.is_empty());
    }

    #[test]
    fn timeout_kills_the_command() {
        let mut s = setup();
        s.timeout = Some(Duration::from_secs(1));
        s.commands.test = Some(format!(
            r#"if grep -q '"1.0.1"' {LOCKFILE}; then sleep 30; fi"#
        ));
        let start = Instant::now();
        let r = run(&s);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(
            r.labels(),
            labels(&[("p", "failed:timeout"), ("q", "fixed")])
        );
        assert_eq!(
            r.reason("p"),
            &FailReason::Timeout {
                step: Step::Test,
                command: s.commands.test.clone().unwrap(),
                after_secs: 1,
            }
        );
    }

    #[test]
    fn baseline_timeout_is_a_baseline_failure() {
        let mut s = setup();
        s.timeout = Some(Duration::from_secs(1));
        s.commands.install = Some("echo installing; sleep 30".into());
        let r = run(&s);
        match r.reason("p") {
            FailReason::BaselineFailed {
                step: Step::Install,
                exit_code: None,
                log_tail,
                ..
            } => assert!(
                log_tail.starts_with("installing") && log_tail.contains("timed out after 1s"),
                "{log_tail}"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn still_vulnerable_when_apply_has_no_effect() {
        let mut s = setup();
        s.fake.no_effect.push("p".into());
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "failed:still_vulnerable"), ("q", "fixed")])
        );
        assert_eq!(
            r.reason("p"),
            &FailReason::StillVulnerable {
                package: "p".into(),
                version: Version::new("1.0.0"),
            }
        );
    }

    #[test]
    fn new_vulnerability_introduced_unless_ignored() {
        let mut s = setup();
        s.fake
            .adds_on_apply
            .insert("p".into(), vec![("evil".into(), "1.0.0".into())]);
        s.fake.publish("evil", "1.0.0", &[]);
        s.records.push(record("E-1", "evil", None));
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "failed:new_vulnerability_introduced"), ("q", "fixed")])
        );
        assert_eq!(
            r.reason("p"),
            &FailReason::NewVulnerabilityIntroduced {
                advisory: "E-1".into(),
                package: "evil".into(),
                version: Version::new("1.0.0"),
            }
        );

        s.ignores.push(IgnoreRule {
            id: "E-1".into(),
            reason: "not reachable".into(),
            expires: None,
        });
        assert_eq!(run(&s).labels(), labels(&[("p", "fixed"), ("q", "fixed")]));
    }

    #[test]
    fn release_age_violation_for_new_transitive_version() {
        let mut s = setup();
        s.fake
            .adds_on_apply
            .insert("q".into(), vec![("fresh".into(), "1.0.0".into())]);
        let yesterday = now()
            .checked_sub(jiff::SignedDuration::from_hours(24))
            .unwrap();
        s.fake
            .publish_with("fresh", "1.0.0", &[], Some(yesterday), false);
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "fixed"), ("q", "failed:release_age_policy_violated")])
        );
        assert_eq!(
            r.reason("q"),
            &FailReason::ReleaseAgePolicyViolated {
                package: "fresh".into(),
                version: Version::new("1.0.0"),
                published_at: Some(yesterday),
            }
        );

        s.policy.min_release_age = Duration::ZERO;
        assert_eq!(run(&s).labels(), labels(&[("p", "fixed"), ("q", "fixed")]));
        assert_eq!(s.fake.cutoffs.borrow().last(), Some(&None));
    }

    #[test]
    fn adapter_errors_map_to_reasons() {
        let mut s = setup();
        s.fake.conflicts.push("q".into());
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "fixed"), ("q", "failed:resolution_conflict")])
        );
    }

    #[test]
    fn still_vulnerable_through_bumped_via() {
        // app -> a@1.0.0 (=1.0.0) -> p@1.0.0 (=1.0.0); a@1.1.0 needs p ^1.0.1.
        // The fake only moves `a`, so p@1.0.0 stays reachable through it.
        let mut s = setup();
        let mut fake = Fake::new();
        let root = fake.root("app", "0.1.0");
        let a = fake.dep(root, "a", "1.0.0", "=1.0.0");
        fake.dep(a, "p", "1.0.0", "=1.0.0");
        fake.publish("a", "1.0.0", &[("p", "=1.0.0")]);
        fake.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        fake.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        s.fake = fake;
        let r = run(&s);
        assert_eq!(
            r.plan.findings[0].change,
            Some(Change::DirectBump {
                package: "a".into(),
                from: Version::new("1.0.0"),
                to: Version::new("1.1.0"),
                bump: BumpKind::Minor,
            })
        );
        assert_eq!(r.labels(), labels(&[("p", "failed:still_vulnerable")]));
    }

    #[test]
    fn change_already_done_by_an_earlier_change_is_kept() {
        // p@1.0.0 via a (^1.0: relock) and via b (=1.0.0, no newer b:
        // override). The relock moves the shared node, so the override's
        // p@1.0.0 is gone when its turn comes.
        let mut s = setup();
        let mut fake = Fake::new();
        let root = fake.root("app", "0.1.0");
        let a = fake.dep(root, "a", "1.0.0", "^1");
        let p = fake.dep(a, "p", "1.0.0", "^1.0");
        let b = fake.dep(root, "b", "1.0.0", "^1");
        fake.graph
            .add_edge(b, p, crate::model::VersionReq::new("=1.0.0"));
        fake.publish("a", "1.0.0", &[("p", "^1.0")]);
        fake.publish("b", "1.0.0", &[("p", "=1.0.0")]);
        fake.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        s.fake = fake;
        let r = run(&s);
        let strategies: Vec<_> = r.plan.changes.iter().map(Change::strategy).collect();
        assert_eq!(
            strategies,
            [
                crate::model::Strategy::Relock,
                crate::model::Strategy::Override
            ]
        );
        assert_eq!(r.labels(), labels(&[("p", "fixed"), ("p", "fixed")]));
        assert_eq!(s.fake.applied.borrow().len(), 1, "override not applied");
        assert_eq!(kept_lock(&r), vec!["a@1.0.0", "p@1.0.1", "b@1.0.0"]);
    }

    #[test]
    fn copy_skips_excludes_and_outside_symlinks() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "s").unwrap();
        let project = tempfile::tempdir().unwrap();
        let p = project.path().canonicalize().unwrap();
        fs::create_dir_all(p.join("src/target")).unwrap();
        fs::create_dir_all(p.join("target/debug")).unwrap();
        fs::write(p.join("src/a.txt"), "a").unwrap();
        fs::write(p.join("target/debug/big"), "x").unwrap();
        std::os::unix::fs::symlink("src/a.txt", p.join("rel")).unwrap();
        std::os::unix::fs::symlink(p.join("src"), p.join("abs")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), p.join("out")).unwrap();
        std::os::unix::fs::symlink("../..", p.join("src/up")).unwrap();

        let dst = tempfile::tempdir().unwrap();
        let copy = dst.path().join("c");
        copy_tree(&p, &copy, &["target"], true).unwrap();
        assert!(!copy.join("target").exists());
        assert!(copy.join("src/target").is_dir(), "only top-level excludes");
        assert_eq!(fs::read_to_string(copy.join("rel")).unwrap(), "a");
        assert_eq!(fs::read_link(copy.join("abs")).unwrap(), copy.join("src"));
        assert!(fs::symlink_metadata(copy.join("out")).is_err());
        assert!(fs::symlink_metadata(copy.join("src/up")).is_err());

        // Snapshot + restore round trip; excluded dirs are left alone.
        let snap = dst.path().join("s");
        copy_tree(&copy, &snap, &["target"], false).unwrap();
        fs::write(copy.join("src/a.txt"), "changed").unwrap();
        fs::write(copy.join("new.txt"), "n").unwrap();
        fs::create_dir_all(copy.join("target")).unwrap();
        fs::write(copy.join("target/keep"), "k").unwrap();
        assert_eq!(
            changed_files(&snap, &copy, &["target"]).unwrap(),
            vec![PathBuf::from("new.txt"), PathBuf::from("src/a.txt")]
        );
        restore(&snap, &copy, &["target"]).unwrap();
        assert_eq!(
            changed_files(&snap, &copy, &["target"]).unwrap(),
            Vec::<PathBuf>::new()
        );
        assert_eq!(fs::read_to_string(copy.join("rel")).unwrap(), "a");
        assert!(copy.join("target/keep").exists());
    }
}
