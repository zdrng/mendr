//! Verification of planned changes.
//!
//! 1. Copy `project.path` to a temp dir: top-level `eco.copy_excludes()`
//!    and `.git` / `node_modules` at any depth ([`SKIP_ANYWHERE`]) are
//!    skipped; symlinks are recreated only when they resolve inside the
//!    project (absolute ones are re-pointed into the copy), all others are
//!    skipped, so nothing outside the tree is reachable through the copy.
//! 2. Baseline: run `commands.install`, `build`, `test` (`sh -c`, cwd = copy,
//!    `project.timeout` per command, each in its own process group that is
//!    killed when the command ends, so background processes do not survive
//!    it; see [`install_signal_handlers`] for Ctrl-C). If anything fails,
//!    every finding that has a change becomes `Failed { BaselineFailed }`
//!    and nothing else runs.
//!    Then resolve the graph and scan it (the "current" state).
//! 3. For each change in `plan.changes` (in order), on top of the changes
//!    kept so far: snapshot the files `apply` may touch (named like one of
//!    `eco.manifest_files()`, at any depth; all files if empty) ->
//!    `eco.apply(copy, change, &ApplyOptions { release_cutoff })`
//!    (error -> `AdapterError::to_fail_reason`)
//!    -> record the files `apply` changed -> `eco.resolve_graph(copy)` ->
//!    release-age check on every registry package version that is new in the
//!    graph (`ReleaseAgePolicyViolated`; unknown publish date fails closed)
//!    -> rescan with `osv.advisories` + `osv::vulnerabilities_for` (a finding
//!    of this change still reachable through its `via` -> `StillVulnerable`;
//!    an advisory/package pair that was not there before and is neither
//!    ignored nor below `min-severity` -> `NewVulnerabilityIntroduced`) ->
//!    install/build/test (`InstallFailed`/`BuildFailed`/`TestFailed`/`Timeout`).
//!    Keep on success, otherwise restore the snapshotted files (other state
//!    the commands left behind stays, see 4). A failing change never
//!    stops the others. A change whose `package@from` is no longer in the
//!    graph (moved by an earlier kept change) is not applied: it is kept if
//!    the rescan shows its findings fixed, else `StillVulnerable`.
//! 4. Because changes are applied cumulatively, the last kept change was
//!    already built and tested together with all earlier kept ones. Only if
//!    a later attempt was reverted after its commands ran (they may have left
//!    state behind, e.g. in `node_modules` or build output) are
//!    install/build/test run once more on the combined state; if that fails,
//!    every kept change fails
//!    with that reason and nothing is written back.
//! 5. Findings whose `change` was kept become `Outcome::Fixed { strategy,
//!    change }`; others become `Outcome::Failed { reason }` with the reason of
//!    their change. Skipped/failed findings from planning are left untouched.
//!
//! `--write` ([`write_back`]) copies back exactly the files `apply` changed
//! for the kept changes, with their content captured right after `apply`
//! (before any build ran), so build and test output never reaches the user's
//! project. It refuses if any of these files changed since the copy, and
//! replaces them by renaming temp files written next to them.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
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
    /// The same paths with their content when the project was copied
    /// (`None` = did not exist). [`write_back`] refuses to overwrite files
    /// that no longer match.
    pub originals: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

/// Verify `plan.changes` in a temporary copy and update every finding's
/// `outcome` in place (`Planned` -> `Fixed` / `Failed`). Never touches
/// `ctx.project.path`. An `Err` means verification could not run at all
/// (e.g. the copy failed); per-change problems are recorded as outcomes.
pub fn verify(ctx: &VerifyContext, osv: &mut Osv, plan: &mut ProjectPlan) -> Result<Verified> {
    // A signal now unwinds at the next check, which removes the temp dir.
    let _defer = defer_signals();
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
    copy_tree(&root, &work, excludes)
        .with_context(|| format!("copying {} to {}", root.display(), work.display()))?;
    // The user's files as we copied them, before any command ran.
    let originals =
        snapshot(Tracked::of(ctx.eco), &work).context("snapshotting the project copy")?;

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
        check_interrupted();
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
        let snap =
            snapshot(Tracked::of(ctx.eco), &work).context("snapshotting the project copy")?;
        match try_change(ctx, osv, &work, &snap, change, &findings, &current) {
            Ok((after, changed)) => {
                step.done("Kept", change);
                current = after;
                files.extend(changed);
                kept.push(change.clone());
                dirty = false;
            }
            Err(Reverted {
                reason,
                ran_commands,
            }) => {
                step.failed(
                    "Reverted",
                    format!("{change}: {}", describe_reason(&reason)),
                );
                restore(Tracked::of(ctx.eco), &work, &snap)
                    .context("restoring the project copy")?;
                failed.insert(change.clone(), reason);
                dirty |= ran_commands;
            }
        }
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

    check_interrupted();
    set_outcomes(plan, &kept, &failed, None);
    let originals = files
        .keys()
        .map(|rel| (rel.clone(), originals.get(rel).cloned()))
        .collect();
    Ok(Verified { files, originals })
}

/// `--write`: write the files changed by the kept changes (manifests and
/// lockfiles, as captured right after `apply`) into the project. Returns the
/// paths written or removed.
///
/// Refuses (writing nothing) if any of these files changed since the
/// project was copied. New contents are first written to temp files next
/// to their targets, then renamed over them, then deletions are done: a
/// failure while preparing leaves the project untouched.
pub fn write_back(ctx: &VerifyContext, verified: &Verified) -> Result<Vec<PathBuf>> {
    use std::os::unix::fs::PermissionsExt;

    // Not interrupted half-way: a signal takes effect afterwards.
    let _defer = defer_signals();
    check_interrupted();
    let root = &ctx.project.path;

    let mut changed = Vec::new();
    for rel in verified.files.keys() {
        let path = root.join(rel);
        let now = read_if_exists(&path).with_context(|| format!("reading {}", path.display()))?;
        if verified.originals.get(rel).cloned().flatten() != now {
            changed.push(format!("  - {}", path.display()));
        }
    }
    if !changed.is_empty() {
        anyhow::bail!(
            "not writing back: these files changed since mendr copied the project\n{}\n\
             Re-run mendr on the current state.",
            changed.join("\n")
        );
    }

    let mut staged = Vec::new();
    let mut removals = Vec::new();
    for (rel, content) in &verified.files {
        let path = root.join(rel);
        let Some(bytes) = content else {
            if path.exists() {
                removals.push(path);
            }
            continue;
        };
        let stage = || -> io::Result<tempfile::NamedTempFile> {
            let parent = path.parent().unwrap_or(root);
            fs::create_dir_all(parent)?;
            let mut tmp = tempfile::Builder::new()
                .prefix(".mendr-")
                .tempfile_in(parent)?;
            io::Write::write_all(&mut tmp, bytes)?;
            let mode = fs::metadata(&path).map_or(0o644, |m| m.permissions().mode() & 0o7777);
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(mode))?;
            Ok(tmp)
        };
        let tmp = stage().with_context(|| format!("preparing {}", path.display()))?;
        staged.push((tmp, path));
    }

    let mut written = Vec::new();
    for (tmp, path) in staged {
        tmp.persist(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        written.push(path);
    }
    for path in removals {
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        written.push(path);
    }
    written.sort();
    Ok(written)
}

/// The content of `path`, `None` if it does not exist.
fn read_if_exists(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

// ---- One change ------------------------------------------------------------------

/// The graph of the project copy and the advisories for its packages.
struct Scan {
    graph: DepGraph,
    advisories: Vec<Advisory>,
}

/// Files that differ from a snapshot, with their new content; `None` =
/// deleted.
type ChangedFiles = Vec<(PathBuf, Option<Vec<u8>>)>;

/// A change that was not kept.
struct Reverted {
    reason: FailReason,
    /// Whether install/build/test ran for it (and may have left state
    /// behind in the copy).
    ran_commands: bool,
}

fn try_change(
    ctx: &VerifyContext,
    osv: &mut Osv,
    work: &Path,
    snap: &Snapshot,
    change: &Change,
    findings: &[&Finding],
    before: &Scan,
) -> Result<(Scan, ChangedFiles), Reverted> {
    let (after, changed) = apply_and_check(ctx, osv, work, snap, change, findings, before)
        .map_err(|reason| Reverted {
            reason,
            ran_commands: false,
        })?;
    run_steps(ctx, work, false).map_err(|reason| Reverted {
        reason,
        ran_commands: true,
    })?;
    Ok((after, changed))
}

/// Apply `change`, record the files it changed, rescan and run the checks
/// that need no build.
fn apply_and_check(
    ctx: &VerifyContext,
    osv: &mut Osv,
    work: &Path,
    snap: &Snapshot,
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
    let now = snapshot(Tracked::of(ctx.eco), work)
        .map_err(|e| error(format!("comparing the project copy: {e}")))?;
    let changed = diff(snap, &now);
    let after = scan(ctx, osv, work)?;
    check_release_age(ctx, &before.graph, &after.graph)?;
    check_still_vulnerable(ctx.eco, findings, &after)?;
    check_new_vulnerabilities(ctx, before, &after)?;
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
/// together, in its own process group. When the command exits, times out
/// or mendr is interrupted, the whole group is killed, so nothing it
/// started in the background keeps running in the copy. A zero timeout
/// counts as none. On an interrupt this unwinds (see [`check_interrupted`]).
fn run_shell(dir: &Path, command: &str, timeout: Option<Duration>) -> Run {
    use std::os::unix::process::CommandExt;

    check_interrupted();
    let timeout = timeout.filter(|t| !t.is_zero());
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
        // Own process group, so we can kill everything it started.
        .process_group(0)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return failed(e),
    };
    let group = child.id() as libc::pid_t;
    CHILD_GROUP.store(group, Ordering::SeqCst);
    let status = wait_for(&mut child, timeout, &SIGNAL);
    kill_group(group);
    CHILD_GROUP.store(0, Ordering::SeqCst);
    check_interrupted();
    let tail = read_tail(&mut log);
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

/// How long a command may take to exit after mendr was interrupted (the
/// signal handler forwards the signal to its group) before it is killed.
const INTERRUPT_GRACE: Duration = Duration::from_secs(1);

/// Poll until the child exits (`Some(status)`), or `limit` passes or
/// `signal` is set (plus [`INTERRUPT_GRACE`]): then kill its process group
/// and return `None`.
fn wait_for(
    child: &mut Child,
    limit: Option<Duration>,
    signal: &AtomicI32,
) -> io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    let mut interrupted_at = None;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if signal.load(Ordering::SeqCst) != 0 {
            interrupted_at.get_or_insert_with(Instant::now);
        }
        let interrupted = interrupted_at.is_some_and(|t: Instant| t.elapsed() >= INTERRUPT_GRACE);
        if interrupted || limit.is_some_and(|l| start.elapsed() >= l) {
            kill_group(child.id() as libc::pid_t);
            let _ = child.kill();
            child.wait()?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// SIGKILL every process left in process group `group`.
fn kill_group(group: libc::pid_t) {
    // SAFETY: plain syscall. The group id is the pid of a child we spawned
    // as a group leader; it cannot be reused while any member is alive, and
    // reuse right after the last one exited would need a pid wraparound
    // within microseconds.
    unsafe {
        libc::killpg(group, libc::SIGKILL);
    }
}

/// [`log_tail`] of the command output in `log`, reading at most the last
/// 64 KiB of it.
fn read_tail(log: &mut fs::File) -> String {
    use std::io::{Read, Seek, SeekFrom};

    const MAX: u64 = 64 * 1024;
    let len = log.seek(SeekFrom::End(0)).unwrap_or(0);
    let start = len.saturating_sub(MAX);
    let mut bytes = Vec::new();
    let _ = log
        .seek(SeekFrom::Start(start))
        .and_then(|_| log.read_to_end(&mut bytes));
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 {
        // Drop the (probably cut) first line.
        let cut = text.find('\n').map_or(text.len(), |i| i + 1);
        text.drain(..cut);
    }
    log_tail(&text)
}

// ---- Interrupts ------------------------------------------------------------------------

/// The signal that interrupted mendr (0 = none yet).
static SIGNAL: AtomicI32 = AtomicI32::new(0);
/// Process group of the command running right now (0 = none).
static CHILD_GROUP: AtomicI32 = AtomicI32::new(0);
/// Number of active [`DeferSignals`] guards.
static DEFERRING: AtomicUsize = AtomicUsize::new(0);

/// Unwind payload of an interrupted run; see [`catch_interrupt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupted(pub i32);

impl Interrupted {
    /// Conventional exit code: 128 + signal number (130 for SIGINT, 143 for
    /// SIGTERM, 129 for SIGHUP).
    pub fn exit_code(self) -> u8 {
        u8::try_from(128 + self.0).unwrap_or(255)
    }
}

/// Install handlers for SIGINT, SIGTERM and SIGHUP (signals that are
/// ignored at startup stay ignored). Commands run in their own process
/// group, so a terminal's Ctrl-C does not reach them; the handler forwards
/// the signal to the running command's group. Outside of [`verify`] and
/// [`write_back`] (nothing to clean up) mendr then exits at once; inside,
/// it unwinds at the next check, so the temp copy is removed and nothing
/// is half-written, and [`catch_interrupt`] turns that into an exit code.
/// A second signal exits at once.
pub fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: `on_signal` only does async-signal-safe things (atomics,
        // killpg, _exit); the sigaction structs are fully initialised.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                && old.sa_sigaction == libc::SIG_IGN
            {
                continue;
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    let group = CHILD_GROUP.load(Ordering::SeqCst);
    let first = SIGNAL
        .compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    // SAFETY: killpg and _exit are async-signal-safe.
    unsafe {
        if group > 0 {
            libc::killpg(group, sig);
        }
        if !first || DEFERRING.load(Ordering::SeqCst) == 0 {
            if group > 0 {
                libc::killpg(group, libc::SIGKILL);
            }
            libc::_exit(128 + sig);
        }
    }
}

/// While a guard is alive, a signal does not exit at once but makes
/// [`check_interrupted`] unwind.
struct DeferSignals;

fn defer_signals() -> DeferSignals {
    DEFERRING.fetch_add(1, Ordering::SeqCst);
    DeferSignals
}

impl Drop for DeferSignals {
    fn drop(&mut self) {
        DEFERRING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Unwind with [`Interrupted`] if a signal arrived. Called between steps,
/// so the temp copy (a `TempDir`) is removed on the way out.
pub fn check_interrupted() {
    let sig = SIGNAL.load(Ordering::SeqCst);
    if sig != 0 {
        unwind_interrupted(sig);
    }
}

fn unwind_interrupted(sig: i32) -> ! {
    // `resume_unwind` does not run the panic hook: no panic message.
    std::panic::resume_unwind(Box::new(Interrupted(sig)))
}

/// Run `f`, turning an unwind from [`check_interrupted`] into
/// `Err(Interrupted)`. Real panics keep unwinding.
pub fn catch_interrupt<T>(f: impl FnOnce() -> T) -> Result<T, Interrupted> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        match payload.downcast::<Interrupted>() {
            Ok(i) => *i,
            Err(other) => std::panic::resume_unwind(other),
        }
    })
}

// ---- Files -----------------------------------------------------------------------------

/// Directories skipped at any depth when copying and walking the project:
/// Git metadata (large, and may hold credentials in remote URLs) and npm
/// install trees (recreated by the install step).
const SKIP_ANYWHERE: &[&str] = &[".git", "node_modules"];

/// Whether the walk skips the entry `name` in a directory at `depth` (0 =
/// the project root).
fn skipped(name: &std::ffi::OsStr, depth: usize, excludes: &[&str]) -> bool {
    SKIP_ANYWHERE.iter().any(|e| name == *e) || (depth == 0 && excludes.iter().any(|e| name == *e))
}

/// Copy the directory `from` to `to` (created), skipping the top-level
/// `excludes` and [`SKIP_ANYWHERE`]. A symlink is recreated only if it
/// resolves inside `from` (absolute targets are re-pointed into `to`) and
/// skipped otherwise. Other special files are skipped.
fn copy_tree(from: &Path, to: &Path, excludes: &[&str]) -> io::Result<()> {
    let root = from.canonicalize()?;
    copy_dir(&root, &root, to, to, excludes, 0)
}

fn copy_dir(
    root: &Path,
    src: &Path,
    dst_root: &Path,
    dst: &Path,
    excludes: &[&str],
    depth: usize,
) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if skipped(&name, depth, excludes) {
            continue;
        }
        let (s, d) = (entry.path(), dst.join(&name));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir(root, &s, dst_root, &d, excludes, depth + 1)?;
        } else if kind.is_file() {
            fs::copy(&s, &d)?;
        } else if kind.is_symlink() {
            let target = fs::read_link(&s)?;
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

/// Contents of the files a change can touch, by path relative to the copy.
type Snapshot = BTreeMap<PathBuf, Vec<u8>>;

/// Which files [`snapshot`] takes: `Ecosystem::copy_excludes` and
/// `Ecosystem::manifest_files`.
#[derive(Clone, Copy)]
struct Tracked<'a> {
    excludes: &'a [&'a str],
    /// File names to take; empty = all.
    names: &'a [&'a str],
}

impl<'a> Tracked<'a> {
    fn of(eco: &'a dyn Ecosystem) -> Self {
        Tracked {
            excludes: eco.copy_excludes(),
            names: eco.manifest_files(),
        }
    }
}

/// The tracked regular files below `dir`.
fn snapshot(tracked: Tracked, dir: &Path) -> io::Result<Snapshot> {
    let Tracked { excludes, names } = tracked;
    let mut out = Snapshot::new();
    for rel in list_files(dir, excludes)? {
        let wanted = names.is_empty()
            || rel
                .file_name()
                .is_some_and(|n| names.iter().any(|m| n == *m));
        if wanted {
            let content = fs::read(dir.join(&rel))?;
            out.insert(rel, content);
        }
    }
    Ok(out)
}

/// Files that differ from `before` in `after`, with their content there
/// (`None` = gone).
fn diff(before: &Snapshot, after: &Snapshot) -> ChangedFiles {
    let paths: BTreeSet<&PathBuf> = before.keys().chain(after.keys()).collect();
    paths
        .into_iter()
        .filter(|p| before.get(*p) != after.get(*p))
        .map(|p| (p.clone(), after.get(p).cloned()))
        .collect()
}

/// Make the snapshotted files in `dir` equal to `snap` again: rewrite
/// changed ones, recreate deleted ones, remove new ones. Everything else
/// (build output, install trees) is left alone.
fn restore(tracked: Tracked, dir: &Path, snap: &Snapshot) -> io::Result<()> {
    for (rel, content) in diff(&snapshot(tracked, dir)?, snap) {
        let path = dir.join(&rel);
        match content {
            Some(content) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, content)?;
            }
            None => fs::remove_file(&path)?,
        }
    }
    Ok(())
}

/// Relative paths of regular files (symlinks are not followed) below `root`,
/// skipping the top-level `excludes` and [`SKIP_ANYWHERE`].
fn list_files(root: &Path, excludes: &[&str]) -> io::Result<BTreeSet<PathBuf>> {
    fn walk(
        root: &Path,
        dir: &Path,
        excludes: &[&str],
        depth: usize,
        out: &mut BTreeSet<PathBuf>,
    ) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if skipped(&entry.file_name(), depth, excludes) {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(root, &entry.path(), excludes, depth + 1, out)?;
            } else if kind.is_file() {
                let path = entry.path();
                out.insert(path.strip_prefix(root).expect("below root").to_path_buf());
            }
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    walk(root, root, excludes, 0, &mut out)?;
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
    fn write_back_refuses_when_the_project_changed() {
        let s = setup();
        let r = run(&s);
        let lock = r.project.path().join(LOCKFILE);
        assert_eq!(
            r.verified.originals[Path::new(LOCKFILE)].as_deref(),
            Some(fs::read(&lock).unwrap().as_slice())
        );
        fs::write(&lock, "edited meanwhile").unwrap();
        let project = ProjectConfig::at(r.project.path().to_path_buf());
        let err = write_back(&ctx(&s, &project), &r.verified).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("changed since mendr copied"), "{err}");
        assert!(err.contains(LOCKFILE), "{err}");
        assert_eq!(fs::read_to_string(&lock).unwrap(), "edited meanwhile");
    }

    /// `Verified` for `(path, original, new)` triples; `None` = absent.
    fn verified(files: &[(&str, Option<&str>, Option<&str>)]) -> Verified {
        let bytes = |s: &Option<&str>| s.map(|s| s.as_bytes().to_vec());
        Verified {
            files: files
                .iter()
                .map(|(p, _, new)| (PathBuf::from(p), bytes(new)))
                .collect(),
            originals: files
                .iter()
                .map(|(p, old, _)| (PathBuf::from(p), bytes(old)))
                .collect(),
        }
    }

    /// Names of all entries below `dir`, sorted.
    fn tree(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = list_files(dir, &[])
            .unwrap()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn write_back_writes_creates_and_deletes() {
        use std::os::unix::fs::PermissionsExt;

        let s = setup();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("a.lock"), "old").unwrap();
        fs::set_permissions(d.join("a.lock"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(d.join("b.json"), "b").unwrap();
        let v = verified(&[
            ("a.lock", Some("old"), Some("new")),
            ("b.json", Some("b"), None),
            ("sub/c.json", None, Some("c")),
        ]);
        let project = ProjectConfig::at(d.to_path_buf());
        let written = write_back(&ctx(&s, &project), &v).unwrap();
        assert_eq!(
            written,
            ["a.lock", "b.json", "sub/c.json"].map(|p| d.join(p))
        );
        assert_eq!(tree(d), ["a.lock", "sub/c.json"]);
        assert_eq!(fs::read_to_string(d.join("a.lock")).unwrap(), "new");
        assert_eq!(fs::read_to_string(d.join("sub/c.json")).unwrap(), "c");
        let mode = |p: &str| fs::metadata(d.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("a.lock"), 0o600, "permissions kept");
        assert_eq!(mode("sub/c.json"), 0o644);

        // Deleted meanwhile: refused too.
        let v = verified(&[
            ("a.lock", Some("new"), Some("newer")),
            ("x", Some("x"), None),
        ]);
        assert!(write_back(&ctx(&s, &project), &v).is_err());
        assert_eq!(fs::read_to_string(d.join("a.lock")).unwrap(), "new");
    }

    #[test]
    fn write_back_failure_while_preparing_writes_nothing() {
        use std::os::unix::fs::PermissionsExt;

        let s = setup();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("a.lock"), "old").unwrap();
        fs::create_dir(d.join("ro")).unwrap();
        fs::write(d.join("ro/m.json"), "m").unwrap();
        fs::set_permissions(d.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        if fs::write(d.join("ro/probe"), "").is_ok() {
            return; // running as root: permissions are not enforced
        }
        let v = verified(&[
            ("a.lock", Some("old"), Some("new")),
            ("ro/m.json", Some("m"), Some("changed")),
        ]);
        let project = ProjectConfig::at(d.to_path_buf());
        let err = write_back(&ctx(&s, &project), &v).unwrap_err();
        assert!(format!("{err:#}").contains("ro/m.json"), "{err:#}");
        fs::set_permissions(d.join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(fs::read_to_string(d.join("a.lock")).unwrap(), "old");
        assert_eq!(fs::read_to_string(d.join("ro/m.json")).unwrap(), "m");
        assert_eq!(tree(d), ["a.lock", "ro/m.json"], "no temp files left");
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

    /// Whether process `pid` still exists, waiting up to 5s for it to go.
    fn still_alive(pid: libc::pid_t) -> bool {
        let start = Instant::now();
        // SAFETY: signal 0 only checks for existence.
        while unsafe { libc::kill(pid, 0) } == 0 {
            if start.elapsed() > Duration::from_secs(5) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn read_pid(path: &Path) -> libc::pid_t {
        fs::read_to_string(path).unwrap().trim().parse().unwrap()
    }

    #[test]
    fn background_processes_do_not_outlive_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let run = run_shell(dir.path(), "sleep 30 & echo $! > bg.pid; exit 0", None);
        assert!(matches!(run, Run::Ok));
        let pid = read_pid(&dir.path().join("bg.pid"));
        assert!(!still_alive(pid), "background process {pid} survived");
    }

    #[test]
    fn zero_timeout_is_no_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let run = run_shell(dir.path(), "sleep 0.1", Some(Duration::ZERO));
        assert!(matches!(run, Run::Ok));
    }

    #[test]
    fn interrupt_kills_the_command_group() {
        use std::os::unix::process::CommandExt;

        let dir = tempfile::tempdir().unwrap();
        // The background process ignores the forwarded SIGTERM.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("(trap '' TERM; sleep 30) & echo $! > bg.pid; wait")
            .current_dir(dir.path())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid_file = dir.path().join("bg.pid");
        let signal = AtomicI32::new(0);
        let start = Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                while fs::read_to_string(&pid_file).map_or(true, |t| !t.ends_with('\n')) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                signal.store(libc::SIGTERM, Ordering::SeqCst);
            });
            let status = wait_for(&mut child, None, &signal).unwrap();
            assert_eq!(status, None);
        });
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(!still_alive(read_pid(&pid_file)));
    }

    #[test]
    fn interrupt_unwinds_and_removes_temp_dirs() {
        let parent = tempfile::tempdir().unwrap();
        let mut path = PathBuf::new();
        let result = catch_interrupt(|| {
            let tmp = tempfile::tempdir_in(parent.path()).unwrap();
            path = tmp.path().to_path_buf();
            unwind_interrupted(libc::SIGTERM);
        });
        assert_eq!(result, Err(Interrupted(libc::SIGTERM)));
        assert_eq!(Interrupted(libc::SIGTERM).exit_code(), 143);
        assert_eq!(Interrupted(libc::SIGINT).exit_code(), 130);
        assert!(!path.as_os_str().is_empty() && !path.exists());
        assert_eq!(catch_interrupt(|| 7), Ok(7));
    }

    /// End to end: mendr's signal handler, the forwarded signal, the kill
    /// of the command's group and the unwind that removes the temp dir. Runs
    /// [`signal_helper`] in a child process (signals are process-wide).
    #[test]
    fn sigterm_cleans_up_and_exits_143() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "verify::tests::signal_helper", "--ignored"])
            .arg("--test-threads=1")
            .env("MENDR_SIGNAL_TEST_DIR", dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid_file = dir.path().join("bg.pid");
        let start = Instant::now();
        while !pid_file.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "helper did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: plain syscall on our own child.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("helper did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(143));
        assert!(!still_alive(read_pid(&pid_file)));
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("work"))
            .collect();
        assert!(left.is_empty(), "temp dir left behind");
    }

    #[test]
    #[ignore = "helper process of sigterm_cleans_up_and_exits_143"]
    fn signal_helper() {
        let Some(dir) = std::env::var_os("MENDR_SIGNAL_TEST_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        install_signal_handlers();
        let result = catch_interrupt(|| {
            let _defer = defer_signals();
            let work = tempfile::Builder::new()
                .prefix("work")
                .tempdir_in(&dir)
                .unwrap();
            let pid = dir.join("bg.pid");
            let command = format!(
                "(trap '' TERM; sleep 30) & echo $! > '{p}.tmp'; mv '{p}.tmp' '{p}'; wait",
                p = pid.display()
            );
            run_shell(work.path(), &command, None);
        });
        std::process::exit(result.err().map_or(0, |i| i.exit_code().into()));
    }

    #[test]
    fn log_tail_reads_only_the_end() {
        let mut log = tempfile::tempfile().unwrap();
        let mut text = "a".repeat(100_000);
        for i in 0..50 {
            text.push_str(&format!("\nline {i}"));
        }
        io::Write::write_all(&mut log, text.as_bytes()).unwrap();
        let tail = read_tail(&mut log);
        assert_eq!(tail.lines().count(), crate::model::LOG_TAIL_LINES);
        assert!(tail.ends_with("line 49") && !tail.contains('a'), "{tail}");

        let mut log = tempfile::tempfile().unwrap();
        io::Write::write_all(&mut log, b"short\noutput\n").unwrap();
        assert_eq!(read_tail(&mut log), "short\noutput");
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
        for dir in [
            ".git/objects",
            "node_modules/x",
            "web/node_modules/y",
            "sub/.git",
        ] {
            fs::create_dir_all(p.join(dir)).unwrap();
            fs::write(p.join(dir).join("f"), "x").unwrap();
        }
        fs::write(p.join(".gitignore"), "target\n").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let copy = dst.path().join("c");
        copy_tree(&p, &copy, &["target"]).unwrap();
        assert!(!copy.join("target").exists());
        assert!(copy.join("src/target").is_dir(), "only top-level excludes");
        for skipped in [".git", "node_modules", "web/node_modules", "sub/.git"] {
            assert!(!copy.join(skipped).exists(), "{skipped} copied");
        }
        assert!(copy.join(".gitignore").is_file());
        assert_eq!(fs::read_to_string(copy.join("rel")).unwrap(), "a");
        assert_eq!(fs::read_link(copy.join("abs")).unwrap(), copy.join("src"));
        assert!(fs::symlink_metadata(copy.join("out")).is_err());
        assert!(fs::symlink_metadata(copy.join("src/up")).is_err());
    }

    #[test]
    fn snapshot_and_restore_tracked_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (rel, text) in [
            ("m.lock", "lock"),
            ("sub/m.toml", "member"),
            ("gone/m.toml", "old"),
            ("src/a.txt", "a"),
            ("target/m.lock", "excluded"),
            ("node_modules/m.toml", "excluded"),
        ] {
            fs::create_dir_all(d.join(rel).parent().unwrap()).unwrap();
            fs::write(d.join(rel), text).unwrap();
        }
        let tracked = Tracked {
            excludes: &["target"],
            names: &["m.lock", "m.toml"],
        };
        let snap = snapshot(tracked, d).unwrap();
        assert_eq!(
            snap.keys().collect::<Vec<_>>(),
            ["gone/m.toml", "m.lock", "sub/m.toml"].map(Path::new)
        );

        // What `apply` and a build could do.
        fs::write(d.join("m.lock"), "new lock").unwrap();
        fs::remove_file(d.join("gone/m.toml")).unwrap();
        fs::create_dir_all(d.join("new")).unwrap();
        fs::write(d.join("new/m.toml"), "added").unwrap();
        fs::write(d.join("src/a.txt"), "built").unwrap();
        fs::write(d.join("target/m.lock"), "changed").unwrap();
        assert_eq!(
            diff(&snap, &snapshot(tracked, d).unwrap()),
            vec![
                (PathBuf::from("gone/m.toml"), None),
                (PathBuf::from("m.lock"), Some(b"new lock".to_vec())),
                (PathBuf::from("new/m.toml"), Some(b"added".to_vec())),
            ]
        );

        restore(tracked, d, &snap).unwrap();
        assert_eq!(snapshot(tracked, d).unwrap(), snap);
        assert!(!d.join("new/m.toml").exists());
        // Untracked files are left alone.
        assert_eq!(fs::read_to_string(d.join("src/a.txt")).unwrap(), "built");
        assert_eq!(
            fs::read_to_string(d.join("target/m.lock")).unwrap(),
            "changed"
        );

        // Without names every file outside the excludes is tracked.
        let all = Tracked {
            excludes: &["target"],
            names: &[],
        };
        let snap = snapshot(all, d).unwrap();
        assert!(snap.contains_key(Path::new("src/a.txt")));
        assert!(!snap.contains_key(Path::new("node_modules/m.toml")));
        fs::write(d.join("src/a.txt"), "again").unwrap();
        restore(all, d, &snap).unwrap();
        assert_eq!(fs::read_to_string(d.join("src/a.txt")).unwrap(), "built");
    }

    #[test]
    fn no_final_rebuild_when_reverted_change_ran_no_commands() {
        let mut s = setup();
        let counter = tempfile::tempdir().unwrap();
        let count = counter.path().join("builds");
        s.commands.build = Some(format!("echo . >> '{}'", count.display()));
        s.fake.no_effect.push("q".into()); // q fails before any command
        let r = run(&s);
        assert_eq!(
            r.labels(),
            labels(&[("p", "fixed"), ("q", "failed:still_vulnerable")])
        );
        // Baseline and p only.
        assert_eq!(fs::read_to_string(&count).unwrap().lines().count(), 2);
    }
}
