//! The `Ecosystem` trait: everything mendr needs to know about one package
//! ecosystem (Cargo, npm, ...). Planning, rules and reporting only talk to
//! this trait.
//!
//! # Adding an adapter
//!
//! 1. Create `src/ecosystem/<name>.rs` with a unit struct implementing
//!    [`Ecosystem`].
//! 2. Add `pub mod <name>;` in the "Adapter modules" block below.
//! 3. Add one line to [`ecosystems`].
//!
//! Adapters are plain, blocking code: run tools with `std::process::Command`
//! (see [`run`]), fetch with [`crate::http`], cache with [`crate::cache`].
//! They should memoize registry responses themselves (the planner calls
//! `releases` / `dependencies_of` repeatedly).

use std::cmp::Ordering;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::model::{Change, DepGraph, FailReason, Strategy, Version, VersionReq};

// ---- Adapter modules (registration point 1 of 2) ---------------------------
pub mod cargo;
// pub mod npm;     // M4
#[cfg(test)]
pub mod fake;
// -----------------------------------------------------------------------------

/// All real adapters, in detection priority order (registration point 2 of 2).
pub fn ecosystems() -> Vec<Box<dyn Ecosystem>> {
    vec![
        Box::new(cargo::Cargo::new()),
        // Box::new(npm::Npm::new()),      // M4
    ]
}

/// The adapter whose `name()` equals `name`.
pub fn by_name(name: &str) -> Option<Box<dyn Ecosystem>> {
    ecosystems().into_iter().find(|e| e.name() == name)
}

/// Names of all registered adapters (used to validate `mendr.toml`).
pub fn names() -> Vec<&'static str> {
    ecosystems().iter().map(|e| e.name()).collect()
}

/// The first registered adapter whose `detect(dir)` returns true.
pub fn detect_ecosystem(dir: &Path) -> Option<Box<dyn Ecosystem>> {
    ecosystems().into_iter().find(|e| e.detect(dir))
}

/// One published version of a package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub version: Version,
    /// Publish time, if the registry reports it. `None` counts as "too new"
    /// whenever `min-release-age` is non-zero (see `rules::release_age_ok`).
    pub published_at: Option<jiff::Timestamp>,
    pub yanked: bool,
}

/// A dependency as declared by a published package version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredDep {
    /// Real package name (Cargo: the `package = ...` name if renamed).
    pub name: String,
    pub req: VersionReq,
    /// Cargo optional deps (feature-gated), npm `optionalDependencies`.
    pub optional: bool,
}

/// Shell command lines (run with `sh -c` in the project copy) for the
/// verification steps. `None` skips the step.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commands {
    /// e.g. `npm ci --ignore-scripts`; Cargo: `None`.
    pub install: Option<String>,
    /// e.g. `cargo build --locked --all-targets`.
    pub build: Option<String>,
    /// e.g. `cargo test --locked`, `npm test`.
    pub test: Option<String>,
}

/// Errors returned by adapters.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// A tool invocation exited unsuccessfully (or could not be started).
    #[error("command `{command}` failed (exit code {exit_code:?}): {stderr_tail}")]
    Command {
        command: String,
        exit_code: Option<i32>,
        /// Last lines of stderr (see `model::log_tail`).
        stderr_tail: String,
    },
    #[error("network error: {0}")]
    Network(String),
    #[error("package `{0}` not found in registry")]
    NotFound(String),
    #[error("could not parse {what}: {message}")]
    Parse { what: String, message: String },
    /// The declaration to edit could not be located or rewritten.
    #[error("manifest not editable: {0}")]
    ManifestNotEditable(String),
    /// The package manager rejected the change (conflicting requirements,
    /// peer dependency errors).
    #[error("resolution conflict: {0}")]
    ResolutionConflict(String),
    /// The adapter does not implement this operation/strategy.
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl AdapterError {
    /// Map an `apply` / `resolve_graph` error to the report's failure reason.
    pub fn to_fail_reason(&self) -> FailReason {
        match self {
            AdapterError::ManifestNotEditable(detail) => FailReason::ManifestNotEditable {
                detail: detail.clone(),
            },
            AdapterError::ResolutionConflict(detail) => FailReason::ResolutionConflict {
                detail: detail.clone(),
            },
            other => FailReason::Error {
                message: other.to_string(),
            },
        }
    }
}

impl From<crate::http::HttpError> for AdapterError {
    fn from(e: crate::http::HttpError) -> Self {
        match e {
            crate::http::HttpError::NotFound(url) => AdapterError::NotFound(url),
            other => AdapterError::Network(other.to_string()),
        }
    }
}

/// One package ecosystem. Implementations are stateless or hold only caches
/// (use `RefCell`/`Mutex` for memoization behind `&self`).
///
/// All methods are blocking. Must stay object-safe (`Box<dyn Ecosystem>`).
/// Options for [`Ecosystem::apply`].
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Newest publish time a resolver may pick (`now - min-release-age`).
    /// `None` when the release-age policy is disabled.
    pub release_cutoff: Option<jiff::Timestamp>,
}

pub trait Ecosystem {
    /// Short identifier used in config and reports: `"cargo"`, `"npm"`.
    fn name(&self) -> &'static str;

    /// OSV ecosystem string: `"crates.io"`, `"npm"`.
    fn osv_ecosystem(&self) -> &'static str;

    /// Whether `dir` contains a project of this ecosystem (e.g. `Cargo.toml`
    /// + `Cargo.lock`). Must be cheap and must not run tools.
    fn detect(&self, dir: &Path) -> bool;

    /// Whether this ecosystem can apply changes of this strategy at all.
    /// The planner never proposes an unsupported strategy.
    fn supports(&self, strategy: Strategy) -> bool;

    // ---- Version semantics -------------------------------------------------

    /// Total order on versions. Unparseable versions must still get a
    /// deterministic order (e.g. fall back to string comparison).
    fn compare(&self, a: &Version, b: &Version) -> Ordering;

    /// Whether `version` satisfies the declared requirement `req`, using the
    /// package manager's own rules (including prerelease handling).
    fn satisfies(&self, req: &VersionReq, version: &Version) -> bool;

    /// Size of the change `from -> to` (`to` > `from`). 0.x-aware for
    /// semver ecosystems: `0.1.2 -> 0.2.0` is `Major`.
    fn bump_kind(&self, from: &Version, to: &Version) -> crate::model::BumpKind;

    /// Whether `version` is a prerelease. The planner never picks a
    /// prerelease as a fix target unless the current version is one.
    fn is_prerelease(&self, version: &Version) -> bool;

    // ---- Project -------------------------------------------------------------

    /// Resolve the project's full dependency graph from its manifest +
    /// lockfile (see the invariants on [`DepGraph`]). May run the native tool
    /// (e.g. `cargo metadata`) but must not modify `project_dir` and must not
    /// run build scripts.
    fn resolve_graph(&self, project_dir: &Path) -> Result<DepGraph, AdapterError>;

    /// Apply one change inside `workdir` (always a temporary copy, never the
    /// user's checkout): edit manifests and update the lockfile. Must not run
    /// install scripts. Adapters whose resolver can honour
    /// `opts.release_cutoff` (e.g. `npm --before`) should pass it on.
    fn apply(
        &self,
        workdir: &Path,
        change: &Change,
        opts: &ApplyOptions,
    ) -> Result<(), AdapterError>;

    /// Default install/build/test commands for this project. Overridden per
    /// field by `[[project]]` config.
    fn default_commands(&self, project_dir: &Path) -> Commands;

    /// Top-level directory names to skip when copying the project to a
    /// temporary directory (`["target"]`, `["node_modules"]`).
    fn copy_excludes(&self) -> &'static [&'static str];

    // ---- Registry --------------------------------------------------------------

    /// All published versions of `package` (any order, including yanked).
    fn releases(&self, package: &str) -> Result<Vec<Release>, AdapterError>;

    /// Dependencies declared by `package@version` that a consumer would
    /// resolve: Cargo normal + build deps (all targets), npm `dependencies` +
    /// `optionalDependencies` + `peerDependencies`. Never dev-dependencies.
    fn dependencies_of(
        &self,
        package: &str,
        version: &Version,
    ) -> Result<Vec<DeclaredDep>, AdapterError>;
}

/// Run a command, returning stdout on success. On failure (or if the program
/// cannot be started) returns [`AdapterError::Command`] with the stderr tail.
pub fn run(cmd: &mut Command) -> Result<String, AdapterError> {
    let command = describe(cmd);
    let output = cmd.output().map_err(|e| AdapterError::Command {
        command: command.clone(),
        exit_code: None,
        stderr_tail: e.to_string(),
    })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(AdapterError::Command {
            command,
            exit_code: output.status.code(),
            stderr_tail: crate::model::log_tail(&String::from_utf8_lossy(&output.stderr)),
        })
    }
}

/// Human-readable `program arg1 arg2` for logs and errors.
pub fn describe(cmd: &Command) -> String {
    let mut s = cmd.get_program().to_string_lossy().into_owned();
    for arg in cmd.get_args() {
        s.push(' ');
        s.push_str(&arg.to_string_lossy());
    }
    s
}

/// Convenience: `dir.join(name).is_file()` for every name.
pub fn has_files(dir: &Path, names: &[&str]) -> bool {
    names.iter().all(|n| dir.join(n).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_reports_failures() {
        let out = run(Command::new("sh").args(["-c", "echo hi"])).unwrap();
        assert_eq!(out.trim(), "hi");
        let err = run(Command::new("sh").args(["-c", "echo oops >&2; exit 3"])).unwrap_err();
        match err {
            AdapterError::Command {
                exit_code,
                stderr_tail,
                ..
            } => {
                assert_eq!(exit_code, Some(3));
                assert_eq!(stderr_tail.trim(), "oops");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(run(&mut Command::new("/nonexistent/program")).is_err());
    }

    #[test]
    fn fake_is_object_safe() {
        let e: Box<dyn Ecosystem> = Box::new(fake::Fake::new());
        assert_eq!(e.name(), "fake");
    }
}
