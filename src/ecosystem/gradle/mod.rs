//! Gradle adapter: builds that use dependency locking (a `gradle.lockfile`
//! per project, see [`lockfile`]). Builds without one are not detected,
//! like npm projects without `package-lock.json`.
//!
//! - **Graph:** rebuilt from the lockfiles, the build's declarations and the
//!   POM dependencies of every locked version (see [`graph`]). Reading it
//!   runs no Gradle and no project code.
//! - **Versions:** Maven's version order (OSV's `Maven` ranges use it) and
//!   Gradle's version notation (see [`version`]).
//! - **Registry:** deps.dev, for versions with publish dates and each
//!   version's POM dependencies (see [`registry`]). Maven Central only.
//! - **Apply:** direct bump = rewrite the declared version in the build
//!   scripts, catalogs or `gradle.properties` (see [`declare`]); a version
//!   shared with other modules (catalog `version.ref`, variable, property)
//!   is bumped only if all of them publish the new version. Override = a `constraints {}` entry in every
//!   project that locks the vulnerable version (see [`constraints`]). Both
//!   then rewrite the lockfiles with `gradle dependencies --write-locks`,
//!   which runs the build scripts, so it goes through
//!   [`ApplyOptions::shell`]. Relock is unsupported: declared versions are
//!   exact.
//! - `ApplyOptions::release_cutoff` is ignored: Gradle cannot resolve by
//!   publish time. Verification's release-age check on the lockfile diff
//!   guards new transitive versions.
//! - Verification commands: `./gradlew` if the build has a wrapper, else
//!   `gradle` from `PATH`; `assemble`, then `test`, without a daemon.

mod constraints;
mod declare;
mod graph;
mod lockfile;
mod registry;
mod version;

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use super::{AdapterError, ApplyOptions, Commands, DeclaredDep, Ecosystem, Release, Shell};
use crate::model::{BumpKind, Change, DepGraph, Strategy, Version, VersionReq};

/// Build scripts that mark a directory as a Gradle build.
const BUILD_FILES: [&str; 4] = [
    "settings.gradle.kts",
    "settings.gradle",
    "build.gradle.kts",
    "build.gradle",
];

/// Gradle errors that mean "this change cannot be resolved".
const CONFLICT_MARKERS: [&str; 2] = ["Cannot find a version of", "Could not find "];

/// `(group:artifact, version)`.
type ModuleVersion = (String, String);

pub struct Gradle {
    /// deps.dev API base URL.
    api: String,
    releases: RefCell<HashMap<String, Rc<[Release]>>>,
    /// By `(package, version)`.
    requirements: RefCell<HashMap<ModuleVersion, Rc<[DeclaredDep]>>>,
}

impl Gradle {
    pub fn new() -> Self {
        Gradle {
            api: registry::DEFAULT_API.to_string(),
            releases: RefCell::default(),
            requirements: RefCell::default(),
        }
    }

    /// Fail if a version declaration that `package` shares with other
    /// modules (a catalog `version.ref`, script variable or property)
    /// cannot move to `to` for all of them.
    fn check_shared_ref(
        &self,
        decls: &declare::Declarations,
        package: &str,
        to: &Version,
    ) -> Result<(), AdapterError> {
        for other in decls.shared_ref_modules(package) {
            let published = self
                .releases(&other)?
                .iter()
                .any(|r| version::compare(r.version.as_str(), to.as_str()) == Ordering::Equal);
            if !published {
                return Err(AdapterError::ManifestNotEditable(format!(
                    "{package} shares its version declaration with {other}, \
                     which has no version {to}"
                )));
            }
        }
        Ok(())
    }
}

impl Default for Gradle {
    fn default() -> Self {
        Self::new()
    }
}

impl Ecosystem for Gradle {
    fn name(&self) -> &'static str {
        "gradle"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "Maven"
    }

    fn detect(&self, dir: &Path) -> bool {
        BUILD_FILES.iter().any(|f| dir.join(f).is_file()) && lockfile::exists(dir)
    }

    fn supports(&self, strategy: Strategy) -> bool {
        strategy != Strategy::Relock
    }

    fn shared_copies(&self) -> bool {
        true
    }

    fn compare(&self, a: &Version, b: &Version) -> Ordering {
        version::compare(a.as_str(), b.as_str())
    }

    fn satisfies(&self, req: &VersionReq, version: &Version) -> bool {
        version::satisfies(req.as_str(), version.as_str())
    }

    fn bump_kind(&self, from: &Version, to: &Version) -> BumpKind {
        version::bump_kind(from.as_str(), to.as_str())
    }

    fn is_prerelease(&self, version: &Version) -> bool {
        version::is_prerelease(version.as_str())
    }

    fn resolve_graph(&self, project_dir: &Path) -> Result<DepGraph, AdapterError> {
        let locks = lockfile::load_all(project_dir)?;
        let decls = declare::scan(project_dir)?;
        let declared = |module: &str| {
            decls
                .contains(module)
                .then(|| decls.version(module, &version::compare).map(str::to_string))
        };
        graph::build(
            &root_name(project_dir),
            &locks,
            &declared,
            &mut |module, version| match self.dependencies_of(module, &Version::new(version)) {
                // Not on Maven Central (private repository): no known edges.
                Err(AdapterError::NotFound(_)) => Ok(Vec::new()),
                other => other,
            },
        )
    }

    fn apply(
        &self,
        workdir: &Path,
        change: &Change,
        opts: &ApplyOptions<'_>,
    ) -> Result<(), AdapterError> {
        let shell = opts.shell.ok_or_else(|| {
            AdapterError::Unsupported(
                "updating gradle.lockfile runs the build: needs a shell".into(),
            )
        })?;
        match change {
            Change::Relock { .. } => {
                return Err(AdapterError::Unsupported("relock for Gradle".into()));
            }
            Change::DirectBump { package, to, .. } => {
                let decls = declare::scan(workdir)?;
                self.check_shared_ref(&decls, package, to)?;
                declare::bump(workdir, package, to.as_str(), &version::compare)?;
            }
            Change::Override { package, from, to } => {
                let locks = lockfile::load_all(workdir)?;
                let projects: Vec<_> = locks
                    .iter()
                    .filter(|l| l.contains(package, from.as_str()))
                    .collect();
                if projects.is_empty() {
                    return Err(AdapterError::Other(format!(
                        "no {} locks {package}@{from}",
                        lockfile::FILE
                    )));
                }
                for lock in projects {
                    if !lock.has_classpaths() {
                        return Err(AdapterError::ManifestNotEditable(format!(
                            "project `{}` has no `implementation` configuration \
                             for a constraint on {package}",
                            lock.dir.display()
                        )));
                    }
                    constraints::add(
                        workdir,
                        &lock.dir,
                        "implementation",
                        package,
                        to.as_str(),
                        &format!("mendr: {package} {from} is vulnerable"),
                    )?;
                }
            }
        }
        write_locks(workdir, shell)
    }

    fn default_commands(&self, project_dir: &Path) -> Commands {
        let gradle = gradle_command(project_dir);
        Commands {
            install: None,
            build: Some(format!("{gradle} assemble --no-daemon --console=plain")),
            test: Some(format!("{gradle} test --no-daemon --console=plain")),
        }
    }

    fn copy_excludes(&self) -> &'static [&'static str] {
        &[
            ".gradle",
            ".kotlin",
            "build",
            "buildSrc/.gradle",
            "buildSrc/.kotlin",
            "buildSrc/build",
            "build-logic/.gradle",
            "build-logic/.kotlin",
            "build-logic/build",
        ]
    }

    fn manifest_files(&self) -> &'static [&'static str] {
        &[
            "*.gradle",
            "*.gradle.kts",
            "*.versions.toml",
            "gradle.properties",
            lockfile::FILE,
        ]
    }

    fn releases(&self, package: &str) -> Result<Vec<Release>, AdapterError> {
        if let Some(r) = self.releases.borrow().get(package) {
            return Ok(r.to_vec());
        }
        let r: Rc<[Release]> = registry::releases(&self.api, package)?.into();
        self.releases
            .borrow_mut()
            .insert(package.to_string(), r.clone());
        Ok(r.to_vec())
    }

    fn dependencies_of(
        &self,
        package: &str,
        version: &Version,
    ) -> Result<Vec<DeclaredDep>, AdapterError> {
        let key = (package.to_string(), version.to_string());
        if let Some(d) = self.requirements.borrow().get(&key) {
            return Ok(d.to_vec());
        }
        let d: Rc<[DeclaredDep]> =
            registry::requirements(&self.api, package, version.as_str())?.into();
        self.requirements.borrow_mut().insert(key, d.clone());
        Ok(d.to_vec())
    }
}

/// `./gradlew` if the build has a wrapper, else `gradle` from `PATH`.
/// The project's wrapper (`./gradlew`, `gradlew.bat` on Windows), else
/// `gradle` from the PATH.
fn gradle_command(dir: &Path) -> String {
    crate::platform::wrapper_script(dir, "gradlew").unwrap_or_else(|| "gradle".to_string())
}

/// Rewrite every project lockfile for the edited build files.
fn write_locks(workdir: &Path, shell: &dyn Shell) -> Result<(), AdapterError> {
    let command = format!(
        "{} dependencies --write-locks --no-daemon --console=plain --quiet",
        gradle_command(workdir)
    );
    shell.run(workdir, &command).map_err(|e| match e {
        AdapterError::Command { stderr_tail, .. }
            if CONFLICT_MARKERS.iter().any(|m| stderr_tail.contains(m)) =>
        {
            AdapterError::ResolutionConflict(stderr_tail)
        }
        other => other,
    })
}

/// `rootProject.name` from the settings script, else the directory name.
fn root_name(dir: &Path) -> String {
    let from_settings = ["settings.gradle.kts", "settings.gradle"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(dir.join(f)).ok())
        .find_map(|text| {
            text.lines().find_map(|line| {
                let rest = line.trim().strip_prefix("rootProject.name")?;
                let value = rest.trim_start().strip_prefix('=')?.trim();
                let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'')?;
                let value = &value[1..];
                Some(value[..value.find(quote)?].to_string())
            })
        });
    from_settings.unwrap_or_else(|| {
        dir.canonicalize()
            .ok()
            .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "root".to_string())
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Records commands instead of running them; fails with `stderr`.
    #[derive(Default)]
    struct FakeShell {
        ran: RefCell<Vec<String>>,
        stderr: Option<String>,
    }

    impl Shell for FakeShell {
        fn run(&self, _dir: &Path, command: &str) -> Result<(), AdapterError> {
            self.ran.borrow_mut().push(command.to_string());
            match &self.stderr {
                None => Ok(()),
                Some(tail) => Err(AdapterError::Command {
                    command: command.to_string(),
                    exit_code: Some(1),
                    stderr_tail: tail.clone(),
                }),
            }
        }
    }

    fn write(dir: &Path, rel: &str, text: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn detection_needs_a_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let gradle = Gradle::new();
        write(d, "settings.gradle.kts", "rootProject.name = \"demo\"\n");
        assert!(!gradle.detect(d));
        write(d, "app/gradle.lockfile", "empty=compileClasspath\n");
        assert!(gradle.detect(d));
        assert_eq!(root_name(d), "demo");
        std::fs::remove_file(d.join("settings.gradle.kts")).unwrap();
        assert!(!gradle.detect(d));
    }

    #[test]
    fn commands_prefer_the_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let gradle = Gradle::new();
        let c = gradle.default_commands(dir.path());
        assert_eq!(c.install, None);
        assert_eq!(
            c.build.as_deref(),
            Some("gradle assemble --no-daemon --console=plain")
        );
        write(dir.path(), "gradlew", "#!/bin/sh\n");
        write(dir.path(), "gradlew.bat", "@echo off\n");
        let c = gradle.default_commands(dir.path());
        let wrapper = if cfg!(windows) {
            "gradlew.bat"
        } else {
            "./gradlew"
        };
        assert_eq!(
            c.test,
            Some(format!("{wrapper} test --no-daemon --console=plain"))
        );
    }

    #[test]
    fn version_semantics() {
        let g = Gradle::new();
        let v = Version::new;
        assert_eq!(g.compare(&v("1.10.0"), &v("1.9")), Ordering::Greater);
        assert!(g.satisfies(&VersionReq::new("1.9"), &v("1.9.0")));
        assert!(!g.satisfies(&VersionReq::new("1.9"), &v("1.10.0")));
        assert!(g.satisfies(&VersionReq::new(""), &v("1.10.0")));
        assert_eq!(g.bump_kind(&v("19.0"), &v("24.1.1-jre")), BumpKind::Major);
        assert!(g.is_prerelease(&v("2.0.0-RC1")));
        assert!(!g.supports(Strategy::Relock));
        assert!(g.supports(Strategy::Override));
    }

    #[test]
    fn override_adds_constraints_and_rewrites_locks() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(d, "settings.gradle.kts", "include(\"app\")\n");
        write(d, "app/build.gradle.kts", "plugins { java }\n");
        write(
            d,
            "app/gradle.lockfile",
            "g:p:1.0=compileClasspath,runtimeClasspath\n",
        );
        let shell = FakeShell::default();
        let opts = ApplyOptions {
            shell: Some(&shell),
            ..ApplyOptions::default()
        };
        let change = Change::Override {
            package: "g:p".into(),
            from: Version::new("1.0"),
            to: Version::new("1.1"),
        };
        Gradle::new().apply(d, &change, &opts).unwrap();
        let script = std::fs::read_to_string(d.join("app/build.gradle.kts")).unwrap();
        assert!(script.contains("implementation(\"g:p:1.1\")"), "{script}");
        assert_eq!(
            *shell.ran.borrow(),
            ["gradle dependencies --write-locks --no-daemon --console=plain --quiet"]
        );

        // Not locked anywhere.
        let gone = Change::Override {
            package: "g:q".into(),
            from: Version::new("1.0"),
            to: Version::new("1.1"),
        };
        assert!(Gradle::new().apply(d, &gone, &opts).is_err());
        // Without a shell nothing is run.
        assert!(matches!(
            Gradle::new().apply(d, &change, &ApplyOptions::default()),
            Err(AdapterError::Unsupported(_))
        ));
    }

    #[test]
    fn resolution_errors_become_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let shell = FakeShell {
            stderr: Some(
                "> Cannot find a version of 'g:p' that satisfies the version constraints".into(),
            ),
            ..FakeShell::default()
        };
        assert!(matches!(
            write_locks(dir.path(), &shell),
            Err(AdapterError::ResolutionConflict(_))
        ));
        let shell = FakeShell {
            stderr: Some("BUILD FAILED".into()),
            ..FakeShell::default()
        };
        assert!(matches!(
            write_locks(dir.path(), &shell),
            Err(AdapterError::Command { .. })
        ));
    }
}
