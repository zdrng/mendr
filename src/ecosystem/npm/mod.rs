//! npm adapter: projects with `package.json` + `package-lock.json`
//! (lockfileVersion 2/3, or `npm-shrinkwrap.json`), including workspaces.
//! yarn and pnpm lockfiles are not supported (not detected).
//!
//! - Graph: parsed from the lockfile's `packages` map (see [`lockfile`]).
//! - Versions: npm's semver rules (see [`semver`]).
//! - Registry: full packuments, cached (see [`registry`]).
//! - Changes are resolved by npm itself, always with `--package-lock-only
//!   --ignore-scripts` and `--before=<release cutoff>`:
//!   - relock: delete the lockfile entries of `package@from` and run
//!     `npm install`, which re-resolves exactly those copies to the newest
//!     version their parents allow;
//!   - direct bump: rewrite the declared range in every local `package.json`
//!     whose dependency resolves to `package@from` (keeping the range
//!     style), then `npm install`;
//!   - override: add `"<package>@<from> - <to>": "<to>"` to the root
//!     `overrides`, then `npm install`.
//!
//!   npm's `ERESOLVE` (peer conflicts), `EOVERRIDE` and `ETARGET` errors
//!   become [`AdapterError::ResolutionConflict`].
//! - Verification commands: `npm ci` (with install scripts: verification runs
//!   build and test code anyway, inside the sandbox the safety checks
//!   require, and many packages need their install scripts), then
//!   `npm run build` / `npm test` when the project defines them.

mod lockfile;
mod manifest;
mod registry;
mod semver;

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::rc::Rc;

use serde_json::Value;

use self::manifest::{JsonFile, SpecBump};
use self::registry::PackageInfo;
use self::semver::{Range, Ver};
use super::{AdapterError, ApplyOptions, Commands, DeclaredDep, Ecosystem, Release};
use crate::model::{BumpKind, Change, DepGraph, Strategy, Version, VersionReq};

#[derive(Debug, Default)]
pub struct Npm {
    /// Packument subsets fetched in this run.
    packages: RefCell<HashMap<String, Rc<PackageInfo>>>,
}

impl Npm {
    pub fn new() -> Self {
        Self::default()
    }

    fn info(&self, name: &str) -> Result<Rc<PackageInfo>, AdapterError> {
        if let Some(info) = self.packages.borrow().get(name) {
            return Ok(info.clone());
        }
        let info = Rc::new(registry::fetch(name)?);
        self.packages
            .borrow_mut()
            .insert(name.to_string(), info.clone());
        Ok(info)
    }
}

/// The range part of a spec: `npm:name@range` -> `range` (`npm:name` -> `*`).
fn range_of(spec: &str) -> &str {
    match spec.strip_prefix("npm:") {
        Some(rest) => rest
            .get(1..)
            .and_then(|r| r.find('@'))
            .map_or("*", |at| &rest[at + 2..]),
        None => spec,
    }
}

impl Ecosystem for Npm {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, dir: &Path) -> bool {
        super::has_files(dir, &["package.json"])
            && (dir.join("package-lock.json").is_file()
                || dir.join("npm-shrinkwrap.json").is_file())
    }

    fn supports(&self, _strategy: Strategy) -> bool {
        true
    }

    fn compare(&self, a: &Version, b: &Version) -> Ordering {
        match (Ver::parse(a.as_str()), Ver::parse(b.as_str())) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.as_str().cmp(b.as_str()),
        }
    }

    fn satisfies(&self, req: &VersionReq, version: &Version) -> bool {
        match (
            Range::parse(range_of(req.as_str())),
            Ver::parse(version.as_str()),
        ) {
            (Some(range), Some(v)) => range.satisfies(&v),
            _ => false,
        }
    }

    fn bump_kind(&self, from: &Version, to: &Version) -> BumpKind {
        match (Ver::parse(from.as_str()), Ver::parse(to.as_str())) {
            (Some(a), Some(b)) => {
                super::semver_bump_kind((a.major, a.minor, a.patch), (b.major, b.minor, b.patch))
            }
            _ => BumpKind::Major,
        }
    }

    fn is_prerelease(&self, version: &Version) -> bool {
        match Ver::parse(version.as_str()) {
            Some(v) => v.is_prerelease(),
            None => version.as_str().contains('-'),
        }
    }

    fn resolve_graph(&self, project_dir: &Path) -> Result<DepGraph, AdapterError> {
        Ok(lockfile::graph(&lockfile::load(project_dir)?))
    }

    fn apply(
        &self,
        workdir: &Path,
        change: &Change,
        opts: &ApplyOptions,
    ) -> Result<(), AdapterError> {
        match change {
            Change::Relock { package, from, .. } => drop_copies(workdir, package, from)?,
            Change::DirectBump {
                package, from, to, ..
            } => bump_declarations(workdir, package, from, to)?,
            Change::Override { package, from, to } => {
                let path = workdir.join("package.json");
                let mut file = JsonFile::read(&path)?;
                manifest::add_override(&mut file.value, package, from.as_str(), to.as_str())
                    .map_err(AdapterError::ManifestNotEditable)?;
                file.write(&path)?;
            }
        }
        npm_install(workdir, opts)
    }

    fn default_commands(&self, project_dir: &Path) -> Commands {
        let scripts = std::fs::read_to_string(project_dir.join("package.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|v| v.get("scripts").cloned());
        let script = |name: &str| {
            scripts
                .as_ref()
                .and_then(|s| s.get(name))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Commands {
            install: Some("npm ci --no-audit --no-fund".into()),
            build: script("build").map(|_| "npm run build".into()),
            // `npm init`'s placeholder test script always fails.
            test: script("test")
                .filter(|s| !s.contains("no test specified"))
                .map(|_| "npm test".into()),
        }
    }

    fn copy_excludes(&self) -> &'static [&'static str] {
        &["node_modules"]
    }

    fn releases(&self, package: &str) -> Result<Vec<Release>, AdapterError> {
        Ok(self.info(package)?.releases.clone())
    }

    fn dependencies_of(
        &self,
        package: &str,
        version: &Version,
    ) -> Result<Vec<DeclaredDep>, AdapterError> {
        self.info(package)?
            .deps
            .get(version.as_str())
            .cloned()
            .ok_or_else(|| AdapterError::NotFound(format!("{package}@{version}")))
    }
}

/// Delete every installed copy of `package@from` from the lockfile, so the
/// next `npm install` re-resolves them from their parents' ranges.
fn drop_copies(workdir: &Path, package: &str, from: &Version) -> Result<(), AdapterError> {
    let path = lockfile::path(workdir);
    let mut file = JsonFile::read(&path)?;
    let lock = lockfile::load(workdir)?;
    let keys = lock.copies(package, from.as_str());
    if keys.is_empty() {
        return Err(AdapterError::Other(format!(
            "{package}@{from} is not in {}",
            path.display()
        )));
    }
    if let Some(packages) = file
        .value
        .get_mut("packages")
        .and_then(Value::as_object_mut)
    {
        for key in &keys {
            packages.shift_remove(key);
        }
    }
    file.write(&path)
}

/// Rewrite the declared range of `package` in every local `package.json`
/// whose dependency currently resolves to `package@from`.
fn bump_declarations(
    workdir: &Path,
    package: &str,
    from: &Version,
    to: &Version,
) -> Result<(), AdapterError> {
    let lock = lockfile::load(workdir)?;
    let mut edited = false;
    let mut relock = false;
    let locals = lock
        .packages
        .iter()
        .filter(|(k, e)| lockfile::is_local(k) && !k.starts_with("../") && !e.link);
    for (key, _) in locals {
        let mut names: Vec<&str> = lock
            .declared(key)
            .into_iter()
            .filter(|(name, _)| {
                lock.resolve(key, name).is_some_and(|k| {
                    lock.name_of(k) == package
                        && lock.packages[k].version.as_deref() == Some(from.as_str())
                })
            })
            .map(|(name, _)| name)
            .collect();
        names.sort_unstable();
        names.dedup();
        if names.is_empty() {
            continue;
        }
        let path = workdir.join(key).join("package.json");
        let mut file = JsonFile::read(&path)?;
        for name in names {
            for section in manifest::SECTIONS {
                let Some(slot) = file.value.get_mut(section).and_then(|s| s.get_mut(name)) else {
                    continue;
                };
                let spec = slot.as_str().unwrap_or_default().to_string();
                match manifest::bump_spec(&spec, to.as_str()) {
                    Some(SpecBump::Rewrite(new)) => *slot = Value::String(new),
                    Some(SpecBump::Keep) => relock = true,
                    None => {
                        return Err(AdapterError::ManifestNotEditable(format!(
                            "{}: `{section}.{name}` is {spec:?}, not a version range",
                            path.display()
                        )));
                    }
                }
                edited = true;
            }
        }
        file.write(&path)?;
    }
    if !edited {
        return Err(AdapterError::ManifestNotEditable(format!(
            "no package.json in the project declares {package}@{from}"
        )));
    }
    if relock {
        drop_copies(workdir, package, from)?;
    }
    Ok(())
}

/// `npm install --package-lock-only` without scripts, honouring the release
/// cutoff.
fn npm_install(workdir: &Path, opts: &ApplyOptions) -> Result<(), AdapterError> {
    let mut cmd = Command::new("npm");
    cmd.current_dir(workdir).args([
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--no-update-notifier",
    ]);
    if let Some(cutoff) = opts.release_cutoff {
        cmd.arg(format!(
            "--before={}",
            cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        ));
    }
    run_npm(&mut cmd)
}

/// npm error codes that mean "this change cannot be resolved".
const CONFLICT_CODES: [&str; 3] = ["ERESOLVE", "EOVERRIDE", "ETARGET"];

fn run_npm(cmd: &mut Command) -> Result<(), AdapterError> {
    let command = super::describe(cmd);
    let output = cmd.output().map_err(|e| AdapterError::Command {
        command: command.clone(),
        exit_code: None,
        stderr_tail: e.to_string(),
    })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(conflict(&stderr).unwrap_or_else(|| AdapterError::Command {
        command,
        exit_code: output.status.code(),
        stderr_tail: crate::model::log_tail(&stderr),
    }))
}

/// `npm error code ERESOLVE` & co. -> [`AdapterError::ResolutionConflict`].
fn conflict(stderr: &str) -> Option<AdapterError> {
    let code = stderr.lines().find_map(|l| {
        let code = l.trim().strip_prefix("npm error code ")?.trim();
        CONFLICT_CODES.contains(&code).then_some(code)
    })?;
    let detail: Vec<&str> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("npm error"))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains("complete log") && !l.contains("_logs"))
        .collect();
    Some(AdapterError::ResolutionConflict(format!(
        "npm {code}: {}",
        crate::model::log_tail(&detail.join("\n"))
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::new(s)
    }

    #[test]
    fn version_semantics() {
        let npm = Npm::new();
        let sat = |r: &str, ver: &str| npm.satisfies(&VersionReq::new(r), &v(ver));
        assert!(sat("^1.2.5", "1.2.6"));
        assert!(!sat("0.0.8", "1.2.6"));
        assert!(sat("npm:minimist@^1.2.5", "1.2.8"));
        assert!(sat("npm:@s/x@~1.0.0", "1.0.3"));
        assert!(sat("npm:minimist", "1.2.8"));
        assert!(!sat("github:a/b", "1.0.0"));
        assert!(!sat("^1", "not-a-version"));

        assert_eq!(npm.compare(&v("1.10.0"), &v("1.9.0")), Ordering::Greater);
        assert_eq!(npm.compare(&v("1.0.0-rc.1"), &v("1.0.0")), Ordering::Less);
        assert_eq!(npm.compare(&v("1.0.0"), &v("junk")), Ordering::Less);
        assert!(npm.is_prerelease(&v("2.0.0-beta.1")));
        assert!(!npm.is_prerelease(&v("2.0.0")));

        let bump = |a: &str, b: &str| npm.bump_kind(&v(a), &v(b));
        assert_eq!(bump("1.4.1", "1.4.2"), BumpKind::Patch);
        assert_eq!(bump("1.4.1", "1.5.0"), BumpKind::Minor);
        assert_eq!(bump("1.4.1", "2.0.0"), BumpKind::Major);
        assert_eq!(bump("0.1.7", "0.1.13"), BumpKind::Patch);
        assert_eq!(bump("0.0.10", "0.2.4"), BumpKind::Major);
        assert_eq!(bump("0.0.1", "0.0.3"), BumpKind::Major);
    }

    #[test]
    fn detection_and_commands() {
        let dir = tempfile::tempdir().unwrap();
        let npm = Npm::new();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"test": "echo \"Error: no test specified\" && exit 1"}}"#,
        )
        .unwrap();
        assert!(!npm.detect(dir.path()));
        std::fs::write(dir.path().join("yarn.lock"), "").unwrap();
        assert!(!npm.detect(dir.path()));
        std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        assert!(npm.detect(dir.path()));
        let c = npm.default_commands(dir.path());
        assert_eq!(c.install.as_deref(), Some("npm ci --no-audit --no-fund"));
        assert_eq!((c.build, c.test), (None, None));

        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "tsc", "test": "node test.js"}}"#,
        )
        .unwrap();
        let c = npm.default_commands(dir.path());
        assert_eq!(c.build.as_deref(), Some("npm run build"));
        assert_eq!(c.test.as_deref(), Some("npm test"));
    }

    #[test]
    fn npm_errors_map_to_conflicts() {
        let eresolve = "npm error code ERESOLVE\nnpm error ERESOLVE unable to resolve dependency tree\n\
                        npm error\nnpm error peer react@\"^18.2.0\" from react-dom@18.2.0\n\
                        npm error A complete log of this run can be found in: /x/_logs/y.log\n";
        match conflict(eresolve) {
            Some(AdapterError::ResolutionConflict(d)) => {
                assert!(d.starts_with("npm ERESOLVE: "), "{d}");
                assert!(d.contains("peer react@"), "{d}");
                assert!(!d.contains("_logs"), "{d}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(conflict("npm error code EOVERRIDE\n").is_some());
        assert!(conflict("npm error code ETARGET\n").is_some());
        assert!(conflict("npm error code E404\n").is_none());
    }

    const LOCK: &str = r#"{
      "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
      "packages": {
        "": {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"],
             "dependencies": {"jsprim": "^1.4.1"}, "devDependencies": {"mkdirp": "0.x"}},
        "node_modules/jsprim": {"version": "1.4.1", "dependencies": {"json-schema": "0.2.3"}},
        "node_modules/json-schema": {"version": "0.2.3"},
        "node_modules/mkdirp": {"version": "0.5.1", "dependencies": {"minimist": "0.0.8"}},
        "node_modules/mkdirp/node_modules/minimist": {"version": "0.0.8"},
        "node_modules/minimist": {"version": "1.2.5"},
        "node_modules/web": {"resolved": "packages/web", "link": true},
        "packages/web": {"name": "web", "version": "0.1.0",
             "dependencies": {"jsprim": "1.x", "minimist": "^1.2.0"}}
      }
    }"#;

    const ROOT: &str = "{\n    \"name\": \"app\",\n    \"version\": \"1.0.0\",\n    \"workspaces\": [\n        \"packages/*\"\n    ],\n    \"dependencies\": {\n        \"jsprim\": \"^1.4.1\"\n    },\n    \"devDependencies\": {\n        \"mkdirp\": \"0.x\"\n    }\n}\n";
    const WEB: &str = "{\n  \"name\": \"web\",\n  \"version\": \"0.1.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\",\n    \"jsprim\": \"1.x\"\n  }\n}\n";

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("packages/web")).unwrap();
        std::fs::write(dir.path().join("package-lock.json"), LOCK).unwrap();
        std::fs::write(dir.path().join("package.json"), ROOT).unwrap();
        std::fs::write(dir.path().join("packages/web/package.json"), WEB).unwrap();
        dir
    }

    fn read(dir: &tempfile::TempDir, path: &str) -> String {
        std::fs::read_to_string(dir.path().join(path)).unwrap()
    }

    #[test]
    fn direct_bump_edits_every_declaring_manifest() {
        let dir = project();
        bump_declarations(dir.path(), "jsprim", &v("1.4.1"), &v("1.4.2")).unwrap();
        assert_eq!(read(&dir, "package.json"), ROOT.replace("^1.4.1", "^1.4.2"));
        // `1.x` already allows 1.4.2: kept, and the lock entry dropped.
        assert_eq!(read(&dir, "packages/web/package.json"), WEB);
        assert!(!read(&dir, "package-lock.json").contains("node_modules/jsprim\""));

        let err = bump_declarations(dir.path(), "minimist", &v("0.0.8"), &v("0.2.4")).unwrap_err();
        assert!(matches!(err, AdapterError::ManifestNotEditable(_)), "{err}");
    }

    #[test]
    fn relock_drops_only_the_vulnerable_copies() {
        let dir = project();
        drop_copies(dir.path(), "minimist", &v("0.0.8")).unwrap();
        let lock = lockfile::load(dir.path()).unwrap();
        assert!(lock.copies("minimist", "0.0.8").is_empty());
        assert_eq!(lock.copies("minimist", "1.2.5").len(), 1);
        assert!(drop_copies(dir.path(), "minimist", &v("9.9.9")).is_err());
    }

    /// Applies each npm fixture's planned change with real npm and checks
    /// the resulting lockfile. Run with
    /// `nix develop -c cargo test npm::tests::apply -- --ignored`.
    #[test]
    #[ignore = "needs npm and network"]
    fn apply_fixture_changes() {
        let cutoff = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(7 * 24);
        let opts = ApplyOptions {
            release_cutoff: Some(cutoff),
        };
        let cases = [
            (
                "relock",
                Change::Relock {
                    package: "minimist".into(),
                    from: v("1.2.5"),
                    to: v("1.2.6"),
                },
                None,
            ),
            (
                "direct-bump",
                Change::DirectBump {
                    package: "jsprim".into(),
                    from: v("1.4.1"),
                    to: v("1.4.2"),
                    bump: BumpKind::Patch,
                },
                Some(("\"jsprim\": \"^1.4.2\"", "json-schema", "0.2.3")),
            ),
            (
                "override",
                Change::Override {
                    package: "path-to-regexp".into(),
                    from: v("0.1.7"),
                    to: v("0.1.13"),
                },
                Some(("\"path-to-regexp@0.1.7 - 0.1.13\": \"0.1.13\"", "", "")),
            ),
        ];
        let npm = Npm::new();
        for (name, change, manifest_check) in cases {
            let src = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-projects/npm")
                .join(name);
            let dir = tempfile::tempdir().unwrap();
            for file in ["package.json", "package-lock.json", "index.js", "test.js"] {
                std::fs::copy(src.join(file), dir.path().join(file)).unwrap();
            }
            let install_and_test = || {
                super::super::run(
                    Command::new("sh")
                        .args(["-c", "npm ci --no-audit --no-fund && npm test"])
                        .current_dir(dir.path()),
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            };
            install_and_test();
            npm.apply(dir.path(), &change, &opts)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            install_and_test();

            let graph = npm.resolve_graph(dir.path()).unwrap();
            let versions: Vec<&Version> = graph
                .nodes
                .iter()
                .filter(|n| n.name == change.package())
                .map(|n| &n.version)
                .collect();
            assert!(
                !versions.is_empty(),
                "{name}: {} vanished",
                change.package()
            );
            for found in versions {
                assert!(
                    npm.compare(found, change.to()).is_ge(),
                    "{name}: {} still at {found}",
                    change.package()
                );
            }
            if let Some((snippet, gone, gone_version)) = manifest_check {
                assert!(read(&dir, "package.json").contains(snippet), "{name}");
                assert!(graph.find(gone, &v(gone_version)).is_none(), "{name}");
            }
        }

        // A bump that breaks a peer requirement: ERESOLVE.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"react": "17.0.2", "react-dom": "17.0.2"}}"#,
        )
        .unwrap();
        npm_install(dir.path(), &ApplyOptions::default()).unwrap();
        let bump = Change::DirectBump {
            package: "react-dom".into(),
            from: v("17.0.2"),
            to: v("18.2.0"),
            bump: BumpKind::Major,
        };
        match npm.apply(dir.path(), &bump, &opts) {
            Err(AdapterError::ResolutionConflict(detail)) => assert!(detail.contains("ERESOLVE")),
            other => panic!("expected a resolution conflict, got {other:?}"),
        }
    }
}
