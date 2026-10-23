//! pnpm adapter: projects with `package.json` + `pnpm-lock.yaml`
//! (lockfileVersion 9), including workspaces. Changes need pnpm >= 10.
//!
//! - Graph: parsed from the lockfile (see [`lockfile`]); the requirements on
//!   edges from registry packages come from their published manifests.
//! - Versions: node-semver rules, as pnpm uses them (see [`semver`]).
//! - Registry: full packuments and version manifests, cached (see
//!   [`registry`]).
//! - Changes are resolved by pnpm itself, always with `pnpm install
//!   --lockfile-only --ignore-scripts`, the release cutoff as a non-strict
//!   `minimum-release-age` (a range with no old-enough version still
//!   resolves; verification's release-age check then reports it) and
//!   `trust-lockfile` (pnpm >= 11 would otherwise reject a lockfile that
//!   already has entries newer than the cutoff):
//!   - relock: pin every dependent of `package@from` whose declared range
//!     allows `to` to exactly `to` for one install, then unpin and install
//!     again, which records the declared ranges and keeps the versions.
//!     Packages are pinned with a parent-scoped override
//!     (`"<parent>@<version>><dep>": "<to>"`), importers by writing `to` as
//!     their spec. A plain `"<package>@<from>"` override would not do: pnpm
//!     matches override keys against declared ranges, not resolved
//!     versions, so it would also move copies of `package` at other
//!     versions (e.g. downgrade a `^1.2.0` copy at 1.2.8 to `to`);
//!   - direct bump: rewrite the declared range in every importer's
//!     `package.json` whose dependency resolves to `package@from` (keeping
//!     the range style; a range that already allows `to` is pinned as for a
//!     relock), then install;
//!   - override: add `"<parent>@<version>><dep>": "<to>"` for every package
//!     that depends on `package@from` (`"<package>@<from>": "<to>"` if an
//!     importer does) to `overrides` in `pnpm-workspace.yaml`, then install.
//!     pnpm >= 11 no longer reads `pnpm.overrides` from `package.json`.
//!
//!   pnpm's `ERR_PNPM_NO_MATCHING_VERSION`,
//!   `ERR_PNPM_NO_MATURE_MATCHING_VERSION` and `ERR_PNPM_PEER_DEP_ISSUES`
//!   become [`AdapterError::ResolutionConflict`].
//! - Verification commands: `pnpm install --frozen-lockfile` (with install
//!   scripts, as far as the project's pnpm settings allow them), then
//!   `pnpm run build` / `pnpm test` when the project defines them.

mod lockfile;
mod manifest;
mod overrides;
mod registry;

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

use serde_json::Value;

use self::lockfile::Holder;
use self::manifest::{JsonFile, SpecBump};
use self::registry::{PackageInfo, Specs};
use super::node_semver::{Range, Ver};
use super::{AdapterError, ApplyOptions, Commands, DeclaredDep, Ecosystem, Release};
use crate::model::{BumpKind, Change, DepGraph, Strategy, Version, VersionReq};

/// pnpm's settings file (workspace packages, overrides, catalogs, ...).
const WORKSPACE: &str = "pnpm-workspace.yaml";

#[derive(Debug, Default)]
pub struct Pnpm {
    /// Packument subsets fetched in this run.
    packages: RefCell<HashMap<String, Rc<PackageInfo>>>,
    /// Dependency specs of published versions fetched in this run.
    specs: RefCell<HashMap<(String, String), Option<Specs>>>,
}

impl Pnpm {
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

    /// What `name@version` declares, by dependency name; `None` if the
    /// registry does not know that version.
    fn specs(&self, name: &str, version: &Version) -> Result<Option<Specs>, AdapterError> {
        let key = (name.to_string(), version.to_string());
        if let Some(specs) = self.specs.borrow().get(&key) {
            return Ok(specs.clone());
        }
        let specs = registry::fetch_specs(name, version.as_str())?;
        self.specs.borrow_mut().insert(key, specs.clone());
        Ok(specs)
    }

    /// The file edits that make `change` in `workdir`.
    fn edits(&self, workdir: &Path, change: &Change) -> Result<Edits, AdapterError> {
        let lock = lockfile::load(workdir)?;
        let (package, from) = (change.package(), change.from());
        let holders = lock.holders(package, from.as_str());
        if holders.is_empty() {
            return Err(AdapterError::Other(format!(
                "{package}@{from} is not in {}",
                lockfile::FILE
            )));
        }
        let mut edits = Edits::default();
        match change {
            Change::Relock { to, .. } => {
                self.pin(workdir, package, &holders, to, &mut edits)?;
                if edits.is_empty() {
                    return Err(AdapterError::ResolutionConflict(format!(
                        "no dependent of {package}@{from} allows {to}"
                    )));
                }
            }
            Change::DirectBump { to, .. } => {
                bump(workdir, package, from, &holders, to, &mut edits)?
            }
            Change::Override { to, .. } => force(package, from, &holders, to, &mut edits),
        }
        Ok(edits)
    }

    /// Pin every holder whose declared range allows `to` to exactly `to`
    /// for the first install. Non-registry parents are left alone: their
    /// declared ranges are unknown.
    fn pin(
        &self,
        workdir: &Path,
        package: &str,
        holders: &[Holder],
        to: &Version,
        edits: &mut Edits,
    ) -> Result<(), AdapterError> {
        for holder in holders {
            match holder {
                Holder::Importer {
                    importer,
                    section,
                    dep,
                } => {
                    let m = edits.manifest(workdir, importer)?;
                    let Some(spec) = m.file.spec(section, dep).map(str::to_string) else {
                        continue;
                    };
                    if self.satisfies(&VersionReq::new(&spec), to)
                        && let Some(exact) = manifest::pin_spec(&spec, to.as_str())
                    {
                        m.pin(section, dep, spec, &exact);
                    }
                }
                Holder::Package {
                    name,
                    version,
                    registry: true,
                    dep,
                } => {
                    let allows = self
                        .specs(name, &Version::new(version))?
                        .and_then(|specs| specs.get(dep).cloned())
                        .is_some_and(|spec| self.satisfies(&VersionReq::new(spec), to));
                    if allows {
                        edits.pinned_overrides.push((
                            format!("{name}@{version}>{dep}"),
                            override_value(package, dep, to),
                        ));
                    }
                }
                Holder::Package { .. } => {}
            }
        }
        Ok(())
    }
}

/// An alias spec `npm:name@range` -> `(name, range)` (`npm:name` -> `*`).
fn alias(spec: &str) -> Option<(&str, &str)> {
    let rest = spec.strip_prefix("npm:")?;
    // Skip the first character: a scope's `@` is not the separator.
    Some(match rest.get(1..).and_then(|r| r.find('@')) {
        Some(at) => (&rest[..at + 1], &rest[at + 2..]),
        None => (rest, "*"),
    })
}

/// The range part of a spec: `npm:name@range` -> `range` (`npm:name` -> `*`).
fn range_of(spec: &str) -> &str {
    alias(spec).map_or(spec, |(_, range)| range)
}

impl Ecosystem for Pnpm {
    fn name(&self) -> &'static str {
        "pnpm"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, dir: &Path) -> bool {
        super::has_files(dir, &["package.json", lockfile::FILE])
    }

    fn supports(&self, _strategy: Strategy) -> bool {
        true
    }

    fn shared_copies(&self) -> bool {
        false
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
        let lock = lockfile::load(project_dir)?;
        let root_id = |importer: &str| {
            let dir = project_dir.join(importer);
            let (name, version) = manifest::identity(&dir.join("package.json"));
            let name = name.unwrap_or_else(|| {
                dir.canonicalize()
                    .ok()
                    .and_then(|d| Some(d.file_name()?.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| importer.to_string())
            });
            (name, Version::new(version.as_deref().unwrap_or("0.0.0")))
        };
        lockfile::graph(&lock, &root_id, &mut |name, version| {
            self.specs(name, version)
        })
    }

    fn apply(
        &self,
        workdir: &Path,
        change: &Change,
        opts: &ApplyOptions,
    ) -> Result<(), AdapterError> {
        self.edits(workdir, change)?
            .run(workdir, &mut || pnpm_install(workdir, opts))
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
            install: Some("pnpm install --frozen-lockfile".into()),
            build: script("build").map(|_| "pnpm run build".into()),
            // `npm init`'s placeholder test script always fails.
            test: script("test")
                .filter(|s| !s.contains("no test specified"))
                .map(|_| "pnpm test".into()),
        }
    }

    fn copy_excludes(&self) -> &'static [&'static str] {
        &["node_modules"]
    }

    fn manifest_files(&self) -> &'static [&'static str] {
        &["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"]
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

/// Rewrite the declared range of every importer that depends on
/// `package@from` (see [`Holder::Importer`]); ranges that already allow `to`
/// are pinned for the first install instead.
fn bump(
    workdir: &Path,
    package: &str,
    from: &Version,
    holders: &[Holder],
    to: &Version,
    edits: &mut Edits,
) -> Result<(), AdapterError> {
    let mut declared = false;
    for holder in holders {
        let Holder::Importer {
            importer,
            section,
            dep,
        } = holder
        else {
            continue;
        };
        let m = edits.manifest(workdir, importer)?;
        let path = Path::new(importer).join("package.json");
        let Some(spec) = m.file.spec(section, dep).map(str::to_string) else {
            return Err(AdapterError::ManifestNotEditable(format!(
                "{}: `{section}.{dep}` is in {} but not in the manifest",
                path.display(),
                lockfile::FILE
            )));
        };
        match manifest::bump_spec(&spec, to.as_str()) {
            Some(SpecBump::Rewrite(new)) => m.set(section, dep, &new),
            Some(SpecBump::Keep) => {
                if let Some(exact) = manifest::pin_spec(&spec, to.as_str()) {
                    m.pin(section, dep, spec, &exact);
                }
            }
            None => {
                let hint = if spec.starts_with("catalog:") {
                    " (pnpm catalogs are not edited)"
                } else {
                    ""
                };
                return Err(AdapterError::ManifestNotEditable(format!(
                    "{}: `{section}.{dep}` is {spec:?}, not a version range{hint}",
                    path.display()
                )));
            }
        }
        declared = true;
    }
    if !declared {
        return Err(AdapterError::ManifestNotEditable(format!(
            "no package.json in the project declares {package}@{from}"
        )));
    }
    Ok(())
}

/// The override value that makes a dependency declared as `dep` resolve to
/// `package@to`: an alias (`"mm": "npm:minimist@^1"`) stays an alias.
fn override_value(package: &str, dep: &str, to: &Version) -> String {
    if dep == package {
        to.to_string()
    } else {
        format!("npm:{package}@{to}")
    }
}

/// Override `package@from` with `to`: scoped to each parent, or for every
/// dependent if an importer depends on it directly.
fn force(package: &str, from: &Version, holders: &[Holder], to: &Version, edits: &mut Edits) {
    if holders.iter().any(|h| matches!(h, Holder::Importer { .. })) {
        edits
            .overrides
            .push((format!("{package}@{from}"), to.to_string()));
        return;
    }
    for holder in holders {
        if let Holder::Package {
            name,
            version,
            registry,
            dep,
        } = holder
        {
            // A non-registry parent's version (git, tarball) does not work
            // as a selector.
            let parent = if *registry {
                format!("{name}@{version}")
            } else {
                name.clone()
            };
            let entry = (format!("{parent}>{dep}"), override_value(package, dep, to));
            if !edits.overrides.contains(&entry) {
                edits.overrides.push(entry);
            }
        }
    }
}

/// An importer's `package.json` with the edits of one change.
struct ManifestEdits {
    file: JsonFile,
    /// Whether anything (permanent or pinned) was changed.
    edited: bool,
    /// Pinned specs: `(section, dependency, spec to restore)`.
    pins: Vec<(&'static str, String, String)>,
}

impl ManifestEdits {
    fn set(&mut self, section: &str, dep: &str, spec: &str) {
        self.file.set_spec(section, dep, spec);
        self.edited = true;
    }

    fn pin(&mut self, section: &'static str, dep: &str, original: String, exact: &str) {
        self.set(section, dep, exact);
        self.pins.push((section, dep.to_string(), original));
    }
}

/// The file edits of one change. Pins steer the first `pnpm install` and
/// are reverted before a second one.
#[derive(Default)]
struct Edits {
    /// By `package.json` path relative to the workspace root.
    manifests: BTreeMap<PathBuf, ManifestEdits>,
    /// `overrides` entries to add to `pnpm-workspace.yaml`.
    overrides: Vec<(String, String)>,
    /// `overrides` entries for the first install only.
    pinned_overrides: Vec<(String, String)>,
}

impl Edits {
    fn manifest(
        &mut self,
        workdir: &Path,
        importer: &str,
    ) -> Result<&mut ManifestEdits, AdapterError> {
        let rel = Path::new(importer).join("package.json");
        if !self.manifests.contains_key(&rel) {
            let file = JsonFile::read(&workdir.join(&rel))?;
            self.manifests.insert(
                rel.clone(),
                ManifestEdits {
                    file,
                    edited: false,
                    pins: Vec::new(),
                },
            );
        }
        Ok(self.manifests.get_mut(&rel).expect("inserted above"))
    }

    fn is_empty(&self) -> bool {
        self.overrides.is_empty()
            && self.pinned_overrides.is_empty()
            && self.manifests.values().all(|m| !m.edited)
    }

    fn has_pins(&self) -> bool {
        !self.pinned_overrides.is_empty() || self.manifests.values().any(|m| !m.pins.is_empty())
    }

    /// Write the edits and `install`. If anything was pinned: restore the
    /// pinned specs, drop the pinned overrides from `pnpm-workspace.yaml`
    /// and the lockfile, and `install` again.
    fn run(
        mut self,
        workdir: &Path,
        install: &mut dyn FnMut() -> Result<(), AdapterError>,
    ) -> Result<(), AdapterError> {
        let settings = workdir.join(WORKSPACE);
        let original = match std::fs::read_to_string(&settings) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let with = |entries: &[&(String, String)]| -> Result<Option<String>, AdapterError> {
            if entries.is_empty() {
                return Ok(original.clone());
            }
            let mut text = original.clone().unwrap_or_default();
            for (key, value) in entries {
                text = overrides::add(&text, key, value)
                    .map_err(|e| AdapterError::ManifestNotEditable(format!("{WORKSPACE}: {e}")))?;
            }
            Ok(Some(text))
        };
        let kept: Vec<&(String, String)> = self.overrides.iter().collect();
        let all: Vec<&(String, String)> =
            kept.iter().copied().chain(&self.pinned_overrides).collect();
        let (first, last) = (with(&all)?, with(&kept)?);

        write_or_remove(&settings, first.as_deref())?;
        for (rel, m) in self.manifests.iter().filter(|(_, m)| m.edited) {
            std::fs::write(workdir.join(rel), m.file.render())?;
        }
        install()?;
        if !self.has_pins() {
            return Ok(());
        }

        write_or_remove(&settings, last.as_deref())?;
        for (rel, m) in self
            .manifests
            .iter_mut()
            .filter(|(_, m)| !m.pins.is_empty())
        {
            for (section, dep, spec) in std::mem::take(&mut m.pins) {
                m.file.set_spec(section, &dep, &spec);
            }
            std::fs::write(workdir.join(rel), m.file.render())?;
        }
        if !self.pinned_overrides.is_empty() {
            let path = workdir.join(lockfile::FILE);
            let keys: Vec<String> = self
                .pinned_overrides
                .iter()
                .map(|(k, _)| k.clone())
                .collect();
            let text = std::fs::read_to_string(&path)?;
            std::fs::write(&path, overrides::remove(&text, &keys))?;
        }
        install()
    }
}

fn write_or_remove(path: &Path, content: Option<&str>) -> Result<(), AdapterError> {
    match content {
        Some(text) => std::fs::write(path, text)?,
        None if path.exists() => std::fs::remove_file(path)?,
        None => {}
    }
    Ok(())
}

/// `pnpm install --lockfile-only` without scripts, honouring the release
/// cutoff (`0` turns off pnpm's own default of one day).
fn pnpm_install(workdir: &Path, opts: &ApplyOptions) -> Result<(), AdapterError> {
    let minutes = opts.release_cutoff.map_or(0, |cutoff| {
        let secs = jiff::Timestamp::now().duration_since(cutoff).as_secs();
        (secs.max(0) + 59) / 60
    });
    let mut cmd = crate::platform::command("pnpm");
    cmd.current_dir(workdir)
        .args([
            "install",
            "--lockfile-only",
            "--ignore-scripts",
            "--no-frozen-lockfile",
            "--config.trust-lockfile=true",
            "--config.minimum-release-age-strict=false",
        ])
        .arg(format!("--config.minimum-release-age={minutes}"));
    run_pnpm(&mut cmd)
}

/// pnpm error codes that mean "this change cannot be resolved".
const CONFLICT_CODES: [&str; 3] = [
    "ERR_PNPM_NO_MATCHING_VERSION",
    "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
    "ERR_PNPM_PEER_DEP_ISSUES",
];

fn run_pnpm(cmd: &mut Command) -> Result<(), AdapterError> {
    let command = super::describe(cmd);
    crate::progress::detail(&format!("$ {command}"));
    let output = cmd.output().map_err(|e| AdapterError::Command {
        command: command.clone(),
        exit_code: None,
        stderr_tail: e.to_string(),
    })?;
    if output.status.success() {
        return Ok(());
    }
    // pnpm 10 and 11 print errors on stdout, pnpm 12 on stderr.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Err(conflict(&text).unwrap_or_else(|| AdapterError::Command {
        command,
        exit_code: output.status.code(),
        stderr_tail: crate::model::log_tail(&text),
    }))
}

/// The first `ERR_PNPM_*` code in pnpm's output: ` ERR_PNPM_X  message`
/// (pnpm 10), `[ERR_PNPM_X] message` (11), `Error: ERR_PNPM_X` (12).
fn error_code(output: &str) -> Option<&str> {
    let rest = &output[output.find("ERR_PNPM_")?..];
    let end = rest
        .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// [`CONFLICT_CODES`] -> [`AdapterError::ResolutionConflict`].
fn conflict(output: &str) -> Option<AdapterError> {
    let code = error_code(output).filter(|code| CONFLICT_CODES.contains(code))?;
    let detail: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    Some(AdapterError::ResolutionConflict(format!(
        "pnpm {code}: {}",
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
        let pnpm = Pnpm::new();
        let sat = |r: &str, ver: &str| pnpm.satisfies(&VersionReq::new(r), &v(ver));
        assert!(sat("^1.2.5", "1.2.6"));
        assert!(!sat("0.0.8", "1.2.6"));
        assert!(sat("npm:minimist@^1.2.5", "1.2.8"));
        assert!(sat("npm:@s/x@~1.0.0", "1.0.3"));
        assert!(sat("npm:minimist", "1.2.8"));
        assert_eq!(alias("npm:@s/x@~1.0.0"), Some(("@s/x", "~1.0.0")));
        assert_eq!(alias("npm:minimist"), Some(("minimist", "*")));
        assert_eq!(alias("^1.2.5"), None);
        for spec in ["github:a/b", "workspace:*", "catalog:", "link:../x"] {
            assert!(!sat(spec, "1.0.0"), "{spec}");
        }
        assert!(!sat("^1", "not-a-version"));

        assert_eq!(pnpm.compare(&v("1.10.0"), &v("1.9.0")), Ordering::Greater);
        assert_eq!(pnpm.compare(&v("1.0.0-rc.1"), &v("1.0.0")), Ordering::Less);
        assert_eq!(pnpm.compare(&v("1.0.0"), &v("junk")), Ordering::Less);
        assert!(pnpm.is_prerelease(&v("2.0.0-beta.1")));
        assert!(!pnpm.is_prerelease(&v("2.0.0")));

        let bump = |a: &str, b: &str| pnpm.bump_kind(&v(a), &v(b));
        assert_eq!(bump("1.4.1", "1.4.2"), BumpKind::Patch);
        assert_eq!(bump("1.4.1", "1.5.0"), BumpKind::Minor);
        assert_eq!(bump("1.4.1", "2.0.0"), BumpKind::Major);
        assert_eq!(bump("0.1.7", "0.1.13"), BumpKind::Patch);
        assert_eq!(bump("0.0.10", "0.2.4"), BumpKind::Major);
    }

    #[test]
    fn detection_and_commands() {
        let dir = tempfile::tempdir().unwrap();
        let pnpm = Pnpm::new();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"test": "echo \"Error: no test specified\" && exit 1"}}"#,
        )
        .unwrap();
        assert!(!pnpm.detect(dir.path()));
        std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        assert!(!pnpm.detect(dir.path()));
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        )
        .unwrap();
        assert!(pnpm.detect(dir.path()));
        let c = pnpm.default_commands(dir.path());
        assert_eq!(c.install.as_deref(), Some("pnpm install --frozen-lockfile"));
        assert_eq!((c.build, c.test), (None, None));

        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "tsc", "test": "node test.js"}}"#,
        )
        .unwrap();
        let c = pnpm.default_commands(dir.path());
        assert_eq!(c.build.as_deref(), Some("pnpm run build"));
        assert_eq!(c.test.as_deref(), Some("pnpm test"));
    }

    #[test]
    fn pnpm_errors_map_to_conflicts() {
        // pnpm 10 (stdout), 11 (stdout) and 12 (stderr).
        let outputs = [
            " ERR_PNPM_NO_MATCHING_VERSION  No matching version found for minimist@^99.0.0\n\n\
             The latest release of minimist is \"1.2.8\".\n",
            "[ERR_PNPM_NO_MATCHING_VERSION] No matching version found for minimist@^99.0.0\n",
            "Error: ERR_PNPM_NO_MATCHING_VERSION\n\n  × installing dependencies\n  \
             ╰─▶ Failed to resolve dependency tree: No matching version found for\n      \
             minimist@^99.0.0\n",
        ];
        for output in outputs {
            match conflict(output) {
                Some(AdapterError::ResolutionConflict(d)) => {
                    assert!(d.starts_with("pnpm ERR_PNPM_NO_MATCHING_VERSION: "), "{d}");
                    assert!(d.contains("minimist@^99.0.0"), "{d}");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(conflict(" ERR_PNPM_NO_MATURE_MATCHING_VERSION  Version 1.2.8").is_some());
        assert!(conflict("[ERR_PNPM_PEER_DEP_ISSUES] Unmet peer dependencies").is_some());
        assert!(conflict(" ERR_PNPM_NO_MATCHING_VERSION_INSIDE_WORKSPACE  x").is_none());
        assert!(conflict(" ERR_PNPM_FETCH_404  GET https://x: Not Found").is_none());
        assert!(conflict("something else").is_none());
        assert_eq!(error_code("Error: ERR_PNPM_X_1\n"), Some("ERR_PNPM_X_1"));
    }

    const LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      minimist:
        specifier: ^1.2.0
        version: 1.2.8
      mkdirp:
        specifier: ^0.5.5
        version: 0.5.5
      router:
        specifier: ^1.3.8
        version: 1.3.8

  packages/web:
    dependencies:
      minimist:
        specifier: 1.x
        version: 1.2.5
    devDependencies:
      mkdirp:
        specifier: 0.5.5
        version: 0.5.5

packages:

  minimist@1.2.5:
    resolution: {integrity: sha512-a}

  minimist@1.2.8:
    resolution: {integrity: sha512-b}

  mkdirp@0.5.5:
    resolution: {integrity: sha512-c}

  path-to-regexp@0.1.7:
    resolution: {integrity: sha512-d}

  router@1.3.8:
    resolution: {integrity: sha512-e}

snapshots:

  minimist@1.2.5: {}

  minimist@1.2.8: {}

  mkdirp@0.5.5:
    dependencies:
      minimist: 1.2.5

  path-to-regexp@0.1.7: {}

  router@1.3.8:
    dependencies:
      path-to-regexp: 0.1.7
";

    const ROOT: &str = "{\n    \"name\": \"app\",\n    \"dependencies\": {\n        \"minimist\": \"^1.2.0\",\n        \"mkdirp\": \"^0.5.5\",\n        \"router\": \"^1.3.8\"\n    }\n}\n";
    const WEB: &str = "{\n  \"name\": \"web\",\n  \"dependencies\": {\n    \"minimist\": \"1.x\"\n  },\n  \"devDependencies\": {\n    \"mkdirp\": \"0.5.5\"\n  }\n}\n";
    const SETTINGS: &str = "packages:\n  - 'packages/*'\n";

    /// A workspace, and an adapter that knows the published specs of its
    /// registry packages.
    fn project() -> (tempfile::TempDir, Pnpm) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("packages/web")).unwrap();
        for (path, text) in [
            ("pnpm-lock.yaml", LOCK),
            ("package.json", ROOT),
            ("packages/web/package.json", WEB),
            (WORKSPACE, SETTINGS),
        ] {
            std::fs::write(dir.path().join(path), text).unwrap();
        }
        let pnpm = Pnpm::new();
        for (name, version, dep, spec) in [
            ("mkdirp", "0.5.5", "minimist", "^1.2.5"),
            ("router", "1.3.8", "path-to-regexp", "0.1.7"),
        ] {
            let specs = Specs::from([(dep.to_string(), spec.to_string())]);
            pnpm.specs
                .borrow_mut()
                .insert((name.into(), version.into()), Some(specs));
        }
        (dir, pnpm)
    }

    fn read(dir: &tempfile::TempDir, path: &str) -> String {
        std::fs::read_to_string(dir.path().join(path)).unwrap_or_default()
    }

    /// Run the edits for `change` with a fake install that records the
    /// files it sees and records `lock_overrides` in the lockfile, as pnpm
    /// would.
    fn run(
        dir: &tempfile::TempDir,
        pnpm: &Pnpm,
        change: &Change,
        lock_overrides: &str,
    ) -> Result<Vec<[String; 4]>, AdapterError> {
        let edits = pnpm.edits(dir.path(), change)?;
        let mut seen = Vec::new();
        edits.run(dir.path(), &mut || {
            let lock = read(dir, "pnpm-lock.yaml");
            if seen.is_empty() && !lock_overrides.is_empty() {
                let lock = lock.replace("importers:", &format!("{lock_overrides}\nimporters:"));
                std::fs::write(dir.path().join("pnpm-lock.yaml"), lock).unwrap();
            }
            seen.push([
                read(dir, "package.json"),
                read(dir, "packages/web/package.json"),
                read(dir, WORKSPACE),
                read(dir, "pnpm-lock.yaml"),
            ]);
            Ok(())
        })?;
        Ok(seen)
    }

    #[test]
    fn relock_pins_every_dependent_that_allows_the_fix_once() {
        let (dir, pnpm) = project();
        let relock = Change::Relock {
            package: "minimist".into(),
            from: v("1.2.5"),
            to: v("1.2.6"),
        };
        let seen = run(
            &dir,
            &pnpm,
            &relock,
            "overrides:\n  mkdirp@0.5.5>minimist: 1.2.6\n",
        )
        .unwrap();
        assert_eq!(seen.len(), 2);
        let [root, web, settings, _] = &seen[0];
        assert_eq!(root, ROOT);
        assert_eq!(web, &WEB.replace("\"1.x\"", "\"1.2.6\""));
        assert_eq!(
            settings,
            &format!("{SETTINGS}overrides:\n  'mkdirp@0.5.5>minimist': '1.2.6'\n")
        );
        // Unpinned for the second install; the temporary override is gone
        // from the lockfile too.
        assert_eq!(seen[1], [ROOT, WEB, SETTINGS, LOCK].map(str::to_string));

        // Nobody's range allows the target.
        let relock = Change::Relock {
            package: "minimist".into(),
            from: v("1.2.5"),
            to: v("2.0.0"),
        };
        match pnpm.edits(dir.path(), &relock) {
            Err(AdapterError::ResolutionConflict(d)) => assert!(d.contains("allows 2.0.0"), "{d}"),
            other => panic!("unexpected {:?}", other.err()),
        }
    }

    #[test]
    fn direct_bump_rewrites_every_declaring_manifest() {
        let (dir, pnpm) = project();
        let bump = Change::DirectBump {
            package: "mkdirp".into(),
            from: v("0.5.5"),
            to: v("0.5.6"),
            bump: BumpKind::Patch,
        };
        let seen = run(&dir, &pnpm, &bump, "").unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(read(&dir, "package.json"), ROOT.replace("^0.5.5", "^0.5.6"));
        assert_eq!(
            read(&dir, "packages/web/package.json"),
            WEB.replace("\"0.5.5\"", "\"0.5.6\"")
        );
        assert_eq!(read(&dir, WORKSPACE), SETTINGS);

        // `1.x` already allows the target: pinned once, then kept.
        let (dir, pnpm) = project();
        let bump = Change::DirectBump {
            package: "minimist".into(),
            from: v("1.2.5"),
            to: v("1.2.6"),
            bump: BumpKind::Patch,
        };
        let seen = run(&dir, &pnpm, &bump, "").unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0][1], WEB.replace("\"1.x\"", "\"1.2.6\""));
        assert_eq!(read(&dir, "packages/web/package.json"), WEB);

        // Only a registry package depends on it.
        let bump = Change::DirectBump {
            package: "path-to-regexp".into(),
            from: v("0.1.7"),
            to: v("0.1.13"),
            bump: BumpKind::Patch,
        };
        let err = pnpm.edits(dir.path(), &bump).err().unwrap();
        assert!(matches!(err, AdapterError::ManifestNotEditable(_)), "{err}");

        // Catalog specs are not edited.
        std::fs::write(
            dir.path().join("package.json"),
            ROOT.replace("\"^0.5.5\"", "\"catalog:\""),
        )
        .unwrap();
        let bump = Change::DirectBump {
            package: "mkdirp".into(),
            from: v("0.5.5"),
            to: v("0.5.6"),
            bump: BumpKind::Patch,
        };
        match pnpm.edits(dir.path(), &bump).err() {
            Some(AdapterError::ManifestNotEditable(d)) => assert!(d.contains("catalogs"), "{d}"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn overrides_are_scoped_to_parents() {
        let (dir, pnpm) = project();
        let force = Change::Override {
            package: "path-to-regexp".into(),
            from: v("0.1.7"),
            to: v("0.1.13"),
        };
        let seen = run(&dir, &pnpm, &force, "").unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            read(&dir, WORKSPACE),
            format!("{SETTINGS}overrides:\n  'router@1.3.8>path-to-regexp': '0.1.13'\n")
        );
        assert_eq!(read(&dir, "package.json"), ROOT);

        // An importer depends on it directly: one unscoped entry.
        let (dir, pnpm) = project();
        std::fs::remove_file(dir.path().join(WORKSPACE)).unwrap();
        let force = Change::Override {
            package: "minimist".into(),
            from: v("1.2.5"),
            to: v("1.2.6"),
        };
        run(&dir, &pnpm, &force, "").unwrap();
        assert_eq!(
            read(&dir, WORKSPACE),
            "overrides:\n  'minimist@1.2.5': '1.2.6'\n"
        );

        // Aliased dependencies stay aliases.
        assert_eq!(override_value("minimist", "minimist", &v("1.2.6")), "1.2.6");
        assert_eq!(
            override_value("minimist", "mm", &v("1.2.6")),
            "npm:minimist@1.2.6"
        );

        let missing = Change::Override {
            package: "minimist".into(),
            from: v("9.9.9"),
            to: v("9.9.10"),
        };
        let err = pnpm.edits(dir.path(), &missing).err().unwrap();
        assert!(err.to_string().contains("not in pnpm-lock.yaml"), "{err}");
    }

    /// Applies each pnpm fixture's planned change with real pnpm and checks
    /// the resulting files. Run with
    /// `nix develop -c cargo test pnpm::tests::apply -- --ignored`.
    #[test]
    #[ignore = "needs pnpm and network"]
    fn apply_fixture_changes() {
        let cutoff = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(7 * 24);
        let opts = ApplyOptions {
            release_cutoff: Some(cutoff),
            ..ApplyOptions::default()
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
                Some(("package.json", "\"jsprim\": \"^1.4.2\"")),
            ),
            (
                "override",
                Change::Override {
                    package: "path-to-regexp".into(),
                    from: v("0.1.7"),
                    to: v("0.1.13"),
                },
                Some((WORKSPACE, "'router@1.3.8>path-to-regexp': '0.1.13'")),
            ),
        ];
        let pnpm = Pnpm::new();
        for (name, change, file_check) in cases {
            let src = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-projects/pnpm")
                .join(name);
            let dir = tempfile::tempdir().unwrap();
            for file in ["package.json", "pnpm-lock.yaml", "index.js", "test.js"] {
                std::fs::copy(src.join(file), dir.path().join(file)).unwrap();
            }
            let install_and_test = || {
                super::super::run(
                    crate::platform::shell("pnpm install --frozen-lockfile && pnpm test")
                        .current_dir(dir.path()),
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            };
            install_and_test();
            let manifest = read(&dir, "package.json");
            pnpm.apply(dir.path(), &change, &opts)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            install_and_test();

            let graph = pnpm.resolve_graph(dir.path()).unwrap();
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
                    pnpm.compare(found, change.to()).is_ge(),
                    "{name}: {} still at {found}",
                    change.package()
                );
            }
            let lock = read(&dir, "pnpm-lock.yaml");
            match file_check {
                Some((file, snippet)) => {
                    assert!(read(&dir, file).contains(snippet), "{name}: {file}")
                }
                None => {
                    // A relock leaves no trace outside the lockfile.
                    assert_eq!(read(&dir, "package.json"), manifest, "{name}");
                    assert!(!dir.path().join(WORKSPACE).exists(), "{name}");
                    assert!(!lock.contains("overrides:"), "{name}: {lock}");
                }
            }
        }

        // No release matches the new range.
        let dir = tempfile::tempdir().unwrap();
        for file in ["package.json", "pnpm-lock.yaml"] {
            let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-projects/pnpm/relock");
            std::fs::copy(src.join(file), dir.path().join(file)).unwrap();
        }
        let bump = Change::DirectBump {
            package: "mkdirp".into(),
            from: v("0.5.5"),
            to: v("99.0.0"),
            bump: BumpKind::Major,
        };
        match pnpm.apply(dir.path(), &bump, &opts) {
            Err(AdapterError::ResolutionConflict(detail)) => {
                assert!(detail.contains("ERR_PNPM_NO_MATCHING_VERSION"), "{detail}")
            }
            other => panic!("expected a resolution conflict, got {other:?}"),
        }
    }
}
