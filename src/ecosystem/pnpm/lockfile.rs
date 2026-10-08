//! `pnpm-lock.yaml` (lockfileVersion 9, written by pnpm 9 and newer)
//! parsing and graph building.
//!
//! - `importers` are the project's own packages, keyed by directory relative
//!   to the workspace root (`.`, `packages/web`). Each dependency records
//!   the declared `specifier` and the resolved `version` reference.
//! - `packages` holds per-`name@version` metadata (`resolution`), and
//!   `snapshots` every resolved instance (`name@version`, or with the peers
//!   it was resolved with: `name@version(peer@1.0.0)`) with its dependencies
//!   as references.
//! - A reference is a version (`1.2.5`, `18.2.0(react@18.2.0)`), a
//!   `name@version` (aliases, non-registry packages) or `link:<dir>` (a
//!   local package, relative to the importer).
//! - `catalogs` resolve `catalog:` specifiers.
//! - pnpm 12 can write an "env" document before the lockfile document; the
//!   lockfile is the last document.
//!
//! The lockfile does not record the ranges registry packages declare for
//! their own dependencies, so the requirements on those edges come from the
//! parent's published manifest (see [`graph`]).

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;

use serde::Deserialize;

use super::registry::Specs;
use crate::ecosystem::AdapterError;
use crate::model::{DepGraph, NodeId, Version, VersionReq};

pub const FILE: &str = "pnpm-lock.yaml";

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lockfile {
    #[serde(default)]
    pub lockfile_version: String,
    #[serde(default)]
    pub importers: BTreeMap<String, Importer>,
    #[serde(default)]
    pub packages: BTreeMap<String, Package>,
    #[serde(default)]
    pub snapshots: BTreeMap<String, Snapshot>,
    /// Catalog name (`default` for `catalog:`) -> package -> entry.
    #[serde(default)]
    pub catalogs: BTreeMap<String, BTreeMap<String, Resolved>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Importer {
    #[serde(default)]
    pub dependencies: BTreeMap<String, Resolved>,
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, Resolved>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, Resolved>,
}

impl Importer {
    /// `(package.json section, dependencies)`, in the sections' order.
    pub fn sections(&self) -> [(&'static str, &BTreeMap<String, Resolved>); 3] {
        [
            ("dependencies", &self.dependencies),
            ("devDependencies", &self.dev_dependencies),
            ("optionalDependencies", &self.optional_dependencies),
        ]
    }
}

/// A declared dependency and what it resolved to.
#[derive(Debug, Default, Deserialize)]
pub struct Resolved {
    pub specifier: String,
    pub version: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Package {
    #[serde(default)]
    pub resolution: Resolution,
    /// Set for non-registry packages (git, tarball, directory), whose key
    /// does not contain the version.
    pub version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Resolution {
    pub tarball: Option<String>,
    /// `git`, `directory`; absent for registry packages.
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
}

impl Snapshot {
    pub fn deps(&self) -> impl Iterator<Item = (&String, &String)> {
        self.dependencies.iter().chain(&self.optional_dependencies)
    }
}

pub fn parse(text: &str) -> Result<Lockfile, AdapterError> {
    let mut lock = None;
    for doc in serde_yaml_ng::Deserializer::from_str(text) {
        lock = Some(Lockfile::deserialize(doc).map_err(|e| AdapterError::Parse {
            what: FILE.into(),
            message: e.to_string(),
        })?);
    }
    let lock = lock.unwrap_or_default();
    if !lock.lockfile_version.starts_with("9.") {
        return Err(AdapterError::Unsupported(format!(
            "{FILE} lockfileVersion {:?} (only 9.x is supported; regenerate it with pnpm >= 9)",
            lock.lockfile_version
        )));
    }
    Ok(lock)
}

pub fn load(dir: &Path) -> Result<Lockfile, AdapterError> {
    parse(&std::fs::read_to_string(dir.join(FILE))?)
}

/// The snapshot key a dependency `name: reference` points at; `None` for
/// `link:` references. pnpm's `refToRelative`: a reference is a
/// `name@version` when it has an `@` before any `:` or `(`.
pub fn snapshot_key(name: &str, reference: &str) -> Option<String> {
    if reference.starts_with("link:") {
        return None;
    }
    if reference.starts_with('@') {
        return Some(reference.to_string());
    }
    let full = match reference.find('@') {
        Some(at) => [':', '(']
            .iter()
            .all(|&c| reference.find(c).is_none_or(|i| at < i)),
        None => false,
    };
    Some(if full {
        reference.to_string()
    } else {
        format!("{name}@{reference}")
    })
}

/// `name@version(peers...)` -> (`name`, `version`).
pub fn split_key(key: &str) -> Option<(&str, &str)> {
    let base = package_key(key);
    let at = base.get(1..)?.find('@')? + 1;
    Some((&base[..at], &base[at + 1..]))
}

/// The `packages` key of a snapshot key: without the peer suffix.
pub fn package_key(key: &str) -> &str {
    key.split_once('(').map_or(key, |(base, _)| base)
}

/// The importer a `link:` reference from `importer` points at, if it stays
/// inside the workspace.
fn link_target(importer: &str, reference: &str) -> Option<String> {
    let mut parts: Vec<&str> = importer
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    for part in reference.strip_prefix("link:")?.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    })
}

/// Where a package version is depended on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Holder {
    /// An importer declares it as `section.dep` in its `package.json`.
    Importer {
        importer: String,
        section: &'static str,
        dep: String,
    },
    /// A package (any of its peer variants) depends on it as `dep`.
    Package {
        name: String,
        version: String,
        registry: bool,
        dep: String,
    },
}

impl Lockfile {
    /// `(name, version)` of the package a snapshot key resolves to.
    pub fn identity<'a>(&'a self, key: &'a str) -> Option<(&'a str, &'a str)> {
        let (name, version) = split_key(key)?;
        let version = self
            .packages
            .get(package_key(key))
            .and_then(|p| p.version.as_deref())
            .unwrap_or(version);
        Some((name, version))
    }

    /// Registry packages have only an integrity hash, or a registry tarball
    /// URL (`.../<name>/-/<file>.tgz`). Git, directory and remote tarball
    /// packages do not.
    pub fn is_registry(&self, key: &str) -> bool {
        let Some(package) = self.packages.get(package_key(key)) else {
            return false;
        };
        let r = &package.resolution;
        r.kind.is_none()
            && r.tarball.as_deref().is_none_or(|t| {
                (t.starts_with("https://") || t.starts_with("http://")) && t.contains("/-/")
            })
    }

    /// The declared spec of an importer dependency, with `catalog:`
    /// specifiers replaced by the catalog's.
    pub fn specifier<'a>(&'a self, name: &str, dep: &'a Resolved) -> &'a str {
        let Some(catalog) = dep.specifier.strip_prefix("catalog:") else {
            return &dep.specifier;
        };
        let catalog = if catalog.is_empty() {
            "default"
        } else {
            catalog
        };
        self.catalogs
            .get(catalog)
            .and_then(|c| c.get(name))
            .map_or(&dep.specifier, |entry| &entry.specifier)
    }

    /// Every place that depends on `name@version`.
    pub fn holders(&self, name: &str, version: &str) -> Vec<Holder> {
        let target = |dep: &str, reference: &str| {
            snapshot_key(dep, reference)
                .is_some_and(|key| self.identity(&key) == Some((name, version)))
        };
        let mut out = Vec::new();
        for (importer, deps) in &self.importers {
            for (section, deps) in deps.sections() {
                for (dep, resolved) in deps {
                    if target(dep, &resolved.version) {
                        out.push(Holder::Importer {
                            importer: importer.clone(),
                            section,
                            dep: dep.clone(),
                        });
                    }
                }
            }
        }
        for (key, snapshot) in &self.snapshots {
            let Some((parent, parent_version)) = self.identity(key) else {
                continue;
            };
            for (dep, reference) in snapshot.deps() {
                if target(dep, reference) {
                    out.push(Holder::Package {
                        name: parent.to_string(),
                        version: parent_version.to_string(),
                        registry: self.is_registry(key),
                        dep: dep.clone(),
                    });
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

/// Looks up what a published package version declares (see [`graph`]).
pub type SpecsLookup<'a> = dyn FnMut(&str, &Version) -> Result<Option<Specs>, AdapterError> + 'a;

/// Build the dependency graph. Roots are the importers, named by
/// `root_id(importer)`. Requirements on edges from importers are their
/// specifiers; on edges from registry packages, the spec in
/// `specs(name, version)` (the published manifest), falling back to the
/// exact locked version when unknown (also for non-registry parents). Only
/// snapshots reachable from an importer become nodes.
pub fn graph(
    lock: &Lockfile,
    root_id: &dyn Fn(&str) -> (String, Version),
    specs: &mut SpecsLookup,
) -> Result<DepGraph, AdapterError> {
    let mut g = DepGraph::new();
    let roots: HashMap<&str, NodeId> = lock
        .importers
        .keys()
        .map(|importer| {
            let (name, version) = root_id(importer);
            (importer.as_str(), g.add_root(&name, &version))
        })
        .collect();

    let mut visit = Visit::default();
    for (importer, deps) in &lock.importers {
        let from = roots[importer.as_str()];
        for (_, deps) in deps.sections() {
            for (name, dep) in deps {
                let req = VersionReq::new(lock.specifier(name, dep));
                let to = match snapshot_key(name, &dep.version) {
                    Some(key) => visit.node(lock, &mut g, key),
                    None => link_target(importer, &dep.version)
                        .and_then(|target| roots.get(target.as_str()).copied()),
                };
                if let Some(to) = to {
                    g.add_edge(from, to, req);
                    if g.node(to).registry {
                        g.nodes[to].direct = true;
                    }
                }
            }
        }
    }

    let mut declared: HashMap<NodeId, Option<Specs>> = HashMap::new();
    while let Some(key) = visit.queue.pop_front() {
        let from = visit.ids[&key];
        let snapshot = &lock.snapshots[&key];
        if snapshot.deps().next().is_none() {
            continue;
        }
        if let Entry::Vacant(slot) = declared.entry(from) {
            let parent = g.node(from);
            slot.insert(if parent.registry {
                specs(&parent.name, &parent.version)?
            } else {
                None
            });
        }
        for (name, reference) in snapshot.deps() {
            let Some(to) = snapshot_key(name, reference).and_then(|k| visit.node(lock, &mut g, k))
            else {
                continue;
            };
            let req = declared[&from]
                .as_ref()
                .and_then(|s| s.get(name))
                .cloned()
                .unwrap_or_else(|| format!("={}", g.node(to).version));
            g.add_edge(from, to, VersionReq::new(req));
        }
    }
    Ok(g)
}

/// Snapshots reached so far by [`graph`], and those still to expand.
#[derive(Default)]
struct Visit {
    ids: HashMap<String, NodeId>,
    queue: VecDeque<String>,
}

impl Visit {
    /// The node of snapshot `key`, added (and queued) on first sight. A key
    /// without a snapshot is a missing optional dependency (or a broken
    /// lockfile, which pnpm reports itself).
    fn node(&mut self, lock: &Lockfile, g: &mut DepGraph, key: String) -> Option<NodeId> {
        if let Some(&id) = self.ids.get(&key) {
            return Some(id);
        }
        lock.snapshots.get(&key)?;
        let (name, version) = lock.identity(&key)?;
        let id = g.add_node(name, &Version::new(version), false, lock.is_registry(&key));
        self.ids.insert(key.clone(), id);
        self.queue.push_back(key);
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

catalogs:
  default:
    mkdirp:
      specifier: ^0.5.5
      version: 0.5.5

importers:

  .:
    dependencies:
      '@ws/web':
        specifier: workspace:^
        version: link:packages/web
      mkdirp:
        specifier: 'catalog:'
        version: 0.5.5
      react-dom:
        specifier: 18.2.0
        version: 18.2.0(react@18.2.0)
      sw:
        specifier: npm:string-width@^4.2.0
        version: string-width@4.2.3
      g:
        specifier: github:x/g
        version: https://codeload.github.com/x/g/tar.gz/abc
    devDependencies:
      react:
        specifier: 18.2.0
        version: 18.2.0

  packages/web:
    dependencies:
      app:
        specifier: workspace:*
        version: link:../..
      mm:
        specifier: 1
        version: minimist@1.2.8
      outside:
        specifier: link:../../../lib
        version: link:../../../lib
    optionalDependencies:
      gone:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  g@https://codeload.github.com/x/g/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/x/g/tar.gz/abc}
    version: 0.1.0

  loose-envify@1.4.0:
    resolution: {integrity: sha512-a}
    hasBin: true

  minimist@1.2.5:
    resolution: {integrity: sha512-b}

  minimist@1.2.8:
    resolution: {integrity: sha512-c, tarball: https://npm.example.com/minimist/-/minimist-1.2.8.tgz}

  mkdirp@0.5.5:
    resolution: {integrity: sha512-d}

  react-dom@18.2.0:
    resolution: {integrity: sha512-e}
    peerDependencies:
      react: ^18.2.0

  react@18.2.0:
    resolution: {integrity: sha512-f}

  string-width@4.2.3:
    resolution: {integrity: sha512-g}

  unused@1.0.0:
    resolution: {integrity: sha512-h}

snapshots:

  g@https://codeload.github.com/x/g/tar.gz/abc:
    dependencies:
      minimist: 1.2.5

  loose-envify@1.4.0: {}

  minimist@1.2.5: {}

  minimist@1.2.8: {}

  mkdirp@0.5.5:
    dependencies:
      minimist: 1.2.5

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      loose-envify: 1.4.0
      react: 18.2.0

  react@18.2.0:
    dependencies:
      loose-envify: 1.4.0

  string-width@4.2.3:
    optionalDependencies:
      mm: minimist@1.2.8

  unused@1.0.0: {}
"#;

    fn edge(g: &DepGraph, from: &str, to: &str) -> Option<String> {
        g.edges
            .iter()
            .find(|e| g.label(e.from) == from && g.label(e.to) == to)
            .map(|e| e.req.to_string())
    }

    fn roots(importer: &str) -> (String, Version) {
        match importer {
            "." => ("app".into(), Version::new("1.0.0")),
            _ => ("@ws/web".into(), Version::new("0.2.0")),
        }
    }

    fn specs(name: &str, version: &Version) -> Result<Option<Specs>, AdapterError> {
        let pairs: &[(&str, &str)] = match (name, version.as_str()) {
            ("mkdirp", "0.5.5") => &[("minimist", "^1.2.5")],
            ("react-dom", "18.2.0") => &[("loose-envify", "^1.1.0"), ("react", "^18.2.0")],
            ("string-width", "4.2.3") => &[("mm", "npm:minimist@^1.2.0")],
            _ => return Ok(None),
        };
        Ok(Some(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ))
    }

    #[test]
    fn references() {
        assert_eq!(snapshot_key("a", "1.2.5").as_deref(), Some("a@1.2.5"));
        assert_eq!(
            snapshot_key("react-dom", "18.2.0(react@18.2.0)").as_deref(),
            Some("react-dom@18.2.0(react@18.2.0)")
        );
        assert_eq!(
            snapshot_key("sw", "string-width@4.2.3").as_deref(),
            Some("string-width@4.2.3")
        );
        assert_eq!(
            snapshot_key("x", "@s/real@1.0.0").as_deref(),
            Some("@s/real@1.0.0")
        );
        assert_eq!(
            snapshot_key("g", "git+ssh://git@github.com/x/g.git#abc").as_deref(),
            Some("g@git+ssh://git@github.com/x/g.git#abc")
        );
        assert_eq!(snapshot_key("w", "link:packages/web"), None);

        assert_eq!(
            split_key("@s/a@1.0.0(react@18.2.0)"),
            Some(("@s/a", "1.0.0"))
        );
        assert_eq!(split_key("a@file:../a"), Some(("a", "file:../a")));
        assert_eq!(split_key("nope"), None);

        assert_eq!(
            link_target("packages/web", "link:../..").as_deref(),
            Some(".")
        );
        assert_eq!(
            link_target(".", "link:packages/web").as_deref(),
            Some("packages/web")
        );
        assert_eq!(link_target("packages/web", "link:../../../lib"), None);
    }

    #[test]
    fn builds_graph_from_importers_and_snapshots() {
        let lock = parse(LOCK).unwrap();
        let g = graph(&lock, &roots, &mut specs).unwrap();
        let labels: Vec<String> = g.roots.iter().map(|&r| g.label(r)).collect();
        assert_eq!(labels, ["app@1.0.0", "@ws/web@0.2.0"]);

        // Importer edges carry the specifier; catalogs are resolved.
        assert_eq!(
            edge(&g, "app@1.0.0", "mkdirp@0.5.5").as_deref(),
            Some("^0.5.5")
        );
        assert_eq!(
            edge(&g, "app@1.0.0", "react@18.2.0").as_deref(),
            Some("18.2.0")
        );
        assert_eq!(
            edge(&g, "app@1.0.0", "string-width@4.2.3").as_deref(),
            Some("npm:string-width@^4.2.0")
        );
        assert_eq!(
            edge(&g, "@ws/web@0.2.0", "minimist@1.2.8").as_deref(),
            Some("1")
        );
        // Workspace links between importers.
        assert_eq!(
            edge(&g, "app@1.0.0", "@ws/web@0.2.0").as_deref(),
            Some("workspace:^")
        );
        assert_eq!(
            edge(&g, "@ws/web@0.2.0", "app@1.0.0").as_deref(),
            Some("workspace:*")
        );
        // Registry edges carry the published spec; peers resolve.
        assert_eq!(
            edge(&g, "mkdirp@0.5.5", "minimist@1.2.5").as_deref(),
            Some("^1.2.5")
        );
        assert_eq!(
            edge(&g, "react-dom@18.2.0", "react@18.2.0").as_deref(),
            Some("^18.2.0")
        );
        assert_eq!(
            edge(&g, "string-width@4.2.3", "minimist@1.2.8").as_deref(),
            Some("npm:minimist@^1.2.0")
        );
        // Non-registry parents: exact versions.
        assert_eq!(
            edge(&g, "g@0.1.0", "minimist@1.2.5").as_deref(),
            Some("=1.2.5")
        );

        let node = |label: &str| {
            let id = (0..g.nodes.len()).find(|&i| g.label(i) == label).unwrap();
            g.node(id).clone()
        };
        assert!(node("mkdirp@0.5.5").direct && node("mkdirp@0.5.5").registry);
        assert!(node("minimist@1.2.8").direct && node("minimist@1.2.8").registry);
        assert!(!node("minimist@1.2.5").direct);
        assert!(node("react@18.2.0").direct);
        assert!(!node("loose-envify@1.4.0").direct);
        assert!(!node("g@0.1.0").registry);
        assert!(!node("app@1.0.0").registry);
        // Unreachable snapshots and missing optional deps are skipped.
        assert!(
            g.nodes
                .iter()
                .all(|n| n.name != "unused" && n.name != "gone")
        );
        assert_eq!(g.nodes.len(), 10);
    }

    #[test]
    fn finds_holders() {
        let lock = parse(LOCK).unwrap();
        let package = |name: &str, version: &str, registry: bool, dep: &str| Holder::Package {
            name: name.into(),
            version: version.into(),
            registry,
            dep: dep.into(),
        };
        assert_eq!(
            lock.holders("minimist", "1.2.5"),
            [
                package("g", "0.1.0", false, "minimist"),
                package("mkdirp", "0.5.5", true, "minimist"),
            ]
        );
        assert_eq!(
            lock.holders("minimist", "1.2.8"),
            [
                Holder::Importer {
                    importer: "packages/web".into(),
                    section: "dependencies",
                    dep: "mm".into()
                },
                package("string-width", "4.2.3", true, "mm"),
            ]
        );
        // Peer variants of one parent count once.
        assert_eq!(
            lock.holders("loose-envify", "1.4.0"),
            [
                package("react", "18.2.0", true, "loose-envify"),
                package("react-dom", "18.2.0", true, "loose-envify"),
            ]
        );
        assert_eq!(
            lock.holders("react", "18.2.0"),
            [
                Holder::Importer {
                    importer: ".".into(),
                    section: "devDependencies",
                    dep: "react".into()
                },
                package("react-dom", "18.2.0", true, "react"),
            ]
        );
        assert!(lock.holders("minimist", "9.9.9").is_empty());
    }

    #[test]
    fn reads_the_last_document_and_checks_the_version() {
        let env =
            "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies: {}\n\n";
        let lock = parse(&format!("{env}---\n{LOCK}")).unwrap();
        assert_eq!(lock.importers.len(), 2);
        assert!(lock.packages.contains_key("mkdirp@0.5.5"));

        for old in ["lockfileVersion: '6.0'\n", "lockfileVersion: 5.4\n", "{}\n"] {
            let err = parse(old).unwrap_err();
            assert!(matches!(err, AdapterError::Unsupported(_)), "{err}");
        }
        assert!(parse("lockfileVersion: '9.0'\nimporters: [").is_err());
    }
}
