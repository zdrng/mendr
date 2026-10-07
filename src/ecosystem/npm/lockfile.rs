//! `package-lock.json` (lockfileVersion 2/3) parsing and graph building.
//!
//! The `packages` map is keyed by install path: `""` is the root,
//! `node_modules/a`, `node_modules/a/node_modules/b` are installed packages,
//! and other keys (`packages/web`, `../lib`) are local packages (workspaces,
//! `file:` directories). `link: true` entries point at a local package via
//! `resolved`. Dependencies are resolved with Node's lookup: the nearest
//! `node_modules/<name>` walking up from the dependent's path.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::Deserialize;

use crate::ecosystem::AdapterError;
use crate::model::{DepGraph, NodeId, Version, VersionReq};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lockfile {
    #[serde(default)]
    pub lockfile_version: u32,
    #[serde(default)]
    pub packages: BTreeMap<String, Entry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// Set for aliases (`"mm": "npm:minimist@1"`) and workspace packages.
    pub name: Option<String>,
    pub version: Option<String>,
    pub resolved: Option<String>,
    #[serde(default)]
    pub link: bool,
    #[serde(default)]
    pub in_bundle: bool,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, String>,
}

/// The lockfile in `dir`: `npm-shrinkwrap.json` wins over
/// `package-lock.json`, as in npm.
pub fn path(dir: &Path) -> std::path::PathBuf {
    let shrinkwrap = dir.join("npm-shrinkwrap.json");
    if shrinkwrap.is_file() {
        shrinkwrap
    } else {
        dir.join("package-lock.json")
    }
}

pub fn parse(text: &str) -> Result<Lockfile, AdapterError> {
    let lock: Lockfile = serde_json::from_str(text).map_err(|e| AdapterError::Parse {
        what: "package-lock.json".into(),
        message: e.to_string(),
    })?;
    if lock.lockfile_version < 2 || lock.packages.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "package-lock.json lockfileVersion {} (only 2 and 3 are supported; \
             regenerate it with npm >= 7)",
            lock.lockfile_version
        )));
    }
    Ok(lock)
}

pub fn load(dir: &Path) -> Result<Lockfile, AdapterError> {
    parse(&std::fs::read_to_string(path(dir))?)
}

/// Whether `key` is a local package (root, workspace, `file:` directory)
/// rather than something installed under `node_modules`.
pub fn is_local(key: &str) -> bool {
    !key.starts_with("node_modules/") && !key.contains("/node_modules/")
}

impl Lockfile {
    /// Package name of the entry at `key`.
    pub fn name_of<'a>(&'a self, key: &'a str) -> &'a str {
        let entry = &self.packages[key];
        if let Some(name) = &entry.name {
            return name;
        }
        match key.rsplit_once("node_modules/") {
            Some((_, name)) => name,
            None => key.rsplit('/').next().unwrap_or(key),
        }
    }

    /// Key of the package `name` as seen from `from` (Node's lookup), with
    /// links followed.
    pub fn resolve(&self, from: &str, name: &str) -> Option<&str> {
        let mut dir = from;
        loop {
            let candidate = if dir.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{dir}/node_modules/{name}")
            };
            if let Some((key, entry)) = self.packages.get_key_value(&candidate) {
                if !entry.link {
                    return Some(key);
                }
                let target = entry.resolved.as_deref()?;
                return self.packages.get_key_value(target).map(|(k, _)| k.as_str());
            }
            if dir.is_empty() {
                return None;
            }
            dir = dir.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
    }

    /// Declared dependencies of the entry at `key` as `(name, spec)`:
    /// dependencies, optional and peer dependencies, plus dev dependencies
    /// for local packages.
    pub fn declared<'a>(&'a self, key: &str) -> Vec<(&'a str, &'a str)> {
        let entry = &self.packages[key];
        let mut sections = vec![
            &entry.dependencies,
            &entry.optional_dependencies,
            &entry.peer_dependencies,
        ];
        if is_local(key) {
            sections.push(&entry.dev_dependencies);
        }
        sections
            .into_iter()
            .flatten()
            .map(|(n, s)| (n.as_str(), s.as_str()))
            .collect()
    }

    /// Keys of installed (non-link) copies of `name@version`.
    pub fn copies(&self, name: &str, version: &str) -> Vec<String> {
        self.packages
            .iter()
            .filter(|(k, e)| {
                !is_local(k)
                    && !e.link
                    && e.version.as_deref() == Some(version)
                    && self.name_of(k) == name
            })
            .map(|(k, _)| k.clone())
            .collect()
    }
}

/// Registry packages have a registry tarball URL (`.../<name>/-/<file>.tgz`)
/// or no `resolved` at all (npm omits it for some registry configs). Git,
/// remote tarball and `file:` dependencies do not.
fn from_registry(entry: &Entry) -> bool {
    match entry.resolved.as_deref() {
        None => true,
        Some(r) => (r.starts_with("https://") || r.starts_with("http://")) && r.contains("/-/"),
    }
}

/// Build the dependency graph. Roots are the root package and every local
/// package inside the project (workspaces, in-tree `file:` packages).
/// Bundled packages are skipped (they ship inside their parent's tarball and
/// cannot be changed on their own).
pub fn graph(lock: &Lockfile) -> DepGraph {
    let mut g = DepGraph::new();
    let mut ids: HashMap<&str, NodeId> = HashMap::new();
    for (key, entry) in &lock.packages {
        if entry.link || entry.in_bundle {
            continue;
        }
        let name = lock.name_of(key);
        let version = Version::new(entry.version.as_deref().unwrap_or("0.0.0"));
        let id = if is_local(key) && !key.starts_with("../") {
            g.add_root(name, &version)
        } else {
            let registry = !is_local(key) && from_registry(entry);
            g.add_node(name, &version, false, registry)
        };
        ids.insert(key, id);
    }
    for key in lock.packages.keys() {
        let Some(&from) = ids.get(key.as_str()) else {
            continue;
        };
        for (name, spec) in lock.declared(key) {
            // Unresolvable deps are missing optional/peer deps (or a broken
            // lockfile, which npm reports itself).
            let Some(&to) = lock.resolve(key, name).and_then(|k| ids.get(k)) else {
                continue;
            };
            g.add_edge(from, to, VersionReq::new(spec));
            if !g.node(from).registry && g.node(to).registry {
                g.nodes[to].direct = true;
            }
        }
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
      "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
      "packages": {
        "": {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"],
             "dependencies": {"a": "^1.0.0", "mm": "npm:minimist@^1.2.5"},
             "devDependencies": {"d": "~2.0.0"}},
        "node_modules/a": {"version": "1.1.0", "resolved": "https://registry.npmjs.org/a/-/a-1.1.0.tgz",
             "dependencies": {"b": "^1.0.0", "c": "^3"}, "optionalDependencies": {"gone": "*"}},
        "node_modules/a/node_modules/b": {"version": "1.0.5",
             "resolved": "https://registry.npmjs.org/b/-/b-1.0.5.tgz", "dependencies": {"c": "^3.1"}},
        "node_modules/b": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"},
        "node_modules/c": {"version": "3.2.0", "resolved": "https://registry.npmjs.org/c/-/c-3.2.0.tgz",
             "dependencies": {"bundled": "1"}},
        "node_modules/c/node_modules/bundled": {"version": "1.0.0", "inBundle": true},
        "node_modules/d": {"version": "2.0.1", "dev": true,
             "resolved": "https://registry.npmjs.org/d/-/d-2.0.1.tgz",
             "devDependencies": {"never": "1"}},
        "node_modules/mm": {"name": "minimist", "version": "1.2.8",
             "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz"},
        "node_modules/@ws/web": {"resolved": "packages/web", "link": true},
        "node_modules/g": {"version": "0.1.0", "resolved": "git+ssh://git@github.com/x/g.git#abc"},
        "packages/web": {"name": "@ws/web", "version": "0.2.0",
             "dependencies": {"b": "^2.0.0", "g": "github:x/g"}, "devDependencies": {"a": "^1.1.0"}}
      }
    }"#;

    fn edge(g: &DepGraph, from: &str, to: &str) -> Option<String> {
        g.edges
            .iter()
            .find(|e| g.label(e.from) == from && g.label(e.to) == to)
            .map(|e| e.req.to_string())
    }

    #[test]
    fn builds_graph_with_node_lookup() {
        let lock = parse(LOCK).unwrap();
        let g = graph(&lock);
        let labels: Vec<String> = g.roots.iter().map(|&r| g.label(r)).collect();
        assert_eq!(labels, ["app@1.0.0", "@ws/web@0.2.0"]);

        // Nested copy wins over the hoisted one; lookups walk up.
        assert_eq!(edge(&g, "a@1.1.0", "b@1.0.5").as_deref(), Some("^1.0.0"));
        assert_eq!(edge(&g, "b@1.0.5", "c@3.2.0").as_deref(), Some("^3.1"));
        assert_eq!(
            edge(&g, "@ws/web@0.2.0", "b@2.0.0").as_deref(),
            Some("^2.0.0")
        );
        // Dev deps of local packages count, of registry packages not.
        assert_eq!(edge(&g, "app@1.0.0", "d@2.0.1").as_deref(), Some("~2.0.0"));
        assert_eq!(
            edge(&g, "@ws/web@0.2.0", "a@1.1.0").as_deref(),
            Some("^1.1.0")
        );
        // Workspace link and alias.
        assert_eq!(edge(&g, "app@1.0.0", "@ws/web@0.2.0"), None); // not declared
        assert_eq!(
            edge(&g, "app@1.0.0", "minimist@1.2.8").as_deref(),
            Some("npm:minimist@^1.2.5")
        );

        let node = |label: &str| {
            let id = (0..g.nodes.len()).find(|&i| g.label(i) == label).unwrap();
            g.node(id).clone()
        };
        assert!(node("a@1.1.0").direct && node("a@1.1.0").registry);
        assert!(node("b@2.0.0").direct);
        assert!(!node("b@1.0.5").direct);
        assert!(!node("g@0.1.0").registry);
        assert!(!node("@ws/web@0.2.0").registry);
        // Bundled packages and missing optional deps are skipped.
        assert!(
            g.nodes
                .iter()
                .all(|n| n.name != "bundled" && n.name != "gone")
        );
    }

    #[test]
    fn copies_and_resolve() {
        let lock = parse(LOCK).unwrap();
        assert_eq!(lock.copies("b", "1.0.5"), ["node_modules/a/node_modules/b"]);
        assert_eq!(lock.copies("minimist", "1.2.8"), ["node_modules/mm"]);
        assert_eq!(lock.resolve("", "@ws/web"), Some("packages/web"));
        assert_eq!(lock.resolve("packages/web", "b"), Some("node_modules/b"));
        assert_eq!(lock.resolve("", "nope"), None);
    }

    #[test]
    fn rejects_old_lockfiles() {
        let err = parse(r#"{"lockfileVersion": 1, "dependencies": {}}"#).unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)), "{err}");
        assert!(parse("not json").is_err());
    }
}
