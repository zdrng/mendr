//! The dependency graph of a Gradle build, rebuilt from its lockfiles.
//!
//! A lockfile is a flat list of module versions per project, without
//! edges, so:
//! - **roots:** one per project lockfile, named like Gradle names projects
//!   (`demo` for the root project, `demo:libs:core` for `libs/core`), with
//!   Gradle's default version `unspecified`;
//! - **edges between modules:** the dependencies each locked version
//!   declares (its POM), to the versions locked in the same project with a
//!   configuration in common;
//! - **edges from a root:** to every locked module the build declares
//!   (build scripts, version catalogs), with the declared version, or an
//!   empty requirement when the build gives it none (platform/BOM-managed).
//!   A module still unreachable after that (declared in a way the scan
//!   cannot see, or below a dependency the registry does not know) is
//!   attached to its project's root with an empty requirement too.

use std::collections::HashSet;

use crate::ecosystem::{AdapterError, DeclaredDep};
use crate::model::{DepGraph, NodeId, Version, VersionReq};

use super::lockfile::Lockfile;

/// Version of every root node.
pub const PROJECT_VERSION: &str = "unspecified";

/// How the build declares a module: `None` = not at all, `Some(None)` =
/// without a version mendr can rewrite, `Some(Some(v))` = with version `v`.
pub type Declared<'a> = &'a dyn Fn(&str) -> Option<Option<String>>;

/// What one module version declares: `deps(module, version)`.
pub type Deps<'a> = &'a mut dyn FnMut(&str, &str) -> Result<Vec<DeclaredDep>, AdapterError>;

/// Build the graph of the projects in `locks` (see the module docs).
/// `deps(module, version)` returns what that version declares; unknown
/// versions should give an empty list.
pub fn build(
    root_name: &str,
    locks: &[Lockfile],
    declared: Declared,
    deps: Deps,
) -> Result<DepGraph, AdapterError> {
    let mut g = DepGraph::new();
    let unspecified = Version::new(PROJECT_VERSION);
    // (project root, locked node) pairs, to attach unreachable nodes.
    let mut owners: Vec<(NodeId, NodeId)> = Vec::new();
    for lock in locks {
        let root = g.add_root(&project_name(root_name, lock), &unspecified);
        let ids: Vec<NodeId> = lock
            .entries
            .iter()
            .map(|e| g.add_node(&e.module, &Version::new(&e.version), false, true))
            .collect();
        owners.extend(ids.iter().map(|&id| (root, id)));
        for (entry, &id) in lock.entries.iter().zip(&ids) {
            if let Some(version) = declared(&entry.module) {
                g.nodes[id].direct = true;
                g.add_edge(root, id, VersionReq::new(version.unwrap_or_default()));
            }
            for dep in deps(&entry.module, &entry.version)? {
                for (target, &to) in lock.entries.iter().zip(&ids) {
                    if target.module == dep.name
                        && !target.configurations.is_disjoint(&entry.configurations)
                    {
                        g.add_edge(id, to, dep.req.clone());
                    }
                }
            }
        }
    }
    attach_unreachable(&mut g, &owners);
    Ok(g)
}

/// Gradle's name for the project of `lock`.
fn project_name(root_name: &str, lock: &Lockfile) -> String {
    let mut name = root_name.to_string();
    for part in lock.dir.components() {
        name.push(':');
        name.push_str(&part.as_os_str().to_string_lossy());
    }
    name
}

/// Attach every node no root reaches to the first project that locks it,
/// preferring nodes without incoming edges (the tops of detached subtrees).
fn attach_unreachable(g: &mut DepGraph, owners: &[(NodeId, NodeId)]) {
    loop {
        let reached = reachable(g);
        let unreached: Vec<NodeId> = (0..g.nodes.len())
            .filter(|id| !reached.contains(id))
            .collect();
        let Some(&pick) = unreached
            .iter()
            .find(|&&id| g.edges_to(id).next().is_none())
            .or(unreached.first())
        else {
            return;
        };
        let root = owners
            .iter()
            .find(|(_, node)| *node == pick)
            .map(|(root, _)| *root)
            .expect("every module node is locked by some project");
        g.nodes[pick].direct = true;
        g.add_edge(root, pick, VersionReq::new(""));
    }
}

fn reachable(g: &DepGraph) -> HashSet<NodeId> {
    let mut seen: HashSet<NodeId> = g.roots.iter().copied().collect();
    let mut stack: Vec<NodeId> = g.roots.clone();
    while let Some(n) = stack.pop() {
        for e in g.edges_from(n) {
            if seen.insert(e.to) {
                stack.push(e.to);
            }
        }
    }
    seen
}

/// `(module, version, [(dependency, requirement)])`.
#[cfg(test)]
type Row<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

/// `deps` for [`build`] from a fixed table, for tests.
#[cfg(test)]
pub fn table(rows: &[Row]) -> impl FnMut(&str, &str) -> Result<Vec<DeclaredDep>, AdapterError> {
    use std::collections::HashMap;

    let map: HashMap<(String, String), Vec<DeclaredDep>> = rows
        .iter()
        .map(|(m, v, deps)| {
            let deps = deps
                .iter()
                .map(|(name, req)| DeclaredDep {
                    name: name.to_string(),
                    req: VersionReq::new(*req),
                    optional: false,
                })
                .collect();
            ((m.to_string(), v.to_string()), deps)
        })
        .collect();
    move |m, v| {
        Ok(map
            .get(&(m.to_string(), v.to_string()))
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn lock(dir: &str, text: &str) -> Lockfile {
        Lockfile::parse(PathBuf::from(dir), text).unwrap()
    }

    fn edges(g: &DepGraph) -> Vec<String> {
        let mut out: Vec<String> = g
            .edges
            .iter()
            .map(|e| format!("{} -> {} ({})", g.label(e.from), g.label(e.to), e.req))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn rebuilds_edges_from_declarations_and_poms() {
        let locks = [
            lock(
                "",
                "g:text:1.9=compileClasspath,runtimeClasspath\n\
                 g:lang:3.11=compileClasspath,runtimeClasspath\n\
                 g:bom:2.0=compileClasspath\n\
                 g:managed:2.0=compileClasspath\n\
                 g:orphan:1.0=runtimeClasspath\n\
                 g:testonly:1.0=testRuntimeClasspath\n",
            ),
            lock("app", "g:lang:3.12=runtimeClasspath\n"),
        ];
        let declared = |m: &str| match m {
            "g:text" => Some(Some("1.9".to_string())),
            "g:bom" => Some(Some("2.0".to_string())),
            "g:managed" => Some(None),
            "g:lang" => Some(Some("3.12".to_string())),
            _ => None,
        };
        let mut deps = table(&[
            (
                "g:text",
                "1.9",
                &[("g:lang", "3.11"), ("g:testonly", "1.0")],
            ),
            ("g:managed", "2.0", &[]),
        ]);
        let g = build("demo", &locks, &declared, &mut deps).unwrap();
        assert_eq!(
            edges(&g),
            [
                "demo:app@unspecified -> g:lang@3.12 (3.12)",
                "demo@unspecified -> g:bom@2.0 (2.0)",
                "demo@unspecified -> g:lang@3.11 (3.12)",
                "demo@unspecified -> g:managed@2.0 ()",
                "demo@unspecified -> g:orphan@1.0 ()",
                "demo@unspecified -> g:testonly@1.0 ()",
                "demo@unspecified -> g:text@1.9 (1.9)",
                "g:text@1.9 -> g:lang@3.11 (3.11)",
            ]
        );
        assert_eq!(g.roots.len(), 2);
        assert!(g.nodes.iter().filter(|n| n.registry).all(|n| n.direct));
    }

    #[test]
    fn detached_subtrees_hang_off_their_top() {
        let locks = [lock(
            "",
            "g:a:1=runtimeClasspath\ng:b:1=runtimeClasspath\ng:c:1=runtimeClasspath\n",
        )];
        let mut deps = table(&[("g:a", "1", &[("g:b", "1")]), ("g:b", "1", &[("g:c", "1")])]);
        let g = build("demo", &locks, &|_| None, &mut deps).unwrap();
        assert_eq!(
            edges(&g),
            [
                "demo@unspecified -> g:a@1 ()",
                "g:a@1 -> g:b@1 (1)",
                "g:b@1 -> g:c@1 (1)",
            ]
        );
        let direct: Vec<&str> = g
            .nodes
            .iter()
            .filter(|n| n.direct)
            .map(|n| n.name.as_str())
            .collect();
        assert_eq!(direct, ["g:a"]);
    }
}
