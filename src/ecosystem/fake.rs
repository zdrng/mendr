//! In-memory ecosystem for unit tests: a fixed graph, a fake registry and
//! simplified Cargo-like semver semantics.
//!
//! Versions are `MAJOR[.MINOR[.PATCH]][-PRE]`. Requirements are
//! comma-separated comparators: `*`, `^1.2`, `~1.2.3`, `=1.0.0`, `>=1`, `>1`,
//! `<=1`, `<2`, or a bare version (= caret, as in Cargo). Prereleases only
//! satisfy `=` comparators.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;

use super::{AdapterError, Commands, DeclaredDep, Ecosystem, Release};
use crate::model::{BumpKind, Change, DepGraph, NodeId, Strategy, Version, VersionReq};

#[derive(Clone, Debug)]
pub struct FakeRelease {
    pub release: Release,
    pub deps: Vec<DeclaredDep>,
}

#[derive(Debug, Default)]
pub struct Fake {
    pub graph: DepGraph,
    pub registry: HashMap<String, Vec<FakeRelease>>,
    pub unsupported: Vec<Strategy>,
    /// Changes passed to `apply`, in order.
    pub applied: RefCell<Vec<Change>>,
    /// Number of registry calls (to check memoization).
    pub registry_calls: RefCell<usize>,
    /// OSV ecosystem name to report (default `"Fake"`).
    pub osv_name: Option<&'static str>,
}

/// Publish date used by [`Fake::publish`]: old enough for any release-age rule.
pub fn old_date() -> jiff::Timestamp {
    "2020-01-01T00:00:00Z".parse().unwrap()
}

impl Fake {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a root (local) package to the graph.
    pub fn root(&mut self, name: &str, version: &str) -> NodeId {
        self.graph.add_root(name, &Version::new(version))
    }

    /// Add a resolved registry package `name@version` as a dependency of
    /// `from` declared with `req`. `direct` is set when `from` is a root.
    pub fn dep(&mut self, from: NodeId, name: &str, version: &str, req: &str) -> NodeId {
        let direct = self.graph.roots.contains(&from);
        let id = self
            .graph
            .add_node(name, &Version::new(version), direct, true);
        self.graph.add_edge(from, id, VersionReq::new(req));
        id
    }

    /// Publish `name@version` (old publish date, not yanked) with deps.
    pub fn publish(&mut self, name: &str, version: &str, deps: &[(&str, &str)]) -> &mut Self {
        self.publish_with(name, version, deps, Some(old_date()), false)
    }

    pub fn publish_with(
        &mut self,
        name: &str,
        version: &str,
        deps: &[(&str, &str)],
        published_at: Option<jiff::Timestamp>,
        yanked: bool,
    ) -> &mut Self {
        let deps = deps
            .iter()
            .map(|(n, r)| DeclaredDep {
                name: n.to_string(),
                req: VersionReq::new(*r),
                optional: false,
            })
            .collect();
        self.registry
            .entry(name.to_string())
            .or_default()
            .push(FakeRelease {
                release: Release {
                    version: Version::new(version),
                    published_at,
                    yanked,
                },
                deps,
            });
        self
    }
}

type Parsed = (u64, u64, u64, Option<String>, usize);

/// Parse `1.2.3-pre` -> (1, 2, 3, Some("pre"), components given).
fn parse(v: &str) -> Option<Parsed> {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p.to_string())),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut nums = [0u64; 3];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = p.parse().ok()?;
    }
    Some((nums[0], nums[1], nums[2], pre, parts.len()))
}

fn cmp_parsed(a: &Parsed, b: &Parsed) -> Ordering {
    (a.0, a.1, a.2)
        .cmp(&(b.0, b.1, b.2))
        .then_with(|| match (&a.3, &b.3) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(x), Some(y)) => x.cmp(y),
        })
}

fn cmp_versions(a: &str, b: &str) -> Ordering {
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => cmp_parsed(&x, &y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

/// Upper bound (exclusive) for caret requirements, Cargo style.
fn caret_upper(p: &Parsed) -> (u64, u64, u64) {
    let (ma, mi, pa, _, n) = p;
    if *ma > 0 || n == &1 {
        (ma + 1, 0, 0)
    } else if *mi > 0 || n == &2 {
        (0, mi + 1, 0)
    } else {
        (0, 0, pa + 1)
    }
}

fn comparator_matches(c: &str, v: &Parsed) -> bool {
    let c = c.trim();
    if c == "*" || c.is_empty() {
        return v.3.is_none();
    }
    let (op, rest) = ["^", "~", ">=", "<=", ">", "<", "="]
        .iter()
        .find_map(|op| c.strip_prefix(op).map(|r| (*op, r.trim())))
        .unwrap_or(("^", c));
    let Some(b) = parse(rest) else { return false };
    if op == "=" {
        return cmp_parsed(v, &b) == Ordering::Equal;
    }
    if v.3.is_some() {
        return false;
    }
    let ord = cmp_parsed(v, &b);
    let core = (v.0, v.1, v.2);
    match op {
        "^" => ord != Ordering::Less && core < caret_upper(&b),
        "~" => {
            let upper = if b.4 == 1 {
                (b.0 + 1, 0, 0)
            } else {
                (b.0, b.1 + 1, 0)
            };
            ord != Ordering::Less && core < upper
        }
        ">=" => ord != Ordering::Less,
        "<=" => ord != Ordering::Greater,
        ">" => ord == Ordering::Greater,
        "<" => ord == Ordering::Less,
        _ => false,
    }
}

impl Ecosystem for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn osv_ecosystem(&self) -> &'static str {
        self.osv_name.unwrap_or("Fake")
    }

    fn detect(&self, dir: &Path) -> bool {
        dir.join("fake.lock").is_file()
    }

    fn supports(&self, strategy: Strategy) -> bool {
        !self.unsupported.contains(&strategy)
    }

    fn compare(&self, a: &Version, b: &Version) -> Ordering {
        cmp_versions(a.as_str(), b.as_str())
    }

    fn satisfies(&self, req: &VersionReq, version: &Version) -> bool {
        let Some(v) = parse(version.as_str()) else {
            return false;
        };
        req.as_str().split(',').all(|c| comparator_matches(c, &v))
    }

    fn bump_kind(&self, from: &Version, to: &Version) -> BumpKind {
        let (Some(a), Some(b)) = (parse(from.as_str()), parse(to.as_str())) else {
            return BumpKind::Major;
        };
        if a.0 != b.0 || (a.0 == 0 && a.1 != b.1) || (a.0 == 0 && a.1 == 0 && a.2 != b.2) {
            BumpKind::Major
        } else if a.1 != b.1 {
            BumpKind::Minor
        } else {
            BumpKind::Patch
        }
    }

    fn is_prerelease(&self, version: &Version) -> bool {
        version.as_str().contains('-')
    }

    fn resolve_graph(&self, _project_dir: &Path) -> Result<DepGraph, AdapterError> {
        Ok(self.graph.clone())
    }

    fn apply(&self, _workdir: &Path, change: &Change) -> Result<(), AdapterError> {
        if !self.supports(change.strategy()) {
            return Err(AdapterError::Unsupported(change.strategy().to_string()));
        }
        self.applied.borrow_mut().push(change.clone());
        Ok(())
    }

    fn default_commands(&self, _project_dir: &Path) -> Commands {
        Commands {
            install: None,
            build: Some("true".into()),
            test: Some("true".into()),
        }
    }

    fn copy_excludes(&self) -> &'static [&'static str] {
        &[]
    }

    fn releases(&self, package: &str) -> Result<Vec<Release>, AdapterError> {
        *self.registry_calls.borrow_mut() += 1;
        self.registry
            .get(package)
            .map(|rs| rs.iter().map(|r| r.release.clone()).collect())
            .ok_or_else(|| AdapterError::NotFound(package.to_string()))
    }

    fn dependencies_of(
        &self,
        package: &str,
        version: &Version,
    ) -> Result<Vec<DeclaredDep>, AdapterError> {
        *self.registry_calls.borrow_mut() += 1;
        self.registry
            .get(package)
            .and_then(|rs| rs.iter().find(|r| &r.release.version == version))
            .map(|r| r.deps.clone())
            .ok_or_else(|| AdapterError::NotFound(format!("{package}@{version}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sat(req: &str, v: &str) -> bool {
        Fake::new().satisfies(&VersionReq::new(req), &Version::new(v))
    }

    #[test]
    fn requirements() {
        assert!(sat("^1.2.3", "1.9.0"));
        assert!(!sat("^1.2.3", "2.0.0"));
        assert!(!sat("^1.2.3", "1.2.2"));
        assert!(sat("^0.2.3", "0.2.9"));
        assert!(!sat("^0.2.3", "0.3.0"));
        assert!(sat("^0", "0.9.0"));
        assert!(sat("1.0", "1.5.0"));
        assert!(sat("~1.2.3", "1.2.9"));
        assert!(!sat("~1.2.3", "1.3.0"));
        assert!(sat("=1.0.0", "1.0.0"));
        assert!(!sat("=1.0.0", "1.0.1"));
        assert!(sat(">=1, <3", "2.5.0"));
        assert!(!sat(">=1, <3", "3.0.0"));
        assert!(sat("*", "7.0.0"));
        assert!(!sat("^1", "1.1.0-beta"));
    }

    #[test]
    fn ordering_and_bumps() {
        let f = Fake::new();
        let v = Version::new;
        assert_eq!(f.compare(&v("1.10.0"), &v("1.9.0")), Ordering::Greater);
        assert_eq!(f.compare(&v("1.0.0-rc1"), &v("1.0.0")), Ordering::Less);
        assert_eq!(f.compare(&v("1.0"), &v("1.0.0")), Ordering::Equal);
        assert_eq!(f.bump_kind(&v("1.0.0"), &v("1.0.1")), BumpKind::Patch);
        assert_eq!(f.bump_kind(&v("1.0.0"), &v("1.1.0")), BumpKind::Minor);
        assert_eq!(f.bump_kind(&v("1.0.0"), &v("2.0.0")), BumpKind::Major);
        assert_eq!(f.bump_kind(&v("0.1.0"), &v("0.2.0")), BumpKind::Major);
        assert_eq!(f.bump_kind(&v("0.1.0"), &v("0.1.1")), BumpKind::Patch);
    }
}
