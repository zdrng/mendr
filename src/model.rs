//! Core data types shared by every module.
//!
//! # Serialization conventions (stable, used by the JSON report)
//!
//! - Struct fields are `snake_case`.
//! - Enums are serialized as `snake_case` strings (`"direct_bump"`, `"major"`).
//! - Enums with data are internally tagged with a `"kind"` field:
//!   `{"kind": "relock", "package": "...", "from": "...", "to": "..."}`.
//! - [`Version`] and [`VersionReq`] are plain JSON strings.
//!
//! Config files (`mendr.toml`) use kebab-case keys; [`Strategy`] additionally
//! accepts the kebab-case spelling (`"direct-bump"`) when deserializing.

use std::collections::{HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

/// A concrete package version as the ecosystem spells it (`"1.2.3"`).
///
/// Opaque on purpose: ordering and compatibility are defined by the
/// ecosystem adapter (`Ecosystem::compare`, `Ecosystem::satisfies`), never by
/// string comparison.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Version(pub String);

/// A version requirement as declared in a manifest (`"^1.2"`, `">=1, <2"`).
/// Opaque; interpreted only by `Ecosystem::satisfies`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionReq(pub String);

impl Version {
    pub fn new(s: impl Into<String>) -> Self {
        Version(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl VersionReq {
    pub fn new(s: impl Into<String>) -> Self {
        VersionReq(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Index of a node in [`DepGraph::nodes`].
pub type NodeId = usize;

/// One resolved package in the dependency graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Package name as known to the registry and to OSV (for Cargo: the real
    /// crate name, not a rename).
    pub name: String,
    /// The resolved (locked) version.
    pub version: Version,
    /// `true` if some local node (a root / workspace member) declares this
    /// package directly in its manifest.
    pub direct: bool,
    /// `true` if the package comes from the ecosystem's registry. `false` for
    /// the project's own packages (roots, workspace members) and for path/git
    /// dependencies. Non-registry nodes are never scanned or bumped.
    pub registry: bool,
}

/// A dependency edge: `from` declares a dependency on `to` with `req`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    /// The requirement as declared by `from`'s manifest.
    pub req: VersionReq,
}

/// The resolved dependency graph of one project.
///
/// Invariants adapters must uphold:
/// - at most one node per `(name, version)` (use [`DepGraph::add_node`],
///   which dedupes);
/// - `roots` are the project's own packages (Cargo workspace members, the npm
///   root package) and have `registry == false`;
/// - every registry node is reachable from some root;
/// - dev-dependencies of the project's own packages are included (they are
///   built and tested), dev-dependencies of registry packages are not.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub roots: Vec<NodeId>,
}

impl DepGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a node, or returns the existing id for the same `(name, version)`.
    /// If the node exists, `direct` is OR-ed in.
    pub fn add_node(
        &mut self,
        name: &str,
        version: &Version,
        direct: bool,
        registry: bool,
    ) -> NodeId {
        if let Some(id) = self.find(name, version) {
            self.nodes[id].direct |= direct;
            return id;
        }
        self.nodes.push(Node {
            name: name.to_string(),
            version: version.clone(),
            direct,
            registry,
        });
        self.nodes.len() - 1
    }

    /// Adds a local root package (`registry = false`, `direct = false`).
    pub fn add_root(&mut self, name: &str, version: &Version) -> NodeId {
        let id = self.add_node(name, version, false, false);
        if !self.roots.contains(&id) {
            self.roots.push(id);
        }
        id
    }

    /// Adds an edge (duplicates with the same `from`, `to`, `req` are ignored).
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, req: VersionReq) {
        let edge = Edge { from, to, req };
        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    pub fn find(&self, name: &str, version: &Version) -> Option<NodeId> {
        self.nodes
            .iter()
            .position(|n| n.name == name && &n.version == version)
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// Outgoing edges of `id`.
    pub fn edges_from(&self, id: NodeId) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.from == id)
    }

    /// Incoming edges of `id`.
    pub fn edges_to(&self, id: NodeId) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.to == id)
    }

    /// All nodes reachable from `start` (including `start`).
    pub fn reachable_from(&self, start: NodeId) -> HashSet<NodeId> {
        self.bfs(start, |g, n| g.edges_from(n).map(|e| e.to).collect())
    }

    /// All nodes from which `target` is reachable (including `target`).
    pub fn reaching(&self, target: NodeId) -> HashSet<NodeId> {
        self.bfs(target, |g, n| g.edges_to(n).map(|e| e.from).collect())
    }

    fn bfs(&self, start: NodeId, next: impl Fn(&Self, NodeId) -> Vec<NodeId>) -> HashSet<NodeId> {
        let mut seen = HashSet::from([start]);
        let mut queue = VecDeque::from([start]);
        while let Some(n) = queue.pop_front() {
            for m in next(self, n) {
                if seen.insert(m) {
                    queue.push_back(m);
                }
            }
        }
        seen
    }

    /// Up to `limit` acyclic paths from any root to `target`, each starting at
    /// a root and ending at `target`. Deterministic (edge insertion order).
    pub fn paths_to(&self, target: NodeId, limit: usize) -> Vec<Vec<NodeId>> {
        let can_reach = self.reaching(target);
        let mut out = Vec::new();
        for &root in &self.roots {
            if can_reach.contains(&root) {
                let mut path = vec![root];
                self.dfs_paths(target, &can_reach, &mut path, &mut out, limit);
            }
        }
        out
    }

    fn dfs_paths(
        &self,
        target: NodeId,
        can_reach: &HashSet<NodeId>,
        path: &mut Vec<NodeId>,
        out: &mut Vec<Vec<NodeId>>,
        limit: usize,
    ) {
        if out.len() >= limit {
            return;
        }
        let last = *path.last().expect("path is never empty");
        if last == target {
            out.push(path.clone());
            return;
        }
        let next: Vec<NodeId> = self.edges_from(last).map(|e| e.to).collect();
        for n in next {
            if can_reach.contains(&n) && !path.contains(&n) {
                path.push(n);
                self.dfs_paths(target, can_reach, path, out, limit);
                path.pop();
            }
        }
    }

    /// `"name@version"` label used in reports.
    pub fn label(&self, id: NodeId) -> String {
        let n = &self.nodes[id];
        format!("{}@{}", n.name, n.version)
    }
}

/// How big a version change is, as defined by the ecosystem
/// (`Ecosystem::bump_kind`; Cargo/npm treat `0.x -> 0.y` as major).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BumpKind {
    Patch,
    Minor,
    Major,
}

/// A fix strategy, cheapest first.
///
/// JSON: `"relock"`, `"direct_bump"`, `"override"`. TOML config also accepts
/// `"direct-bump"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Only the lockfile changes: the parent's declared requirement already
    /// allows a fixed version.
    Relock,
    /// Bump the requirement of a direct dependency in the user's manifest.
    #[serde(alias = "direct-bump")]
    DirectBump,
    /// Force a version through the ecosystem's override mechanism (npm
    /// `overrides`, Gradle constraints).
    Override,
}

impl Strategy {
    pub const ALL: [Strategy; 3] = [Strategy::Relock, Strategy::DirectBump, Strategy::Override];
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Strategy::Relock => "relock",
            Strategy::DirectBump => "direct_bump",
            Strategy::Override => "override",
        })
    }
}

/// A concrete change to apply to a project copy (`Ecosystem::apply`).
///
/// JSON: `{"kind": "relock" | "direct_bump" | "override", ...fields}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    /// Move `package` from `from` to `to` in the lockfile only. Every parent's
    /// declared requirement already allows `to`.
    Relock {
        package: String,
        from: Version,
        to: Version,
    },
    /// Raise the declared requirement of the direct dependency `package` so it
    /// resolves to `to` (currently locked at `from`). The adapter writes the
    /// ecosystem's natural requirement for `to` (Cargo: `"1.2.3"`, npm: keep
    /// the existing range operator, e.g. `"^1.2.3"`) in every local manifest
    /// that declares `package`, then re-locks.
    DirectBump {
        package: String,
        from: Version,
        to: Version,
        bump: BumpKind,
    },
    /// Force every copy of `package` currently at `from` to `to` using the
    /// ecosystem's override mechanism.
    Override {
        package: String,
        from: Version,
        to: Version,
    },
}

impl Change {
    pub fn strategy(&self) -> Strategy {
        match self {
            Change::Relock { .. } => Strategy::Relock,
            Change::DirectBump { .. } => Strategy::DirectBump,
            Change::Override { .. } => Strategy::Override,
        }
    }

    /// The package whose version this change moves.
    pub fn package(&self) -> &str {
        match self {
            Change::Relock { package, .. }
            | Change::DirectBump { package, .. }
            | Change::Override { package, .. } => package,
        }
    }

    pub fn from(&self) -> &Version {
        match self {
            Change::Relock { from, .. }
            | Change::DirectBump { from, .. }
            | Change::Override { from, .. } => from,
        }
    }

    pub fn to(&self) -> &Version {
        match self {
            Change::Relock { to, .. }
            | Change::DirectBump { to, .. }
            | Change::Override { to, .. } => to,
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} -> {}",
            self.strategy(),
            self.package(),
            self.from(),
            self.to()
        )
    }
}

/// Result of handling one finding.
///
/// JSON: `{"kind": "planned" | "fixed" | "skipped" | "failed", ...}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// A change was planned but not verified (`--plan-only`, or verification
    /// has not run yet).
    Planned { strategy: Strategy, change: Change },
    /// The change was applied in a copy and build + test passed.
    Fixed { strategy: Strategy, change: Change },
    /// mendr decided not to attempt a fix.
    Skipped { reason: SkipReason },
    /// mendr attempted a fix and it did not work.
    Failed { reason: FailReason },
}

impl Outcome {
    /// Short stable label: `"planned"`, `"fixed"`, `"skipped:<reason>"`,
    /// `"failed:<reason>"` (the format of `expected.json`).
    #[cfg(test)]
    pub fn label(&self) -> String {
        match self {
            Outcome::Planned { .. } => "planned".into(),
            Outcome::Fixed { .. } => "fixed".into(),
            Outcome::Skipped { reason } => format!("skipped:{}", reason.kind()),
            Outcome::Failed { reason } => format!("failed:{}", reason.kind()),
        }
    }

    /// `true` if the finding needs no further action: fixed, planned (a fix
    /// exists), ignored, or below the severity threshold. Drives exit code 1.
    pub fn is_resolved(&self) -> bool {
        match self {
            Outcome::Planned { .. } | Outcome::Fixed { .. } => true,
            Outcome::Skipped { reason } => {
                matches!(
                    reason,
                    SkipReason::Ignored { .. } | SkipReason::BelowMinSeverity { .. }
                )
            }
            Outcome::Failed { .. } => false,
        }
    }
}

/// Why mendr did not attempt a fix. JSON: `{"kind": "<snake_case>", ...}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkipReason {
    /// No released, non-yanked, non-prerelease version of `package` newer than
    /// the current one is free of known advisories.
    NoPatchedVersion { package: String },
    /// No newer version of the direct dependency `package` resolves to a
    /// non-vulnerable `vulnerable`, and no other strategy applied.
    NoParentVersionFixes { package: String, vulnerable: String },
    /// The only fix is a major bump of `package` and `allow-major` is off.
    MajorBumpBlocked {
        package: String,
        from: Version,
        to: Version,
    },
    /// The only fix uses a strategy this ecosystem does not support.
    StrategyUnsupported { strategy: Strategy },
    /// Every candidate fix version is younger than `min-release-age` (or has
    /// no known publish date). `version` is the first rejected candidate.
    ReleaseTooRecent {
        package: String,
        version: Version,
        published_at: Option<jiff::Timestamp>,
        min_release_age_secs: u64,
    },
    /// Matched an `[[ignore]]` entry that has not expired.
    Ignored {
        reason: String,
        expires: Option<String>,
    },
    /// The advisory's severity is below `min-severity`.
    BelowMinSeverity {
        severity: crate::osv::SeverityLevel,
        min_severity: crate::osv::SeverityLevel,
    },
}

impl SkipReason {
    /// The serde tag (`"no_patched_version"`, ...).
    pub fn kind(&self) -> &'static str {
        match self {
            SkipReason::NoPatchedVersion { .. } => "no_patched_version",
            SkipReason::NoParentVersionFixes { .. } => "no_parent_version_fixes",
            SkipReason::MajorBumpBlocked { .. } => "major_bump_blocked",
            SkipReason::StrategyUnsupported { .. } => "strategy_unsupported",
            SkipReason::ReleaseTooRecent { .. } => "release_too_recent",
            SkipReason::Ignored { .. } => "ignored",
            SkipReason::BelowMinSeverity { .. } => "below_min_severity",
        }
    }
}

/// Which verification step a command belonged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Apply,
    Install,
    Build,
    Test,
}

/// Why an attempted fix failed. JSON: `{"kind": "<snake_case>", ...}`.
/// `log_tail` holds the last lines of combined stdout/stderr (see
/// [`log_tail`]); it is not a stable field for comparisons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FailReason {
    /// The unmodified project already fails at `step`; nothing was attempted.
    BaselineFailed {
        step: Step,
        command: String,
        exit_code: Option<i32>,
        log_tail: String,
    },
    /// The package manager could not resolve the change (e.g. npm peer
    /// dependency errors, Cargo version conflicts).
    ResolutionConflict { detail: String },
    /// The change pulled in a package version younger than `min-release-age`.
    ReleaseAgePolicyViolated {
        package: String,
        version: Version,
        published_at: Option<jiff::Timestamp>,
    },
    InstallFailed {
        command: String,
        exit_code: Option<i32>,
        log_tail: String,
    },
    BuildFailed {
        command: String,
        exit_code: Option<i32>,
        log_tail: String,
    },
    TestFailed {
        command: String,
        exit_code: Option<i32>,
        log_tail: String,
    },
    Timeout {
        step: Step,
        command: String,
        after_secs: u64,
    },
    /// After the change, the rescan found a vulnerability that was not there
    /// before.
    NewVulnerabilityIntroduced {
        advisory: String,
        package: String,
        version: Version,
    },
    /// The vulnerable version is still in the graph after applying the change.
    StillVulnerable { package: String, version: Version },
    /// The adapter could not find or edit the declaration to change.
    ManifestNotEditable { detail: String },
    /// Anything else (registry/network errors, I/O, adapter bugs).
    Error { message: String },
}

impl FailReason {
    /// The serde tag (`"build_failed"`, ...).
    pub fn kind(&self) -> &'static str {
        match self {
            FailReason::BaselineFailed { .. } => "baseline_failed",
            FailReason::ResolutionConflict { .. } => "resolution_conflict",
            FailReason::ReleaseAgePolicyViolated { .. } => "release_age_policy_violated",
            FailReason::InstallFailed { .. } => "install_failed",
            FailReason::BuildFailed { .. } => "build_failed",
            FailReason::TestFailed { .. } => "test_failed",
            FailReason::Timeout { .. } => "timeout",
            FailReason::NewVulnerabilityIntroduced { .. } => "new_vulnerability_introduced",
            FailReason::StillVulnerable { .. } => "still_vulnerable",
            FailReason::ManifestNotEditable { .. } => "manifest_not_editable",
            FailReason::Error { .. } => "error",
        }
    }
}

/// Number of lines kept by [`log_tail`].
pub const LOG_TAIL_LINES: usize = 40;

/// The last `LOG_TAIL_LINES` lines of `output`.
pub fn log_tail(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::new(s)
    }

    #[test]
    fn graph_dedupes_nodes_and_finds_paths() {
        let mut g = DepGraph::new();
        let root = g.add_root("app", &v("0.1.0"));
        let a = g.add_node("a", &v("1.0.0"), true, true);
        let b = g.add_node("b", &v("1.0.0"), true, true);
        let p = g.add_node("p", &v("1.0.0"), false, true);
        assert_eq!(g.add_node("a", &v("1.0.0"), false, true), a);
        g.add_edge(root, a, VersionReq::new("^1"));
        g.add_edge(root, b, VersionReq::new("^1"));
        g.add_edge(a, p, VersionReq::new("^1"));
        g.add_edge(b, p, VersionReq::new("^1"));
        g.add_edge(p, a, VersionReq::new("^1")); // cycle
        let paths = g.paths_to(p, 10);
        assert_eq!(paths, vec![vec![root, a, p], vec![root, b, p]]);
        assert_eq!(g.paths_to(p, 1).len(), 1);
        assert!(g.reaching(p).contains(&root));
        assert_eq!(g.label(p), "p@1.0.0");
    }

    #[test]
    fn serde_shapes_are_stable() {
        let change = Change::DirectBump {
            package: "a".into(),
            from: v("1.0.0"),
            to: v("2.0.0"),
            bump: BumpKind::Major,
        };
        let json = serde_json::to_value(&change).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kind": "direct_bump", "package": "a", "from": "1.0.0", "to": "2.0.0", "bump": "major"})
        );
        let outcome = Outcome::Skipped {
            reason: SkipReason::NoPatchedVersion {
                package: "p".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            serde_json::json!({"kind": "skipped", "reason": {"kind": "no_patched_version", "package": "p"}})
        );
        assert_eq!(outcome.label(), "skipped:no_patched_version");
        let failed = Outcome::Failed {
            reason: FailReason::Timeout {
                step: Step::Test,
                command: "cargo test".into(),
                after_secs: 5,
            },
        };
        assert_eq!(failed.label(), "failed:timeout");
        let back: Outcome = serde_json::from_value(serde_json::to_value(&failed).unwrap()).unwrap();
        assert_eq!(back, failed);
        let s: Strategy = serde_json::from_str("\"direct-bump\"").unwrap();
        assert_eq!(s, Strategy::DirectBump);
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"direct_bump\"");
    }

    #[test]
    fn reason_kind_matches_serde_tag() {
        let reasons = [
            FailReason::ResolutionConflict {
                detail: String::new(),
            },
            FailReason::StillVulnerable {
                package: "p".into(),
                version: v("1"),
            },
            FailReason::Error {
                message: String::new(),
            },
        ];
        for r in reasons {
            let json = serde_json::to_value(&r).unwrap();
            assert_eq!(json["kind"], r.kind());
        }
        let skip = SkipReason::MajorBumpBlocked {
            package: "a".into(),
            from: v("1"),
            to: v("2"),
        };
        assert_eq!(serde_json::to_value(&skip).unwrap()["kind"], skip.kind());
    }

    #[test]
    fn log_tail_keeps_last_lines() {
        let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
        let tail = log_tail(&text);
        assert_eq!(tail.lines().count(), LOG_TAIL_LINES);
        assert!(tail.ends_with("line 99"));
    }
}
