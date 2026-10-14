//! Ecosystem-agnostic fix planning.
//!
//! For every vulnerable registry node `P@v` the planner:
//!
//! 1. Splits the paths to `P` by **via**: the first registry package on the
//!    path, i.e. the dependency a local manifest declares (`via == P` when
//!    `P` itself is direct). Each `(advisory, P@v, via)` is one [`Finding`]
//!    with up to [`MAX_PATHS`] of its paths. Only a via declared by a root
//!    (the project's own manifests, not a path/git dependency's) with a
//!    version of its own (a non-empty requirement) can be bumped.
//! 2. Classifies advisories: active `[[ignore]]` -> `skipped:ignored`; below
//!    `min-severity` -> `skipped:below_min_severity`.
//! 3. Computes fix candidates for `P`: released versions > `v`, not yanked,
//!    not prerelease (unless `v` is), and not affected by any advisory for
//!    `P` that is neither ignored nor below `min-severity`. None ->
//!    `skipped:no_patched_version`.
//! 4. Tries the policy's strategies in order, first success wins:
//!    - **relock**: some candidate satisfies every parent requirement of `P`
//!      inside the via group (of every parent of `P` if the ecosystem has
//!      `shared_copies`, e.g. Cargo) -> `Change::Relock`.
//!    - **direct bump**: if `via == P`, bump `P` to a candidate. Otherwise walk
//!      newer versions of `via` ascending and pick the first that is not
//!      affected by an advisory for `via` itself and whose dependency subtree
//!      can resolve to a non-vulnerable `P` (see [`Planner::subtree_ok`]) ->
//!      `Change::DirectBump`. Major bumps need `allow-major`.
//!    - **override**: force `P` to a candidate (major needs `allow-major`).
//!
//!    Every picked version must pass `min-release-age`. With
//!    `target = "latest-compatible"` the highest acceptable version that is
//!    not a major bump from the minimal one is picked instead.
//! 5. If nothing worked the reason is, in priority order: the first policy
//!    block met (`major_bump_blocked`, `release_too_recent`), else
//!    `no_parent_version_fixes` (direct bump was tried), else
//!    `strategy_unsupported`, else `no_parent_version_fixes`.
//! 6. Merges changes: same `(package, from)` relocks/bumps collapse into one
//!    change (a bump wins over a relock) with the highest `to` if it still
//!    fixes every merged finding, else the lower one; a change that fits
//!    neither stays separate. Same for overrides. Findings point at the
//!    merged change. A merged bump/override that became major without
//!    `allow-major` -> `skipped:major_bump_blocked`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::config::{IgnoreRule, Policy, TargetPolicy};
use crate::ecosystem::{AdapterError, DeclaredDep, Ecosystem, Release};
use crate::model::{
    BumpKind, Change, DepGraph, Node, NodeId, Outcome, SkipReason, Strategy, Version, VersionReq,
};
use crate::osv::{self, Advisory, Severity};
use crate::rules::{self, IgnoreMatch};

/// Max paths reported per finding.
pub const MAX_PATHS: usize = 5;
/// Max newer versions of a direct dependency examined.
pub const MAX_CANDIDATES: usize = 200;
/// Max depth of the registry subtree walk below a direct dependency.
pub const MAX_DEPTH: usize = 8;

/// Advisory summary embedded in a finding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryRef {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Option<Severity>,
}

impl From<&Advisory> for AdvisoryRef {
    fn from(a: &Advisory) -> Self {
        AdvisoryRef {
            id: a.id.clone(),
            aliases: a.aliases.clone(),
            summary: a.summary.clone(),
            severity: a.severity,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub name: String,
    pub version: Version,
}

/// One advisory affecting one package version through one direct dependency.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub advisory: AdvisoryRef,
    /// The vulnerable package and its locked version.
    pub package: String,
    pub version: Version,
    /// The direct dependency the paths go through (== package when direct).
    pub via: PackageRef,
    /// Up to [`MAX_PATHS`] paths, each `["root@0.1.0", "via@1.0.0", ..., "package@version"]`.
    pub paths: Vec<Vec<String>>,
    /// Strategy of `change`, if any.
    pub strategy: Option<Strategy>,
    /// The planned (merged) change that fixes this finding, if any.
    pub change: Option<Change>,
    pub outcome: Outcome,
}

/// Planner output for one project.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProjectPlan {
    /// Sorted by (package, version, advisory id, via); versions in the
    /// ecosystem's order.
    pub findings: Vec<Finding>,
    /// Distinct merged changes, in order of first use.
    pub changes: Vec<Change>,
}

pub struct PlanInput<'a> {
    pub eco: &'a dyn Ecosystem,
    pub graph: &'a DepGraph,
    /// All advisories for the graph's packages (`Osv::advisories`).
    pub advisories: &'a [Advisory],
    pub policy: &'a Policy,
    pub ignores: &'a [IgnoreRule],
    pub now: Timestamp,
}

/// Plan fixes for one project. Never fails: registry errors become
/// `failed:error` outcomes on the affected findings.
pub fn plan(input: &PlanInput) -> ProjectPlan {
    let eco = input.eco;
    let mut planner = Planner::new(input);
    let mut findings = planner.findings();
    findings.sort_by(|(a, _), (b, _)| {
        a.package
            .cmp(&b.package)
            .then_with(|| eco.compare(&a.version, &b.version))
            .then_with(|| a.advisory.id.cmp(&b.advisory.id))
            .then_with(|| a.via.name.cmp(&b.via.name))
            .then_with(|| eco.compare(&a.via.version, &b.via.version))
    });
    let (mut findings, goals): (Vec<Finding>, Vec<Option<Goal>>) = findings.into_iter().unzip();
    let changes = merge(eco, input.policy, &mut findings, &mut |i, change| {
        goals[i]
            .as_ref()
            .is_some_and(|goal| planner.fixes(goal, change.package(), change.to()))
    });
    ProjectPlan { findings, changes }
}

/// Paths to a vulnerable node that share the same direct dependency.
struct Group {
    via: NodeId,
    /// Whether a root (the project's own manifest) declares `via`; only then
    /// can it be bumped.
    editable: bool,
    /// Requirements a relock of `P` must satisfy: those of its parents
    /// inside this group, or of all its parents with `shared_copies`.
    parent_reqs: Vec<VersionReq>,
    /// Names of registry packages between `via` and `P` (exclusive).
    corridor: BTreeSet<String>,
    paths: Vec<Vec<String>>,
}

/// What a planned change must achieve for its finding; a merged change is
/// re-checked against it (see [`Planner::fixes`]).
struct Goal {
    /// The vulnerable package.
    target: String,
    /// The finding's group corridor (for a bump of its via).
    corridor: BTreeSet<String>,
    /// Requirements the new version must satisfy (a relock's parent
    /// requirements; empty otherwise).
    reqs: Vec<VersionReq>,
}

/// How one candidate version fares in [`Planner::select`].
enum Verdict {
    Accept,
    Reject,
    /// Rejected by policy; remember the reason, keep looking.
    Blocked(SkipReason),
    /// Rejected by policy; later candidates will fail too.
    Stop(SkipReason),
}

/// Context for checking a candidate subtree against one vulnerable package.
struct Target<'b> {
    name: &'b str,
    advisories: Vec<&'b Advisory>,
}

/// Settled [`Planner::subtree_ok`] answers per `(package, version)`, with
/// the smallest depth each may be reused at (see [`Subtree::cut`]).
type Memo = HashMap<(String, Version), (bool, usize)>;

/// Answer of [`Planner::subtree_ok`] for one node.
#[derive(Clone, Copy)]
struct Subtree {
    ok: bool,
    /// Smallest depth of an in-progress node assumed fine (`usize::MAX` if
    /// none).
    assumed: usize,
    /// Whether a depth cut assumed something fine. Such an answer is reused
    /// only at the depth it was computed at or deeper, where a fresh walk
    /// would not look further.
    cut: bool,
}

impl Subtree {
    const OK: Subtree = Subtree {
        ok: true,
        assumed: usize::MAX,
        cut: false,
    };
    const FAIL: Subtree = Subtree {
        ok: false,
        ..Self::OK
    };
}

/// State of the [`Planner::subtree_ok`] walks for one target and corridor.
struct Walk<'w> {
    target: &'w Target<'w>,
    corridor: &'w BTreeSet<String>,
    memo: Memo,
    /// Nodes being evaluated, with their depth.
    stack: HashMap<(String, Version), usize>,
}

struct Planner<'a> {
    input: &'a PlanInput<'a>,
    releases: HashMap<String, Rc<[Release]>>,
    deps: HashMap<(String, Version), Rc<[DeclaredDep]>>,
    /// What a fresh resolution picks per `(package, requirement)`.
    picks: HashMap<(String, VersionReq), Option<Version>>,
    /// `(parent, dependency)` names of the graph's edges.
    edge_names: HashSet<(&'a str, &'a str)>,
    /// Subtree results per target package and corridor (they depend on
    /// nothing else), kept across groups and findings.
    memos: HashMap<String, Vec<(BTreeSet<String>, Memo)>>,
}

impl<'a> Planner<'a> {
    fn new(input: &'a PlanInput<'a>) -> Self {
        let g = input.graph;
        let edge_names = g
            .edges
            .iter()
            .map(|e| (g.node(e.from).name.as_str(), g.node(e.to).name.as_str()))
            .collect();
        Planner {
            input,
            releases: HashMap::new(),
            deps: HashMap::new(),
            picks: HashMap::new(),
            edge_names,
            memos: HashMap::new(),
        }
    }

    fn eco(&self) -> &'a dyn Ecosystem {
        self.input.eco
    }

    fn releases(&mut self, package: &str) -> Result<Rc<[Release]>, AdapterError> {
        if let Some(r) = self.releases.get(package) {
            return Ok(Rc::clone(r));
        }
        let r: Rc<[Release]> = self.eco().releases(package)?.into();
        self.releases.insert(package.to_string(), Rc::clone(&r));
        Ok(r)
    }

    fn dependencies_of(
        &mut self,
        package: &str,
        version: &Version,
    ) -> Result<Rc<[DeclaredDep]>, AdapterError> {
        let key = (package.to_string(), version.clone());
        if let Some(d) = self.deps.get(&key) {
            return Ok(Rc::clone(d));
        }
        let d: Rc<[DeclaredDep]> = self.eco().dependencies_of(package, version)?.into();
        self.deps.insert(key, Rc::clone(&d));
        Ok(d)
    }

    /// The version a fresh resolution picks for `package` under `req`: the
    /// highest non-yanked release that satisfies it (prereleases only where
    /// the ecosystem's `satisfies` allows them).
    fn pick(&mut self, package: &str, req: &VersionReq) -> Result<Option<Version>, AdapterError> {
        let key = (package.to_string(), req.clone());
        if let Some(v) = self.picks.get(&key) {
            return Ok(v.clone());
        }
        let eco = self.eco();
        let picked = self
            .releases(package)?
            .iter()
            .filter(|r| !r.yanked && eco.satisfies(req, &r.version))
            .max_by(|a, b| eco.compare(&a.version, &b.version))
            .map(|r| r.version.clone());
        self.picks.insert(key, picked.clone());
        Ok(picked)
    }

    /// Non-yanked releases newer than `current`, sorted ascending.
    /// Prereleases only if `current` is a prerelease.
    fn newer(&self, releases: &[Release], current: &Version) -> Vec<Release> {
        let eco = self.eco();
        let allow_pre = eco.is_prerelease(current);
        let mut out: Vec<Release> = releases
            .iter()
            .filter(|r| !r.yanked && (allow_pre || !eco.is_prerelease(&r.version)))
            .filter(|r| eco.compare(&r.version, current).is_gt())
            .cloned()
            .collect();
        out.sort_by(|a, b| eco.compare(&a.version, &b.version));
        out
    }

    fn age_ok(&self, r: &Release) -> bool {
        rules::release_age_ok(
            r.published_at,
            self.input.policy.min_release_age,
            self.input.now,
        )
    }

    fn too_recent(&self, package: &str, r: &Release) -> SkipReason {
        SkipReason::ReleaseTooRecent {
            package: package.to_string(),
            version: r.version.clone(),
            published_at: r.published_at,
            min_release_age_secs: self.input.policy.min_release_age.as_secs(),
        }
    }

    /// Policy verdict for moving `node` to `c` by a manifest bump or an
    /// override: a major bump needs `allow-major`, and `c` must pass
    /// `min-release-age`.
    fn move_verdict(&self, node: &Node, c: &Release) -> Verdict {
        let bump = self.eco().bump_kind(&node.version, &c.version);
        if !rules::bump_allowed(bump, self.input.policy) {
            Verdict::Stop(SkipReason::MajorBumpBlocked {
                package: node.name.clone(),
                from: node.version.clone(),
                to: c.version.clone(),
            })
        } else if !self.age_ok(c) {
            Verdict::Blocked(self.too_recent(&node.name, c))
        } else {
            Verdict::Accept
        }
    }

    /// Walk ascending `cands`; return the accepted version per target policy,
    /// or the first policy block met (if any). Once a version is chosen,
    /// blocks no longer matter (`Stop` still ends the walk).
    fn select(
        &mut self,
        cands: &[Release],
        mut verdict: impl FnMut(&mut Self, &Release) -> Result<Verdict, AdapterError>,
    ) -> Result<Result<Release, Option<SkipReason>>, AdapterError> {
        let mut blocked = None;
        let mut chosen: Option<Release> = None;
        for c in cands {
            if let Some(min) = &chosen
                && (self.input.policy.target == TargetPolicy::Minimal
                    || self.eco().bump_kind(&min.version, &c.version) == BumpKind::Major)
            {
                break;
            }
            match verdict(self, c)? {
                Verdict::Accept => chosen = Some(c.clone()),
                Verdict::Reject => {}
                Verdict::Blocked(r) => {
                    blocked.get_or_insert(r);
                }
                Verdict::Stop(r) => {
                    blocked.get_or_insert(r);
                    break;
                }
            }
        }
        Ok(chosen.ok_or(blocked))
    }

    /// Why `adv` is not acted on: an active `[[ignore]]` or a severity below
    /// `min-severity`. `None` if it counts.
    fn skip_reason(&self, adv: &Advisory) -> Option<SkipReason> {
        let input = self.input;
        if let IgnoreMatch::Active(rule) =
            rules::ignore_match(adv, input.ignores, rules::today(input.now))
        {
            return Some(SkipReason::Ignored {
                reason: rule.reason.clone(),
                expires: rule.expires.map(|d| d.to_string()),
            });
        }
        if !rules::severity_ok(adv.severity, input.policy.min_severity) {
            return Some(SkipReason::BelowMinSeverity {
                severity: adv
                    .severity
                    .map(|s| s.level)
                    .expect("unknown severity always passes"),
                min_severity: input.policy.min_severity,
            });
        }
        None
    }

    /// Advisories for `package` that count (not skipped, see
    /// [`Planner::skip_reason`]).
    fn active_advisories(&self, package: &str) -> Vec<&'a Advisory> {
        let input = self.input;
        input
            .advisories
            .iter()
            .filter(|a| a.mentions(input.eco, package) && self.skip_reason(a).is_none())
            .collect()
    }

    /// Unsorted findings, each with the [`Goal`] of its change (if any).
    fn findings(&mut self) -> Vec<(Finding, Option<Goal>)> {
        let input = self.input;
        let mut out = Vec::new();
        for vn in osv::vulnerabilities_for(input.graph, input.eco, input.advisories) {
            let node = input.graph.node(vn.node);
            let groups = self.groups(vn.node);
            let mut active = Vec::new();
            let mut skipped = Vec::new();
            for &i in &vn.advisories {
                let adv = &input.advisories[i];
                match self.skip_reason(adv) {
                    Some(reason) => skipped.push((adv, reason)),
                    None => active.push(adv),
                }
            }

            let decisions: Vec<Result<Change, Outcome>> = if active.is_empty() {
                Vec::new()
            } else {
                match self.candidates(&node.name, &node.version) {
                    Err(e) => groups
                        .iter()
                        .map(|_| {
                            Err(Outcome::Failed {
                                reason: e.to_fail_reason(),
                            })
                        })
                        .collect(),
                    Ok((_, cands)) if cands.is_empty() => groups
                        .iter()
                        .map(|_| {
                            Err(Outcome::Skipped {
                                reason: SkipReason::NoPatchedVersion {
                                    package: node.name.clone(),
                                },
                            })
                        })
                        .collect(),
                    Ok((target, cands)) => groups
                        .iter()
                        .map(|g| self.decide(vn.node, g, &target, &cands))
                        .collect(),
                }
            };

            for (gi, g) in groups.iter().enumerate() {
                let via = input.graph.node(g.via);
                let finding = |adv: &Advisory, change: Option<Change>, outcome: Outcome| Finding {
                    advisory: adv.into(),
                    package: node.name.clone(),
                    version: node.version.clone(),
                    via: PackageRef {
                        name: via.name.clone(),
                        version: via.version.clone(),
                    },
                    paths: g.paths.clone(),
                    strategy: change.as_ref().map(Change::strategy),
                    change,
                    outcome,
                };
                let goal = |change: &Change| Goal {
                    target: node.name.clone(),
                    corridor: g.corridor.clone(),
                    reqs: match change {
                        Change::Relock { .. } => g.parent_reqs.clone(),
                        _ => Vec::new(),
                    },
                };
                for adv in &active {
                    out.push(match &decisions[gi] {
                        Ok(change) => (
                            finding(
                                adv,
                                Some(change.clone()),
                                Outcome::Planned {
                                    strategy: change.strategy(),
                                    change: change.clone(),
                                },
                            ),
                            Some(goal(change)),
                        ),
                        Err(outcome) => (finding(adv, None, outcome.clone()), None),
                    });
                }
                for (adv, reason) in &skipped {
                    let outcome = Outcome::Skipped {
                        reason: reason.clone(),
                    };
                    out.push((finding(adv, None, outcome), None));
                }
            }
        }
        out
    }

    /// Fix candidates for `package@current` (see module docs), plus the
    /// context needed to check subtrees.
    fn candidates(
        &mut self,
        package: &'a str,
        current: &Version,
    ) -> Result<(Target<'a>, Vec<Release>), AdapterError> {
        let releases = self.releases(package)?;
        let target = Target {
            name: package,
            advisories: self.active_advisories(package),
        };
        let cands = self
            .newer(&releases, current)
            .into_iter()
            .filter(|r| target.is_safe(self.eco(), &r.version))
            .collect();
        Ok((target, cands))
    }

    fn groups(&self, p: NodeId) -> Vec<Group> {
        let g = self.input.graph;
        let reaching_p = g.reaching(p);
        let is_local = |id: NodeId| !g.node(id).registry;
        let mut vias: Vec<NodeId> = reaching_p
            .iter()
            .copied()
            .filter(|&id| g.node(id).registry && g.edges_to(id).any(|e| is_local(e.from)))
            .collect();
        vias.sort_unstable();

        let shared = self.eco().shared_copies();
        vias.into_iter()
            .map(|via| {
                let reach = g.reachable_from(via);
                let in_group = |from: NodeId| {
                    if via == p {
                        is_local(from)
                    } else {
                        !is_local(from) && reach.contains(&from)
                    }
                };
                let parent_reqs = g
                    .edges_to(p)
                    .filter(|e| shared || in_group(e.from))
                    .map(|e| e.req.clone())
                    .collect();
                let corridor = if via == p {
                    BTreeSet::new()
                } else {
                    reach
                        .intersection(&reaching_p)
                        .filter(|&&id| id != p && id != via && !is_local(id))
                        .map(|&id| g.node(id).name.clone())
                        .collect()
                };
                // Paths whose first registry package is `via`: local nodes
                // that lead to `via` through local nodes only, then anything.
                let mut locals_to_via = HashSet::new();
                let mut stack = vec![via];
                while let Some(n) = stack.pop() {
                    for e in g.edges_to(n) {
                        if is_local(e.from) && locals_to_via.insert(e.from) {
                            stack.push(e.from);
                        }
                    }
                }
                let paths = g
                    .paths_to(p, &reaching_p, MAX_PATHS, &|path, next| {
                        next == via || path.contains(&via) || locals_to_via.contains(&next)
                    })
                    .iter()
                    .map(|path| path.iter().map(|&id| g.label(id)).collect())
                    .collect();
                Group {
                    via,
                    editable: g
                        .edges_to(via)
                        .any(|e| g.roots.contains(&e.from) && !e.req.as_str().is_empty()),
                    parent_reqs,
                    corridor,
                    paths,
                }
            })
            .collect()
    }

    /// Try the strategies for one group.
    fn decide(
        &mut self,
        p: NodeId,
        group: &Group,
        target: &Target,
        cands: &[Release],
    ) -> Result<Change, Outcome> {
        let fail = |e: AdapterError| Outcome::Failed {
            reason: e.to_fail_reason(),
        };
        let policy = self.input.policy;
        let eco = self.eco();
        let node = self.input.graph.node(p);
        let mut blocked: Option<SkipReason> = None;
        let mut bump_reason: Option<SkipReason> = None;
        let mut unsupported: Option<SkipReason> = None;

        for &strategy in &policy.strategies {
            if !eco.supports(strategy) {
                unsupported.get_or_insert(SkipReason::StrategyUnsupported { strategy });
                continue;
            }
            if strategy == Strategy::DirectBump && !group.editable {
                continue; // declared only by a path/git dependency
            }
            let result = match strategy {
                Strategy::Relock => {
                    let reqs = &group.parent_reqs;
                    let allowed: Vec<Release> = if reqs.is_empty() {
                        Vec::new()
                    } else {
                        cands
                            .iter()
                            .filter(|c| reqs.iter().all(|r| eco.satisfies(r, &c.version)))
                            .cloned()
                            .collect()
                    };
                    self.select(&allowed, |s, c| {
                        Ok(if s.age_ok(c) {
                            Verdict::Accept
                        } else {
                            Verdict::Blocked(s.too_recent(&node.name, c))
                        })
                    })
                    .map_err(fail)?
                    .map(|r| Change::Relock {
                        package: node.name.clone(),
                        from: node.version.clone(),
                        to: r.version,
                    })
                }
                Strategy::DirectBump => {
                    let via = self.input.graph.node(group.via);
                    let res = if group.via == p {
                        // `cands` are already safe from every advisory for `p`.
                        self.select(cands, |s, c| Ok(s.move_verdict(via, c)))
                    } else {
                        let rel = self.releases(&via.name).map_err(fail)?;
                        let mut via_cands = self.newer(&rel, &via.version);
                        via_cands.truncate(MAX_CANDIDATES);
                        // The new version of the via must not be vulnerable itself.
                        let via_advisories = self.active_advisories(&via.name);
                        let mut walk = self.walk(target, &group.corridor);
                        let res = self.select(&via_cands, |s, c| {
                            if via_advisories
                                .iter()
                                .any(|a| a.affects(eco, &via.name, &c.version))
                                || !s.subtree_ok(&via.name, &c.version, &mut walk, 0)?.ok
                            {
                                return Ok(Verdict::Reject);
                            }
                            Ok(s.move_verdict(via, c))
                        });
                        self.store(walk);
                        res
                    }
                    .map_err(fail)?;
                    if matches!(res, Err(None)) {
                        bump_reason = Some(SkipReason::NoParentVersionFixes {
                            package: via.name.clone(),
                            vulnerable: node.name.clone(),
                        });
                    }
                    res.map(|r| Change::DirectBump {
                        package: via.name.clone(),
                        from: via.version.clone(),
                        bump: eco.bump_kind(&via.version, &r.version),
                        to: r.version,
                    })
                }
                Strategy::Override => self
                    .select(cands, |s, c| Ok(s.move_verdict(node, c)))
                    .map_err(fail)?
                    .map(|r| Change::Override {
                        package: node.name.clone(),
                        from: node.version.clone(),
                        to: r.version,
                    }),
            };
            match result {
                Ok(change) => return Ok(change),
                Err(Some(reason)) => {
                    blocked.get_or_insert(reason);
                }
                Err(None) => {}
            }
        }
        let via = self.input.graph.node(group.via);
        let reason =
            blocked
                .or(bump_reason)
                .or(unsupported)
                .unwrap_or(SkipReason::NoParentVersionFixes {
                    package: via.name.clone(),
                    vulnerable: node.name.clone(),
                });
        Err(Outcome::Skipped { reason })
    }

    /// Whether moving `package` to `to` still fixes the finding `goal`
    /// belongs to: a move of the vulnerable package itself must land on a
    /// safe version, a bump of its via on a version that is not vulnerable
    /// itself and whose subtree resolves to a safe target.
    fn fixes(&mut self, goal: &Goal, package: &str, to: &Version) -> bool {
        let eco = self.eco();
        if !goal.reqs.iter().all(|r| eco.satisfies(r, to)) {
            return false;
        }
        let target = Target {
            name: &goal.target,
            advisories: self.active_advisories(&goal.target),
        };
        if package == goal.target {
            return target.is_safe(eco, to);
        }
        if self
            .active_advisories(package)
            .iter()
            .any(|a| a.affects(eco, package, to))
        {
            return false;
        }
        let mut walk = self.walk(&target, &goal.corridor);
        let answer = self.subtree_ok(package, to, &mut walk, 0);
        self.store(walk);
        answer.is_ok_and(|a| a.ok)
    }

    /// Start walks for `target` through `corridor`, with the results
    /// settled by earlier walks.
    fn walk<'w>(&mut self, target: &'w Target<'w>, corridor: &'w BTreeSet<String>) -> Walk<'w> {
        let memo = self
            .memos
            .get_mut(target.name)
            .and_then(|m| m.iter_mut().find(|(c, _)| c == corridor))
            .map(|(_, memo)| std::mem::take(memo))
            .unwrap_or_default();
        Walk {
            target,
            corridor,
            memo,
            stack: HashMap::new(),
        }
    }

    /// Keep the settled results of `walk` for later walks.
    fn store(&mut self, walk: Walk) {
        let memos = self.memos.entry(walk.target.name.to_string()).or_default();
        match memos.iter_mut().find(|(c, _)| c == walk.corridor) {
            Some((_, memo)) => *memo = walk.memo,
            None => memos.push((walk.corridor.clone(), walk.memo)),
        }
    }

    /// Whether `package@version` (a candidate version of the group's direct
    /// dependency, or a package below it) can resolve to a non-vulnerable
    /// target package.
    ///
    /// Only dependencies that lead to the target in the current graph (the
    /// walk's corridor) are followed, each resolved to what a fresh
    /// resolution picks ([`Planner::pick`]); a requirement on the target
    /// itself must pick a safe release. Optional dependencies count only if
    /// the current graph already has them (an edge between the same names).
    /// New paths a candidate introduces are not explored; verification
    /// rescans.
    ///
    /// Cycles and subtrees below [`MAX_DEPTH`] are assumed fine. A failure
    /// is final; a success that assumed an in-progress node fine is only
    /// memoized once that node is settled.
    fn subtree_ok(
        &mut self,
        package: &str,
        version: &Version,
        walk: &mut Walk,
        depth: usize,
    ) -> Result<Subtree, AdapterError> {
        let key = (package.to_string(), version.clone());
        if let Some(&(ok, from)) = walk.memo.get(&key)
            && depth >= from
        {
            return Ok(Subtree {
                cut: from > 0,
                ..if ok { Subtree::OK } else { Subtree::FAIL }
            });
        }
        if let Some(&d) = walk.stack.get(&key) {
            // A cycle: fine as far as this node is concerned.
            return Ok(Subtree {
                assumed: d,
                ..Subtree::OK
            });
        }
        walk.stack.insert(key.clone(), depth);
        let eco = self.eco();
        let mut answer = Subtree::OK;
        for dep in self.dependencies_of(package, version)?.iter() {
            if dep.optional && !self.edge_names.contains(&(package, dep.name.as_str())) {
                continue;
            }
            let sub = if dep.name == walk.target.name {
                let picked = self.pick(&dep.name, &dep.req)?;
                if picked.is_some_and(|v| walk.target.is_safe(eco, &v)) {
                    Subtree::OK
                } else {
                    Subtree::FAIL
                }
            } else if !walk.corridor.contains(&dep.name) {
                continue;
            } else if depth >= MAX_DEPTH {
                Subtree {
                    cut: true,
                    ..Subtree::OK
                }
            } else {
                match self.pick(&dep.name, &dep.req)? {
                    Some(v) => self.subtree_ok(&dep.name, &v, walk, depth + 1)?,
                    None => Subtree::FAIL,
                }
            };
            if !sub.ok {
                answer = Subtree::FAIL;
                break;
            }
            answer.assumed = answer.assumed.min(sub.assumed);
            answer.cut |= sub.cut;
        }
        walk.stack.remove(&key);
        if answer.assumed >= depth {
            let from = if answer.cut { depth } else { 0 };
            walk.memo.insert(key, (answer.ok, from));
        }
        Ok(answer)
    }
}

impl Target<'_> {
    fn is_safe(&self, eco: &dyn Ecosystem, version: &Version) -> bool {
        !self
            .advisories
            .iter()
            .any(|a| a.affects(eco, self.name, version))
    }
}

/// Merge planned changes (see module docs) and rewrite findings to point at
/// the merged change. `fixes(i, change)` tells whether `change` still fixes
/// finding `i`. Returns the distinct changes in order of first use.
fn merge(
    eco: &dyn Ecosystem,
    policy: &Policy,
    findings: &mut [Finding],
    fixes: &mut dyn FnMut(usize, &Change) -> bool,
) -> Vec<Change> {
    // (is_override, package, from) -> first merged change with that key
    let mut by_key: HashMap<(bool, String, Version), usize> = HashMap::new();
    // Merged changes with the findings they fix.
    let mut merged: Vec<(Change, Vec<usize>)> = Vec::new();
    let mut merged_into: Vec<Option<usize>> = vec![None; findings.len()];
    for (i, f) in findings.iter().enumerate() {
        let Some(change) = &f.change else { continue };
        let key = (
            matches!(change, Change::Override { .. }),
            change.package().to_string(),
            change.from().clone(),
        );
        if let Some(&m) = by_key.get(&key) {
            let (existing, members) = &merged[m];
            let (low, high) = if eco.compare(existing.to(), change.to()).is_ge() {
                (change.to(), existing.to())
            } else {
                (existing.to(), change.to())
            };
            // The higher version, else the lower one, if it fixes them all.
            let fixing = [high, low]
                .map(|to| combine(eco, existing, change, to.clone()))
                .into_iter()
                .find(|c| members.iter().chain([&i]).all(|&j| fixes(j, c)));
            if let Some(c) = fixing {
                merged[m].0 = c;
                merged[m].1.push(i);
                merged_into[i] = Some(m);
                continue;
            }
        }
        // The first change with this key, or one that cannot be merged.
        by_key.entry(key).or_insert(merged.len());
        merged_into[i] = Some(merged.len());
        merged.push((change.clone(), vec![i]));
    }
    for (f, m) in findings.iter_mut().zip(&merged_into) {
        let Some(m) = m else { continue };
        let m = &merged[*m].0;
        if major_blocked(eco, policy, m) {
            f.strategy = None;
            f.change = None;
            f.outcome = Outcome::Skipped {
                reason: SkipReason::MajorBumpBlocked {
                    package: m.package().to_string(),
                    from: m.from().clone(),
                    to: m.to().clone(),
                },
            };
            continue;
        }
        f.strategy = Some(m.strategy());
        f.change = Some(m.clone());
        if let Outcome::Planned { .. } = f.outcome {
            f.outcome = Outcome::Planned {
                strategy: m.strategy(),
                change: m.clone(),
            };
        }
    }
    let mut changes = Vec::new();
    for (c, _) in merged {
        if !major_blocked(eco, policy, &c) && !changes.contains(&c) {
            changes.push(c);
        }
    }
    changes
}

/// A merged bump or override can be major although each part was not (a
/// relock may go further than a manifest bump allows); `allow-major` still
/// applies.
fn major_blocked(eco: &dyn Ecosystem, policy: &Policy, c: &Change) -> bool {
    !matches!(c, Change::Relock { .. })
        && !rules::bump_allowed(eco.bump_kind(c.from(), c.to()), policy)
}

/// `a` merged with `b` (same package and `from`) as one change to `to`: a
/// bump wins over a relock; overrides only merge with overrides.
fn combine(eco: &dyn Ecosystem, a: &Change, b: &Change, to: Version) -> Change {
    let package = a.package().to_string();
    let from = a.from().clone();
    match (a, b) {
        (Change::Override { .. }, Change::Override { .. }) => {
            Change::Override { package, from, to }
        }
        (Change::Override { .. }, _) | (_, Change::Override { .. }) => {
            unreachable!("overrides are merged only with overrides")
        }
        (Change::Relock { .. }, Change::Relock { .. }) => Change::Relock { package, from, to },
        _ => Change::DirectBump {
            bump: eco.bump_kind(&from, &to),
            package,
            from,
            to,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::fake::{Fake, old_date};
    use crate::osv::{OsvRecord, SeverityLevel};

    fn now() -> Timestamp {
        "2026-10-07T00:00:00Z".parse().unwrap()
    }

    fn v(s: &str) -> Version {
        Version::new(s)
    }

    /// Advisory `id` on `pkg` with OSV range events `[introduced, fixed]`.
    fn adv(id: &str, pkg: &str, introduced: &str, fixed: &str) -> Advisory {
        let record: OsvRecord = serde_json::from_value(serde_json::json!({
            "id": id,
            "affected": [{
                "package": {"ecosystem": "Fake", "name": pkg},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": introduced}, {"fixed": fixed}]}]
            }]
        }))
        .unwrap();
        osv::dedupe(vec![record]).remove(0)
    }

    fn run(fake: &Fake, advisories: &[Advisory], policy: &Policy) -> ProjectPlan {
        run_with(fake, advisories, policy, &[])
    }

    fn run_with(
        fake: &Fake,
        advisories: &[Advisory],
        policy: &Policy,
        ignores: &[IgnoreRule],
    ) -> ProjectPlan {
        plan(&PlanInput {
            eco: fake,
            graph: &fake.graph,
            advisories,
            policy,
            ignores,
            now: now(),
        })
    }

    fn only(plan: &ProjectPlan) -> &Finding {
        assert_eq!(plan.findings.len(), 1, "{:#?}", plan.findings);
        &plan.findings[0]
    }

    fn skip_reason(f: &Finding) -> &SkipReason {
        match &f.outcome {
            Outcome::Skipped { reason } => reason,
            other => panic!("expected skipped, got {other:?}"),
        }
    }

    /// root -> a@1.0.0 (req ^1) -> p@1.0.0 (req `p_req`).
    fn transitive(p_req: &str) -> Fake {
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        f.dep(a, "p", "1.0.0", p_req);
        f.publish("a", "1.0.0", &[("p", p_req)]);
        f.publish("p", "1.0.0", &[]);
        f.publish("p", "1.0.1", &[]);
        f
    }

    fn policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn relock_when_parent_req_allows_fix() {
        let f = transitive("^1.0");
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        let finding = only(&plan);
        let expected = Change::Relock {
            package: "p".into(),
            from: v("1.0.0"),
            to: v("1.0.1"),
        };
        assert_eq!(finding.change, Some(expected.clone()));
        assert_eq!(finding.strategy, Some(Strategy::Relock));
        assert_eq!(finding.outcome.label(), "planned");
        assert_eq!(finding.via.name, "a");
        assert_eq!(finding.paths, vec![vec!["app@0.1.0", "a@1.0.0", "p@1.0.0"]]);
        assert_eq!(finding.advisory.id, "A-1");
        assert_eq!(plan.changes, vec![expected]);
    }

    #[test]
    fn candidates_skip_yanked_prerelease_and_other_advisories() {
        let mut f = transitive("^1.0");
        f.registry
            .get_mut("p")
            .unwrap()
            .retain(|r| r.release.version != v("1.0.1"));
        f.publish_with("p", "1.0.1", &[], Some(old_date()), true); // yanked
        f.publish("p", "1.0.2-rc.1", &[]);
        f.publish("p", "1.0.3", &[]); // affected by B
        f.publish("p", "1.0.4", &[]);
        let advisories = [
            adv("A-1", "p", "0", "1.0.1"),
            adv("B-1", "p", "1.0.3", "1.0.4"),
        ];
        let plan = run(&f, &advisories, &policy());
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.0.4"));
    }

    #[test]
    fn no_patched_version() {
        let f = transitive("^1.0");
        let plan = run(&f, &[adv("A-1", "p", "0", "9.0.0")], &policy());
        assert_eq!(
            skip_reason(only(&plan)),
            &SkipReason::NoPatchedVersion {
                package: "p".into()
            }
        );
        assert!(plan.changes.is_empty());
    }

    #[test]
    fn direct_bump_when_parent_pins() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.0.1", &[("p", "=1.0.0")]); // does not help
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("a", "1.2.0", &[("p", "^1.0.1")]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(
            only(&plan).change,
            Some(Change::DirectBump {
                package: "a".into(),
                from: v("1.0.0"),
                to: v("1.1.0"),
                bump: BumpKind::Minor,
            })
        );
    }

    #[test]
    fn direct_bump_latest_compatible() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("a", "1.2.0", &[("p", "^1.0.1")]);
        f.publish("a", "2.0.0", &[("p", "^1.0.1")]);
        let mut pol = policy();
        pol.target = TargetPolicy::LatestCompatible;
        pol.allow_major = true;
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &pol);
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.2.0"));
    }

    #[test]
    fn relock_latest_compatible() {
        let mut f = transitive("^1.0");
        f.publish("p", "1.0.5", &[]);
        f.publish("p", "1.3.0", &[]);
        f.publish("p", "2.0.0", &[]);
        let mut pol = policy();
        pol.target = TargetPolicy::LatestCompatible;
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &pol);
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.3.0"));
    }

    #[test]
    fn direct_bump_recursive_through_intermediate() {
        // root -> a@1.0.0 -> b@1.0.0 -> p@1.0.0, b pins p.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        let b = f.dep(a, "b", "1.0.0", "=1.0.0");
        f.dep(b, "p", "1.0.0", "=1.0.0");
        f.publish("a", "1.0.0", &[("b", "=1.0.0")]);
        f.publish("a", "1.1.0", &[("b", "~1.0.0")]); // resolves b@1.0.5: still pins p
        f.publish("a", "1.2.0", &[("b", "^1.1.0"), ("unrelated", "^1")]);
        f.publish("b", "1.0.0", &[("p", "=1.0.0")]);
        f.publish("b", "1.0.5", &[("p", "=1.0.0")]);
        f.publish("b", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("p", "1.0.0", &[]);
        f.publish("p", "1.0.1", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        let change = only(&plan).change.clone().unwrap();
        assert_eq!(change.package(), "a");
        assert_eq!(change.to(), &v("1.2.0"));
    }

    #[test]
    fn direct_bump_when_new_version_drops_the_dependency() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.1.0"));
    }

    #[test]
    fn registry_cycles_terminate() {
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        let b = f.dep(a, "b", "1.0.0", "=1.0.0");
        f.dep(b, "p", "1.0.0", "=1.0.0");
        f.graph.add_edge(b, a, VersionReq::new("^1"));
        f.publish("a", "1.0.0", &[("b", "=1.0.0")]);
        f.publish("a", "1.1.0", &[("b", "^1")]);
        f.publish("b", "1.0.0", &[("p", "=1.0.0"), ("a", "^1")]);
        f.publish("p", "1.0.0", &[]);
        f.publish("p", "1.0.1", &[]);
        f.unsupported = vec![Strategy::Override];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(
            skip_reason(only(&plan)),
            &SkipReason::NoParentVersionFixes {
                package: "a".into(),
                vulnerable: "p".into()
            }
        );
    }

    #[test]
    fn major_bump_blocked_unless_allowed() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[("p", "=1.0.0")]);
        f.publish("a", "2.0.0", &[("p", "^1.0.1")]);
        f.unsupported = vec![Strategy::Override];
        let advisories = [adv("A-1", "p", "0", "1.0.1")];
        let plan = run(&f, &advisories, &policy());
        assert_eq!(
            skip_reason(only(&plan)),
            &SkipReason::MajorBumpBlocked {
                package: "a".into(),
                from: v("1.0.0"),
                to: v("2.0.0")
            }
        );
        let mut pol = policy();
        pol.allow_major = true;
        let plan = run(&f, &advisories, &pol);
        assert_eq!(
            only(&plan).change,
            Some(Change::DirectBump {
                package: "a".into(),
                from: v("1.0.0"),
                to: v("2.0.0"),
                bump: BumpKind::Major
            })
        );
    }

    #[test]
    fn no_parent_version_fixes_without_override() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[("p", "=1.0.0")]);
        f.unsupported = vec![Strategy::Override];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(
            only(&plan).outcome.label(),
            "skipped:no_parent_version_fixes"
        );
    }

    #[test]
    fn override_when_no_parent_fixes() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[("p", "=1.0.0")]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(
            only(&plan).change,
            Some(Change::Override {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("1.0.1")
            })
        );
    }

    #[test]
    fn override_major_blocked() {
        let mut f = transitive("=1.0.0");
        f.registry
            .get_mut("p")
            .unwrap()
            .retain(|r| r.release.version != v("1.0.1"));
        f.publish("p", "2.0.0", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "2.0.0")], &policy());
        assert_eq!(only(&plan).outcome.label(), "skipped:major_bump_blocked");
    }

    #[test]
    fn strategy_unsupported_when_only_option() {
        let mut f = transitive("=1.0.0");
        f.unsupported = vec![Strategy::Override];
        let mut pol = policy();
        pol.strategies = vec![Strategy::Override];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &pol);
        assert_eq!(
            skip_reason(only(&plan)),
            &SkipReason::StrategyUnsupported {
                strategy: Strategy::Override
            }
        );
    }

    #[test]
    fn strategy_order_is_respected() {
        let mut f = transitive("^1.0");
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        let mut pol = policy();
        pol.strategies = vec![Strategy::DirectBump, Strategy::Relock];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &pol);
        assert_eq!(only(&plan).strategy, Some(Strategy::DirectBump));
    }

    #[test]
    fn release_age_blocks_recent_and_undated_versions() {
        let mut f = transitive("^1.0");
        f.registry
            .get_mut("p")
            .unwrap()
            .retain(|r| r.release.version != v("1.0.1"));
        f.publish_with(
            "p",
            "1.0.1",
            &[],
            Some("2026-10-06T00:00:00Z".parse().unwrap()),
            false,
        );
        f.publish_with("p", "1.0.2", &[], None, false);
        f.unsupported = vec![Strategy::Override];
        let advisories = [adv("A-1", "p", "0", "1.0.1")];
        let plan = run(&f, &advisories, &policy());
        match skip_reason(only(&plan)) {
            SkipReason::ReleaseTooRecent {
                package,
                version,
                min_release_age_secs,
                ..
            } => {
                assert_eq!(package, "p");
                assert_eq!(version, &v("1.0.1"));
                assert_eq!(*min_release_age_secs, 7 * 86_400);
            }
            other => panic!("{other:?}"),
        }
        let mut pol = policy();
        pol.min_release_age = std::time::Duration::ZERO;
        assert_eq!(
            only(&run(&f, &advisories, &pol)).strategy,
            Some(Strategy::Relock)
        );
        pol.min_release_age = std::time::Duration::from_secs(3600);
        assert_eq!(
            only(&run(&f, &advisories, &pol))
                .change
                .as_ref()
                .unwrap()
                .to(),
            &v("1.0.1")
        );
    }

    #[test]
    fn direct_dependency_relock_or_bump() {
        for (req, expected) in [("^1.0", Strategy::Relock), ("=1.0.0", Strategy::DirectBump)] {
            let mut f = Fake::new();
            let root = f.root("app", "0.1.0");
            f.dep(root, "p", "1.0.0", req);
            f.publish("p", "1.0.0", &[]);
            f.publish("p", "1.0.1", &[]);
            let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
            let finding = only(&plan);
            assert_eq!(finding.strategy, Some(expected));
            assert_eq!(finding.via.name, "p");
            assert_eq!(finding.change.as_ref().unwrap().to(), &v("1.0.1"));
        }
    }

    #[test]
    fn separate_findings_per_direct_dependency() {
        // p reached via a (relockable) and via b (pinned).
        let mut f = transitive("^1.0");
        let root = f.graph.roots[0];
        let p = f.graph.find("p", &v("1.0.0")).unwrap();
        let b = f.dep(root, "b", "1.0.0", "^1");
        f.graph.add_edge(b, p, VersionReq::new("=1.0.0"));
        f.publish("b", "1.0.0", &[("p", "=1.0.0")]);
        f.publish("b", "1.0.1", &[("p", "^1.0.1")]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(plan.findings.len(), 2);
        assert_eq!(plan.findings[0].via.name, "a");
        assert_eq!(plan.findings[0].strategy, Some(Strategy::Relock));
        assert_eq!(plan.findings[1].via.name, "b");
        assert_eq!(plan.findings[1].strategy, Some(Strategy::DirectBump));
        assert_eq!(plan.changes.len(), 2);
    }

    #[test]
    fn merges_bumps_of_the_same_direct_dependency() {
        let mut f = transitive("=1.0.0");
        let a = f.graph.find("a", &v("1.0.0")).unwrap();
        f.dep(a, "q", "1.0.0", "=1.0.0");
        f.registry.get_mut("a").unwrap()[0]
            .deps
            .push(crate::ecosystem::DeclaredDep {
                name: "q".into(),
                req: VersionReq::new("=1.0.0"),
                optional: false,
            });
        f.publish("q", "1.0.0", &[]);
        f.publish("q", "1.0.1", &[]);
        f.publish("a", "1.1.0", &[("p", "^1.0.1"), ("q", "=1.0.0")]);
        f.publish("a", "1.2.0", &[("p", "^1.0.1"), ("q", "^1.0.1")]);
        let advisories = [adv("A-1", "p", "0", "1.0.1"), adv("B-1", "q", "0", "1.0.1")];
        let plan = run(&f, &advisories, &policy());
        assert_eq!(plan.findings.len(), 2);
        let merged = Change::DirectBump {
            package: "a".into(),
            from: v("1.0.0"),
            to: v("1.2.0"),
            bump: BumpKind::Minor,
        };
        assert_eq!(plan.changes, vec![merged.clone()]);
        for finding in &plan.findings {
            assert_eq!(finding.change, Some(merged.clone()));
            assert_eq!(
                finding.outcome,
                Outcome::Planned {
                    strategy: Strategy::DirectBump,
                    change: merged.clone()
                }
            );
        }
    }

    #[test]
    fn merge_prefers_bump_over_relock_for_same_package() {
        let f = Fake::new();
        let relock = Change::Relock {
            package: "p".into(),
            from: v("1.0.0"),
            to: v("1.0.1"),
        };
        let bump = Change::DirectBump {
            package: "p".into(),
            from: v("1.0.0"),
            to: v("1.0.0"),
            bump: BumpKind::Patch,
        };
        let c = combine(&f, &relock, &bump, v("1.0.1"));
        assert_eq!(
            c,
            Change::DirectBump {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("1.0.1"),
                bump: BumpKind::Patch
            }
        );
    }

    #[test]
    fn ignored_and_below_severity() {
        let f = transitive("^1.0");
        let mut low = adv("LOW-1", "p", "0", "1.0.1");
        low.severity = Some(Severity {
            level: SeverityLevel::Low,
            score: Some(2.0),
        });
        let ignored = adv("IGN-1", "p", "0", "1.0.1");
        let expired = adv("EXP-1", "p", "0", "1.0.1");
        let ignores = vec![
            IgnoreRule {
                id: "IGN-1".into(),
                reason: "not reachable".into(),
                expires: None,
            },
            IgnoreRule {
                id: "EXP-1".into(),
                reason: "old".into(),
                expires: Some(jiff::civil::date(2020, 1, 1)),
            },
        ];
        let mut pol = policy();
        pol.min_severity = SeverityLevel::Medium;
        let plan = run_with(&f, &[low, ignored, expired], &pol, &ignores);
        let labels: Vec<(String, String)> = plan
            .findings
            .iter()
            .map(|f| (f.advisory.id.clone(), f.outcome.label()))
            .collect();
        assert_eq!(
            labels,
            vec![
                ("EXP-1".into(), "planned".into()),
                ("IGN-1".into(), "skipped:ignored".into()),
                ("LOW-1".into(), "skipped:below_min_severity".into()),
            ]
        );
        assert!(plan.findings.iter().all(|f| f.outcome.is_resolved()));
    }

    #[test]
    fn skipped_advisories_do_not_restrict_candidates() {
        let mut f = transitive("^1.0");
        f.publish("p", "1.0.2", &[]);
        // p@1.0.1 is affected only by an ignored and a low-severity advisory.
        let mut low = adv("LOW-1", "p", "1.0.1", "1.0.2");
        low.severity = Some(Severity {
            level: SeverityLevel::Low,
            score: Some(2.0),
        });
        let advisories = [
            adv("A-1", "p", "0", "1.0.1"),
            adv("IGN-1", "p", "1.0.1", "1.0.2"),
            low,
        ];
        let ignores = [IgnoreRule {
            id: "IGN-1".into(),
            reason: "not reachable".into(),
            expires: None,
        }];
        let mut pol = policy();
        pol.min_severity = SeverityLevel::Medium;
        let plan = run_with(&f, &advisories, &pol, &ignores);
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.0.1"));
    }

    #[test]
    fn direct_bump_skips_vulnerable_versions_of_the_via() {
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]); // affected by V-1
        f.publish("a", "1.2.0", &[("p", "^1.0.1")]);
        let advisories = [
            adv("A-1", "p", "0", "1.0.1"),
            adv("V-1", "a", "1.1.0", "1.2.0"),
        ];
        let plan = run(&f, &advisories, &policy());
        assert_eq!(
            only(&plan).change,
            Some(Change::DirectBump {
                package: "a".into(),
                from: v("1.0.0"),
                to: v("1.2.0"),
                bump: BumpKind::Minor,
            })
        );
    }

    #[test]
    fn registry_errors_become_failed_outcomes() {
        let mut f = transitive("^1.0");
        f.registry.remove("p");
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(only(&plan).outcome.label(), "failed:error");
        assert!(!only(&plan).outcome.is_resolved());
    }

    #[test]
    fn registry_calls_are_memoized() {
        let mut f = transitive("=1.0.0");
        for i in 1..30 {
            f.publish("a", &format!("1.{i}.0"), &[("p", "=1.0.0")]);
        }
        f.unsupported = vec![Strategy::Override];
        let advisories = [adv("A-1", "p", "0", "1.0.1"), adv("A-2", "p", "0", "1.0.1")];
        run(&f, &advisories, &policy());
        // 1x releases(p), 1x releases(a), 30x dependencies_of(a@...) at most.
        assert!(
            *f.registry_calls.borrow() <= 32,
            "{}",
            f.registry_calls.borrow()
        );
    }

    #[test]
    fn non_registry_nodes_are_not_scanned() {
        let mut f = Fake::new();
        let root = f.root("p", "1.0.0");
        let local = f.root("lib", "1.0.0"); // workspace member
        f.graph.add_edge(root, local, VersionReq::new("*"));
        f.dep(local, "q", "1.0.0", "=1.0.0");
        f.publish("q", "1.0.0", &[]);
        f.publish("q", "1.0.1", &[]);
        let plan = run(
            &f,
            &[adv("A-1", "p", "0", "2.0.0"), adv("B-1", "q", "0", "1.0.1")],
            &policy(),
        );
        // Only q is reported; it is declared by a local package, so it is its own via.
        let finding = only(&plan);
        assert_eq!(finding.package, "q");
        assert_eq!(finding.via.name, "q");
        assert_eq!(finding.strategy, Some(Strategy::DirectBump));
        assert_eq!(
            finding.paths,
            vec![
                vec!["p@1.0.0", "lib@1.0.0", "q@1.0.0"],
                vec!["lib@1.0.0", "q@1.0.0"]
            ]
        );
    }

    #[test]
    fn shared_copies_relock_must_satisfy_every_parent() {
        // p reached via a (^1.0) and via b (=1.0.0): one shared p@1.0.0.
        let mut f = transitive("^1.0");
        let root = f.graph.roots[0];
        let p = f.graph.find("p", &v("1.0.0")).unwrap();
        let b = f.dep(root, "b", "1.0.0", "^1");
        f.graph.add_edge(b, p, VersionReq::new("=1.0.0"));
        f.publish("b", "1.0.0", &[("p", "=1.0.0")]);
        f.publish("b", "1.0.1", &[("p", "^1.0.1")]);
        f.unsupported = vec![Strategy::Override];
        f.shared_copies = true;
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        let outcomes: Vec<(&str, String)> = plan
            .findings
            .iter()
            .map(|f| (f.via.name.as_str(), f.outcome.label()))
            .collect();
        // b's `=1.0.0` blocks moving the shared copy for a.
        assert_eq!(
            outcomes,
            vec![
                ("a", "skipped:no_parent_version_fixes".to_string()),
                ("b", "planned".to_string())
            ]
        );
        assert_eq!(plan.findings[1].strategy, Some(Strategy::DirectBump));
    }

    #[test]
    fn via_declared_only_by_a_git_dependency_is_not_bumped() {
        // app -> gitdep (not from the registry, not a member) -> a -> p.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let git = f.graph.add_node("gitdep", &v("0.3.0"), true, false);
        f.graph.add_edge(root, git, VersionReq::new("*"));
        let a = f.dep(git, "a", "1.0.0", "^1");
        f.dep(a, "p", "1.0.0", "=1.0.0");
        f.publish("a", "1.0.0", &[("p", "=1.0.0")]);
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        let finding = only(&plan);
        assert_eq!(finding.via.name, "a");
        assert_eq!(
            finding.paths,
            vec![vec!["app@0.1.0", "gitdep@0.3.0", "a@1.0.0", "p@1.0.0"]]
        );
        assert_eq!(
            finding.change,
            Some(Change::Override {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("1.0.1")
            })
        );
    }

    #[test]
    fn via_declared_without_a_version_is_not_bumped() {
        // app -> a (version managed elsewhere, e.g. a Gradle platform) -> p.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "");
        f.dep(a, "p", "1.0.0", "=1.0.0");
        f.publish("a", "1.0.0", &[("p", "=1.0.0")]);
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(
            only(&plan).change,
            Some(Change::Override {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("1.0.1")
            })
        );
    }

    #[test]
    fn merged_major_bump_respects_allow_major() {
        let finding = |via: &str, change: Change| Finding {
            advisory: (&adv("A-1", "p", "0", "2.0.0")).into(),
            package: "p".into(),
            version: v("1.0.0"),
            via: PackageRef {
                name: via.into(),
                version: v("1.0.0"),
            },
            paths: Vec::new(),
            strategy: Some(change.strategy()),
            outcome: Outcome::Planned {
                strategy: change.strategy(),
                change: change.clone(),
            },
            change: Some(change),
        };
        // A relock allowed by a's range, and a minor bump of the direct p.
        let findings = || {
            let relock = Change::Relock {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("2.0.0"),
            };
            let bump = Change::DirectBump {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("1.1.0"),
                bump: BumpKind::Minor,
            };
            vec![finding("a", relock), finding("p", bump)]
        };
        let f = Fake::new();
        let mut blocked = findings();
        assert!(merge(&f, &policy(), &mut blocked, &mut |_, _| true).is_empty());
        for finding in &blocked {
            assert_eq!(
                skip_reason(finding),
                &SkipReason::MajorBumpBlocked {
                    package: "p".into(),
                    from: v("1.0.0"),
                    to: v("2.0.0")
                }
            );
            assert_eq!((&finding.change, finding.strategy), (&None, None));
        }

        let mut pol = policy();
        pol.allow_major = true;
        assert_eq!(
            merge(&f, &pol, &mut findings(), &mut |_, _| true),
            vec![Change::DirectBump {
                package: "p".into(),
                from: v("1.0.0"),
                to: v("2.0.0"),
                bump: BumpKind::Major
            }]
        );
    }

    #[test]
    fn every_via_gets_paths() {
        // Over 1000 paths through a (10 diamonds), then one through b.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let mut last = f.dep(root, "a", "1.0.0", "^1");
        for i in 0..10 {
            let l = f.dep(last, &format!("l{i}"), "1.0.0", "^1");
            let r = f.dep(last, &format!("r{i}"), "1.0.0", "^1");
            let m = f.dep(l, &format!("m{i}"), "1.0.0", "^1");
            f.graph.add_edge(r, m, VersionReq::new("^1"));
            last = m;
        }
        f.dep(last, "p", "1.0.0", "^1");
        let b = f.dep(root, "b", "1.0.0", "^1");
        f.dep(b, "p", "1.0.0", "^1");
        f.publish("p", "1.0.0", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "9.0.0")], &policy());
        assert_eq!(plan.findings.len(), 2);
        assert_eq!(plan.findings[0].paths.len(), MAX_PATHS);
        assert_eq!(
            plan.findings[1].paths,
            vec![vec!["app@0.1.0", "b@1.0.0", "p@1.0.0"]]
        );
    }

    fn no_parent_fix(package: &str, vulnerable: &str) -> SkipReason {
        SkipReason::NoParentVersionFixes {
            package: package.into(),
            vulnerable: vulnerable.into(),
        }
    }

    /// Adds `names` as a chain of registry packages below `from` (each
    /// `1.0.0`, declared `^1`, published with the next one as dependency and
    /// `last` at the end). Returns the last node of the chain.
    fn chain(f: &mut Fake, from: NodeId, names: &[String], last: (&str, &str)) -> NodeId {
        let mut prev = from;
        for (i, name) in names.iter().enumerate() {
            prev = f.dep(prev, name, "1.0.0", "^1");
            let next = names.get(i + 1).map_or(last, |n| (n.as_str(), "^1"));
            f.publish(name, "1.0.0", &[next]);
        }
        prev
    }

    #[test]
    fn cycle_results_are_settled_before_reuse() {
        // root -> a -> b -> c -> p, and c -> b. b pins p.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        let b = f.dep(a, "b", "1.0.0", "=1.0.0");
        let c = f.dep(b, "c", "1.0.0", "^1");
        let p = f.dep(c, "p", "1.0.0", "^1");
        f.graph.add_edge(c, b, VersionReq::new("^1"));
        f.graph.add_edge(b, p, VersionReq::new("=1.0.0"));
        f.publish("a", "1.0.0", &[("b", "=1.0.0")]);
        f.publish("a", "1.1.0", &[("b", "^1")]);
        f.publish("a", "1.2.0", &[("c", "^1")]); // c -> b still pins p
        f.publish("b", "1.0.0", &[("c", "^1"), ("p", "=1.0.0")]);
        f.publish("c", "1.0.0", &[("b", "^1"), ("p", "^1")]);
        f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        f.unsupported = vec![Strategy::Override];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(skip_reason(only(&plan)), &no_parent_fix("a", "p"));
    }

    #[test]
    fn depth_cut_results_are_not_reused_closer_to_the_root() {
        // root -> a -> c1 .. c7 -> x -> y -> p; y pins p. Walking a@1.1.0
        // reaches x at MAX_DEPTH (y unexplored), a@1.2.0 reaches x at depth 1.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        let names: Vec<String> = (1..MAX_DEPTH).map(|i| format!("c{i}")).collect();
        let last = chain(&mut f, a, &names, ("x", "^1"));
        let y = chain(&mut f, last, &["x".into(), "y".into()], ("p", "=1.0.0"));
        f.dep(y, "p", "1.0.0", "=1.0.0");
        f.publish("a", "1.0.0", &[("c1", "^1")]);
        f.publish("a", "1.1.0", &[("c1", "^1"), ("p", "=1.0.0")]);
        f.publish("a", "1.2.0", &[("x", "^1")]);
        f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        f.unsupported = vec![Strategy::Override];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        assert_eq!(skip_reason(only(&plan)), &no_parent_fix("a", "p"));
    }

    #[test]
    fn subtree_walk_stops_at_max_depth() {
        // root -> a -> c1 .. cN -> y -> p; y pins p. a@1.1.0 changes nothing:
        // the pin is seen only if y is at most MAX_DEPTH below a.
        for (len, expected) in [
            (MAX_DEPTH - 1, "skipped:no_parent_version_fixes"),
            (MAX_DEPTH, "planned"),
        ] {
            let mut f = Fake::new();
            let root = f.root("app", "0.1.0");
            let a = f.dep(root, "a", "1.0.0", "^1");
            let names: Vec<String> = (1..=len).map(|i| format!("c{i}")).collect();
            let last = chain(&mut f, a, &names, ("y", "^1"));
            let y = chain(&mut f, last, &["y".into()], ("p", "=1.0.0"));
            f.dep(y, "p", "1.0.0", "=1.0.0");
            f.publish("a", "1.0.0", &[("c1", "^1")]);
            f.publish("a", "1.1.0", &[("c1", "^1")]);
            f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
            f.unsupported = vec![Strategy::Override];
            let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
            assert_eq!(only(&plan).outcome.label(), expected, "chain of {len}");
        }
    }

    #[test]
    fn wide_corridors_below_max_depth_are_walked_once_per_depth() {
        // root -> a -> 12 layers of 5 packages, each depending on every
        // package of the next layer -> p, pinned by the last layer. A walk
        // that never reused cut-off answers would visit 5^MAX_DEPTH paths.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let layers: Vec<Vec<String>> = (0..12)
            .map(|l| (0..5).map(|i| format!("l{l}x{i}")).collect())
            .collect();
        let reqs = |names: &[String]| -> Vec<(String, String)> {
            names.iter().map(|n| (n.clone(), "^1".into())).collect()
        };
        let mut parents = vec![f.dep(root, "a", "1.0.0", "^1")];
        let mut published = vec![("a".to_string(), reqs(&layers[0]))];
        for (l, names) in layers.iter().enumerate() {
            let ids: Vec<NodeId> = names
                .iter()
                .map(|n| f.graph.add_node(n, &v("1.0.0"), false, true))
                .collect();
            for &from in &parents {
                for &to in &ids {
                    f.graph.add_edge(from, to, VersionReq::new("^1"));
                }
            }
            let deps = match layers.get(l + 1) {
                Some(next) => reqs(next),
                None => vec![("p".into(), "=1.0.0".into())],
            };
            published.extend(names.iter().map(|n| (n.clone(), deps.clone())));
            parents = ids;
        }
        for &id in &parents {
            f.dep(id, "p", "1.0.0", "=1.0.0");
        }
        for (name, deps) in &published {
            let deps: Vec<(&str, &str)> =
                deps.iter().map(|(n, r)| (n.as_str(), r.as_str())).collect();
            f.publish(name, "1.0.0", &deps);
        }
        let a_deps: Vec<(&str, &str)> = layers[0].iter().map(|n| (n.as_str(), "^1")).collect();
        f.publish("a", "1.1.0", &a_deps);
        f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        f.unsupported = vec![Strategy::Override];
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
        // The pins are below MAX_DEPTH: assumed fine.
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.1.0"));
    }

    #[test]
    fn target_requirement_uses_the_version_a_fresh_resolution_picks() {
        let mut f = transitive("=1.0.0");
        f.publish("p", "1.0.2", &[]); // affected by B
        f.publish_with("p", "1.0.3", &[], Some(old_date()), true); // yanked
        f.publish("a", "1.1.0", &[("p", "^1.0.0")]); // resolves p@1.0.2
        f.publish("a", "1.2.0", &[("p", ">=1.0.1, <1.0.2")]);
        f.publish("a", "1.3.0", &[("p", "=1.0.4-rc.1")]);
        f.publish("p", "1.0.4-rc.1", &[]);
        let advisories = [
            adv("A-1", "p", "0", "1.0.1"),
            adv("B-1", "p", "1.0.2", "1.0.3"),
        ];
        let plan = run(&f, &advisories, &policy());
        assert_eq!(
            only(&plan).change.clone().unwrap(),
            Change::DirectBump {
                package: "a".into(),
                from: v("1.0.0"),
                to: v("1.2.0"),
                bump: BumpKind::Minor,
            }
        );
        // A prerelease pin resolves to that prerelease.
        f.registry.get_mut("a").unwrap().retain(|r| {
            let v = r.release.version.as_str();
            v != "1.1.0" && v != "1.2.0"
        });
        let plan = run(&f, &advisories, &policy());
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.3.0"));
    }

    #[test]
    fn optional_dependencies_count_only_when_enabled() {
        // root -> a -> b -> p; a@1.1.0 also has an optional pin on p.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        let b = f.dep(a, "b", "1.0.0", "=1.0.0");
        let p = f.dep(b, "p", "1.0.0", "=1.0.0");
        f.publish("a", "1.0.0", &[("b", "=1.0.0")]);
        f.publish("a", "1.1.0", &[("b", "^1.1.0"), ("p", "=1.0.0")]);
        f.registry.get_mut("a").unwrap()[1].deps[1].optional = true;
        f.publish("b", "1.0.0", &[("p", "=1.0.0")]);
        f.publish("b", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("p", "1.0.0", &[]).publish("p", "1.0.1", &[]);
        f.unsupported = vec![Strategy::Override];
        let advisories = [adv("A-1", "p", "0", "1.0.1")];
        let plan = run(&f, &advisories, &policy());
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.1.0"));
        // The feature is on today (a -> p in the graph): the pin counts.
        f.graph.add_edge(a, p, VersionReq::new("=1.0.0"));
        let plan = run(&f, &advisories, &policy());
        assert_eq!(skip_reason(only(&plan)), &no_parent_fix("a", "p"));
    }

    #[test]
    fn merged_change_must_fix_every_finding() {
        // a@1.0.0 is vulnerable itself and pins p. A relock of a picks the
        // latest 1.2.0, which pins p again; the bump of a for p picks 1.1.0.
        let mut f = transitive("=1.0.0");
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        f.publish("a", "1.2.0", &[("p", "=1.0.0")]);
        let mut pol = policy();
        pol.target = TargetPolicy::LatestCompatible;
        let advisories = [adv("A-1", "p", "0", "1.0.1"), adv("V-1", "a", "0", "1.0.1")];
        let plan = run(&f, &advisories, &pol);
        let merged = Change::DirectBump {
            package: "a".into(),
            from: v("1.0.0"),
            to: v("1.1.0"),
            bump: BumpKind::Minor,
        };
        assert_eq!(plan.changes, vec![merged.clone()]);
        assert_eq!(plan.findings.len(), 2);
        for finding in &plan.findings {
            assert_eq!(finding.change, Some(merged.clone()), "{}", finding.package);
        }
    }

    #[test]
    fn merge_falls_back_to_the_lower_version_or_keeps_changes_apart() {
        let relock = |to: &str| Change::Relock {
            package: "p".into(),
            from: v("1.0.0"),
            to: v(to),
        };
        let finding = |via: &str, change: Change| Finding {
            advisory: (&adv("A-1", "p", "0", "2.0.0")).into(),
            package: "p".into(),
            version: v("1.0.0"),
            via: PackageRef {
                name: via.into(),
                version: v("1.0.0"),
            },
            paths: Vec::new(),
            strategy: Some(change.strategy()),
            outcome: Outcome::Planned {
                strategy: change.strategy(),
                change: change.clone(),
            },
            change: Some(change),
        };
        let findings = || vec![finding("a", relock("1.0.2")), finding("b", relock("1.0.1"))];
        let f = Fake::new();
        // b's parents do not allow 1.0.2: both move to 1.0.1.
        let mut low = findings();
        let changes = merge(&f, &policy(), &mut low, &mut |i, c| {
            i == 0 || c.to() == &v("1.0.1")
        });
        assert_eq!(changes, vec![relock("1.0.1")]);
        assert!(low.iter().all(|f| f.change == Some(relock("1.0.1"))));
        // Neither version fixes both: each keeps its own change.
        let mut apart = findings();
        let changes = merge(&f, &policy(), &mut apart, &mut |i, c| {
            c.to() == &v(["1.0.2", "1.0.1"][i])
        });
        assert_eq!(changes, vec![relock("1.0.2"), relock("1.0.1")]);
        assert_eq!(apart[1].change, Some(relock("1.0.1")));
    }

    #[test]
    fn two_vulnerable_versions_sort_in_version_order() {
        // p@1.9.0 via a and p@1.10.0 via b; both pinned.
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        let b = f.dep(root, "b", "1.0.0", "^1");
        f.dep(b, "p", "1.10.0", "=1.10.0");
        let a = f.dep(root, "a", "1.0.0", "^1");
        f.dep(a, "p", "1.9.0", "=1.9.0");
        for (name, pin) in [("a", "=1.9.0"), ("b", "=1.10.0")] {
            f.publish(name, "1.0.0", &[("p", pin)]);
            f.publish(name, "1.1.0", &[("p", "^1.11")]);
        }
        for version in ["1.9.0", "1.10.0", "1.11.0"] {
            f.publish("p", version, &[]);
        }
        let plan = run(&f, &[adv("A-1", "p", "0", "1.11.0")], &policy());
        let seen: Vec<(&str, &str)> = plan
            .findings
            .iter()
            .map(|f| (f.version.as_str(), f.via.name.as_str()))
            .collect();
        assert_eq!(seen, vec![("1.9.0", "a"), ("1.10.0", "b")]);
        let bumped: Vec<&str> = plan.changes.iter().map(Change::package).collect();
        assert_eq!(bumped, vec!["a", "b"]);
        assert!(plan.findings.iter().all(|f| f.outcome.label() == "planned"));
    }

    #[test]
    fn prerelease_current_version_may_move_to_a_prerelease() {
        let mut f = Fake::new();
        let root = f.root("app", "0.1.0");
        f.dep(root, "p", "1.0.0-rc.1", "=1.0.0-rc.1");
        f.publish("p", "1.0.0-rc.1", &[])
            .publish("p", "1.0.0-rc.2", &[]);
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.0-rc.2")], &policy());
        assert_eq!(
            only(&plan).change,
            Some(Change::DirectBump {
                package: "p".into(),
                from: v("1.0.0-rc.1"),
                to: v("1.0.0-rc.2"),
                bump: BumpKind::Patch,
            })
        );
    }

    #[test]
    fn direct_bump_examines_at_most_max_candidates() {
        for (pinned, expected) in [
            (MAX_CANDIDATES - 1, "planned"),
            (MAX_CANDIDATES, "skipped:no_parent_version_fixes"),
        ] {
            let mut f = transitive("=1.0.0");
            for i in 1..=pinned {
                f.publish("a", &format!("1.{i}.0"), &[("p", "=1.0.0")]);
            }
            f.publish("a", &format!("1.{}.0", pinned + 1), &[("p", "^1.0.1")]);
            f.unsupported = vec![Strategy::Override];
            let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &policy());
            assert_eq!(only(&plan).outcome.label(), expected, "{pinned} pinned");
        }
    }

    #[test]
    fn direct_bump_latest_compatible_skips_too_recent_versions() {
        let mut f = transitive("=1.0.0");
        let recent = Some("2026-10-06T00:00:00Z".parse().unwrap());
        f.publish("a", "1.1.0", &[("p", "^1.0.1")]);
        f.publish_with("a", "1.2.0", &[("p", "^1.0.1")], recent, false);
        f.publish("a", "1.3.0", &[("p", "^1.0.1")]);
        f.publish_with("a", "1.4.0", &[("p", "^1.0.1")], recent, false);
        let mut pol = policy();
        pol.target = TargetPolicy::LatestCompatible;
        let plan = run(&f, &[adv("A-1", "p", "0", "1.0.1")], &pol);
        assert_eq!(only(&plan).change.as_ref().unwrap().to(), &v("1.3.0"));
    }

    #[test]
    fn select_keeps_the_chosen_version_after_a_block() {
        let f = Fake::new();
        let mut pol = policy();
        pol.target = TargetPolicy::LatestCompatible;
        let input = PlanInput {
            eco: &f,
            graph: &f.graph,
            advisories: &[],
            policy: &pol,
            ignores: &[],
            now: now(),
        };
        let mut planner = Planner::new(&input);
        let cands: Vec<Release> = ["1.0.1", "1.0.2", "1.0.3"]
            .iter()
            .map(|s| Release {
                version: v(s),
                published_at: Some(old_date()),
                yanked: false,
            })
            .collect();
        let reason = SkipReason::NoPatchedVersion {
            package: "p".into(),
        };
        for (stop, expected) in [(false, "1.0.3"), (true, "1.0.1")] {
            let chosen = planner
                .select(&cands, |_, c| {
                    Ok(match (c.version.as_str(), stop) {
                        ("1.0.2", true) => Verdict::Stop(reason.clone()),
                        ("1.0.2", false) => Verdict::Blocked(reason.clone()),
                        _ => Verdict::Accept,
                    })
                })
                .unwrap();
            assert_eq!(chosen.ok().map(|r| r.version), Some(v(expected)));
        }
    }
}
