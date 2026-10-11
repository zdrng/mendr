//! OSV advisories: live API client with on-disk cache, offline snapshot
//! loading, range matching, alias dedupe and severity.
//!
//! Records follow the standard schema (<https://ossf.github.io/osv-schema/>).
//! Only the fields mendr needs are parsed; everything else is ignored.
//!
//! Filtering rules:
//! - records with `withdrawn` set are dropped;
//! - RustSec "informational" records (`database_specific.informational`, e.g.
//!   `unmaintained`, `unsound`, `notice`) are dropped: they are not
//!   vulnerabilities and have no fixed version;
//! - `GIT` ranges are ignored; `SEMVER` and `ECOSYSTEM` ranges are evaluated
//!   with `Ecosystem::compare`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::IgnoreRule;
use crate::ecosystem::Ecosystem;
use crate::model::{DepGraph, NodeId, Version};

/// Default API base URL; `MENDR_OSV_API` overrides it (mirrors, tests).
const OSV_API: &str = "https://api.osv.dev/v1";
const BATCH_SIZE: usize = 500;
/// Parallel `GET /v1/vulns/{id}` requests.
const FETCH_WORKERS: usize = 8;

// ---- Schema -------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

// ---- Severity -----------------------------------------------------------------

/// Severity bucket (CVSS v3 qualitative scale). Ordered `low < medium < high
/// < critical`. JSON/TOML: `"low"`, `"medium"`, `"high"`, `"critical"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    pub fn from_score(score: f64) -> SeverityLevel {
        if score >= 9.0 {
            SeverityLevel::Critical
        } else if score >= 7.0 {
            SeverityLevel::High
        } else if score >= 4.0 {
            SeverityLevel::Medium
        } else {
            SeverityLevel::Low
        }
    }

    /// Parses `low`/`medium`/`moderate`/`high`/`critical` (any case).
    pub fn parse(s: &str) -> Option<SeverityLevel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(SeverityLevel::Low),
            "medium" | "moderate" => Some(SeverityLevel::Medium),
            "high" => Some(SeverityLevel::High),
            "critical" => Some(SeverityLevel::Critical),
            _ => None,
        }
    }
}

/// Severity of an advisory. `score` is the CVSS v3 base score when a v3
/// vector was available.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Severity {
    pub level: SeverityLevel,
    pub score: Option<f64>,
}

/// CVSS v3.0/v3.1 base score from a vector like
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (= 9.8).
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    if !parts.next()?.starts_with("CVSS:3") {
        return None;
    }
    let metrics: HashMap<&str, &str> = parts.filter_map(|p| p.split_once(':')).collect();
    let get = |k: &str| metrics.get(k).copied();
    let changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f64> {
        match get(k)? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup(raw))
}

/// CVSS v3.1 "Roundup": smallest number with one decimal >= x.
fn roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

fn level_from_json(v: Option<&serde_json::Value>) -> Option<SeverityLevel> {
    SeverityLevel::parse(v?.get("severity")?.as_str()?)
}

/// Severity of one record: CVSS v3 vector score if present, else
/// `database_specific.severity` (GHSA: LOW/MODERATE/HIGH/CRITICAL), else the
/// same fields on `affected[]` entries. `None` if nothing is known.
pub fn record_severity(record: &OsvRecord) -> Option<Severity> {
    let vectors = record
        .severity
        .iter()
        .chain(record.affected.iter().flat_map(|a| a.severity.iter()));
    for s in vectors {
        if s.kind == "CVSS_V3"
            && let Some(score) = cvss3_base_score(&s.score)
        {
            return Some(Severity {
                level: SeverityLevel::from_score(score),
                score: Some(score),
            });
        }
    }
    let level = level_from_json(record.database_specific.as_ref()).or_else(|| {
        record.affected.iter().find_map(|a| {
            level_from_json(a.database_specific.as_ref())
                .or_else(|| level_from_json(a.ecosystem_specific.as_ref()))
        })
    })?;
    Some(Severity { level, score: None })
}

// ---- Matching -------------------------------------------------------------------

fn ecosystem_matches(osv_eco: &str, eco: &dyn Ecosystem) -> bool {
    osv_eco.split(':').next() == Some(eco.osv_ecosystem())
}

/// Whether the record has an `affected` entry for `package` in `eco`.
pub fn mentions(record: &OsvRecord, eco: &dyn Ecosystem, package: &str) -> bool {
    record
        .affected
        .iter()
        .filter_map(|a| a.package.as_ref())
        .any(|p| p.name == package && ecosystem_matches(&p.ecosystem, eco))
}

/// Whether `package@version` is affected by `record`: listed in
/// `affected[].versions`, or inside a `SEMVER`/`ECOSYSTEM` range.
pub fn is_affected(
    record: &OsvRecord,
    eco: &dyn Ecosystem,
    package: &str,
    version: &Version,
) -> bool {
    record.affected.iter().any(|a| {
        let Some(p) = &a.package else { return false };
        if p.name != package || !ecosystem_matches(&p.ecosystem, eco) {
            return false;
        }
        a.versions.iter().any(|v| v == version.as_str())
            || a.ranges
                .iter()
                .filter(|r| r.kind == "SEMVER" || r.kind == "ECOSYSTEM")
                .any(|r| range_affects(r, eco, version))
    })
}

enum Ev<'a> {
    Introduced(&'a str),
    Fixed(&'a str),
    LastAffected(&'a str),
    Limit(&'a str),
}

impl Ev<'_> {
    fn version(&self) -> &str {
        match self {
            Ev::Introduced(v) | Ev::Fixed(v) | Ev::LastAffected(v) | Ev::Limit(v) => v,
        }
    }
}

/// Compare with OSV's special `"0"` (= before every version).
fn cmp_osv(eco: &dyn Ecosystem, a: &str, b: &str) -> Ordering {
    match (a == "0", b == "0") {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => eco.compare(&Version::new(a), &Version::new(b)),
    }
}

/// OSV range evaluation: walk events sorted by version, toggling
/// "vulnerable" on `introduced` (v >= e), off on `fixed` (v >= e) and
/// `last_affected` (v > e). `limit` (v >= e) excludes.
fn range_affects(range: &OsvRange, eco: &dyn Ecosystem, version: &Version) -> bool {
    let mut events: Vec<Ev> = Vec::new();
    for e in &range.events {
        if let Some(v) = &e.introduced {
            events.push(Ev::Introduced(v));
        }
        if let Some(v) = &e.fixed {
            events.push(Ev::Fixed(v));
        }
        if let Some(v) = &e.last_affected {
            events.push(Ev::LastAffected(v));
        }
        if let Some(v) = &e.limit {
            events.push(Ev::Limit(v));
        }
    }
    events.sort_by(|a, b| cmp_osv(eco, a.version(), b.version()));
    let v = version.as_str();
    let mut vulnerable = false;
    for e in &events {
        match e {
            Ev::Introduced(x) => {
                if cmp_osv(eco, v, x) != Ordering::Less {
                    vulnerable = true;
                }
            }
            Ev::Fixed(x) => {
                if cmp_osv(eco, v, x) != Ordering::Less {
                    vulnerable = false;
                }
            }
            Ev::LastAffected(x) => {
                if cmp_osv(eco, v, x) == Ordering::Greater {
                    vulnerable = false;
                }
            }
            Ev::Limit(x) => {
                if cmp_osv(eco, v, x) != Ordering::Less {
                    return false;
                }
            }
        }
    }
    vulnerable
}

// ---- Advisories (deduped) ------------------------------------------------------

/// One logical vulnerability of one package: OSV records that alias each
/// other and affect that package, merged. Records are merged per package
/// only, so one CVE in two packages gives two advisories, each with the ids,
/// summary and severity of its own package's records (and an ignore rule for
/// one package's id does not silence the other).
#[derive(Clone, Debug, PartialEq)]
pub struct Advisory {
    /// Primary id: the smallest non-`CVE-` record id in the group (sorted
    /// lexicographically), else the smallest id.
    pub id: String,
    /// Every other id and alias in the group, sorted, without `id`.
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// Highest severity among the group's records.
    pub severity: Option<Severity>,
    pub records: Vec<OsvRecord>,
    /// The package (ecosystem without `:suffix`); `None` for records that
    /// name no package.
    pub package: Option<OsvPackage>,
}

impl Advisory {
    /// Whether this is the advisory of `package` in `eco`.
    fn is_for(&self, eco: &dyn Ecosystem, package: &str) -> bool {
        self.package
            .as_ref()
            .is_some_and(|p| p.name == package && ecosystem_matches(&p.ecosystem, eco))
    }

    /// Affected if any record of the group says so.
    pub fn affects(&self, eco: &dyn Ecosystem, package: &str, version: &Version) -> bool {
        self.is_for(eco, package)
            && self
                .records
                .iter()
                .any(|r| is_affected(r, eco, package, version))
    }

    pub fn mentions(&self, eco: &dyn Ecosystem, package: &str) -> bool {
        self.is_for(eco, package)
    }

    /// Whether `id` is the primary id or one of the aliases, ignoring
    /// surrounding whitespace and ASCII case (ids in `mendr.toml` are
    /// hand-written).
    pub fn has_id(&self, id: &str) -> bool {
        let id = id.trim();
        std::iter::once(&self.id)
            .chain(&self.aliases)
            .any(|a| a.eq_ignore_ascii_case(id))
    }
}

/// Ids and aliases (see [`normalize_id`]) of every advisory returned by
/// [`Osv::advisories`] in this process, for [`warn_unmatched_ignores`].
static SEEN_IDS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// An advisory id as [`Advisory::has_id`] compares it.
fn normalize_id(id: &str) -> String {
    id.trim().to_ascii_uppercase()
}

fn remember_ids(advisories: &[Advisory]) {
    let mut seen = SEEN_IDS.lock().unwrap_or_else(|e| e.into_inner());
    for a in advisories {
        seen.extend(
            std::iter::once(&a.id)
                .chain(&a.aliases)
                .map(|id| normalize_id(id)),
        );
    }
}

/// Rules (not expired on `today`) whose id is not in `seen`.
fn unmatched_ignores<'a>(
    ignores: &'a [IgnoreRule],
    seen: &BTreeSet<String>,
    today: jiff::civil::Date,
) -> Vec<&'a IgnoreRule> {
    ignores
        .iter()
        .filter(|r| !crate::rules::ignore_expired(r, today) && !seen.contains(&normalize_id(&r.id)))
        .collect()
}

/// Warn about `[[ignore]]` rules that matched no advisory of the packages
/// scanned so far (a typo, or no longer needed). Call after all projects.
/// Expired rules are skipped: they already get their own warning.
pub fn warn_unmatched_ignores(ignores: &[IgnoreRule], today: jiff::civil::Date) {
    let seen = SEEN_IDS.lock().unwrap_or_else(|e| e.into_inner());
    for rule in unmatched_ignores(ignores, &seen, today) {
        crate::progress::warn(format!(
            "[[ignore]] entry for {} matched no advisory of the scanned packages \
             (check the id, or remove the entry if it is no longer needed)",
            rule.id.trim()
        ));
    }
}

fn is_informational(record: &OsvRecord) -> bool {
    let info = |v: &Option<serde_json::Value>| {
        v.as_ref()
            .and_then(|v| v.get("informational"))
            .is_some_and(|i| !i.is_null())
    };
    info(&record.database_specific) || record.affected.iter().any(|a| info(&a.database_specific))
}

/// Whether mendr should consider the record at all (not withdrawn, not
/// informational).
pub fn is_relevant(record: &OsvRecord) -> bool {
    record.withdrawn.is_none() && !is_informational(record)
}

/// Drop irrelevant records and merge, per affected package, records that
/// share an id/alias (a record naming several packages joins each of their
/// groups). Output is sorted by primary id, then package.
pub fn dedupe(records: Vec<OsvRecord>) -> Vec<Advisory> {
    // (ecosystem, name) -> records; `None` for records without packages.
    let mut by_package: BTreeMap<Option<(String, String)>, Vec<OsvRecord>> = BTreeMap::new();
    for record in records.into_iter().filter(is_relevant) {
        let keys: BTreeSet<(String, String)> = record
            .affected
            .iter()
            .filter_map(|a| a.package.as_ref())
            .map(|p| {
                let eco = p.ecosystem.split(':').next().unwrap_or_default();
                (eco.to_string(), p.name.clone())
            })
            .collect();
        if keys.is_empty() {
            by_package.entry(None).or_default().push(record);
        } else {
            for key in keys {
                by_package
                    .entry(Some(key))
                    .or_default()
                    .push(record.clone());
            }
        }
    }
    let mut out: Vec<Advisory> = by_package
        .into_iter()
        .flat_map(|(key, records)| {
            let package = key.map(|(ecosystem, name)| OsvPackage { ecosystem, name });
            merge_aliases(records)
                .into_iter()
                .map(move |(ids, records)| advisory(ids, records, package.clone()))
        })
        .collect();
    let package_key = |a: &Advisory| {
        a.package
            .as_ref()
            .map(|p| (p.name.clone(), p.ecosystem.clone()))
    };
    out.sort_by(|a, b| (&a.id, package_key(a)).cmp(&(&b.id, package_key(b))));
    out
}

/// Groups of records that share an id/alias (transitively), with all their
/// ids.
fn merge_aliases(records: Vec<OsvRecord>) -> Vec<(BTreeSet<String>, Vec<OsvRecord>)> {
    let mut groups: Vec<(BTreeSet<String>, Vec<OsvRecord>)> = Vec::new();
    for record in records {
        let mut ids: BTreeSet<String> = record.aliases.iter().cloned().collect();
        ids.insert(record.id.clone());
        let mut merged = (ids, vec![record]);
        let mut i = 0;
        while i < groups.len() {
            if groups[i].0.intersection(&merged.0).next().is_some() {
                let (ids, recs) = groups.swap_remove(i);
                merged.0.extend(ids);
                merged.1.extend(recs);
                i = 0; // the merged set may now touch earlier groups
            } else {
                i += 1;
            }
        }
        groups.push(merged);
    }
    groups
}

/// One merged group as an advisory.
fn advisory(
    ids: BTreeSet<String>,
    mut records: Vec<OsvRecord>,
    package: Option<OsvPackage>,
) -> Advisory {
    records.sort_by(|a, b| a.id.cmp(&b.id));
    records.dedup_by(|a, b| a.id == b.id);
    let primary = records
        .iter()
        .map(|r| r.id.as_str())
        .min_by_key(|id| (id.starts_with("CVE-"), *id))
        .expect("group is non-empty")
        .to_string();
    let aliases = ids.into_iter().filter(|i| *i != primary).collect();
    let summary = records
        .iter()
        .find(|r| r.id == primary)
        .and_then(|r| r.summary.clone())
        .or_else(|| records.iter().find_map(|r| r.summary.clone()));
    let severity = records.iter().filter_map(record_severity).max_by(|a, b| {
        (a.level, a.score.unwrap_or(0.0))
            .partial_cmp(&(b.level, b.score.unwrap_or(0.0)))
            .unwrap_or(Ordering::Equal)
    });
    Advisory {
        id: primary,
        aliases,
        summary,
        severity,
        records,
        package,
    }
}

/// A graph node affected by at least one advisory.
#[derive(Clone, Debug, PartialEq)]
pub struct VulnerableNode {
    pub node: NodeId,
    /// Indices into the advisory slice passed to [`vulnerabilities_for`].
    pub advisories: Vec<usize>,
}

/// Every registry node of `graph` affected by some advisory, in node order.
pub fn vulnerabilities_for(
    graph: &DepGraph,
    eco: &dyn Ecosystem,
    advisories: &[Advisory],
) -> Vec<VulnerableNode> {
    graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.registry)
        .filter_map(|(id, n)| {
            let hits: Vec<usize> = advisories
                .iter()
                .enumerate()
                .filter(|(_, a)| a.affects(eco, &n.name, &n.version))
                .map(|(i, _)| i)
                .collect();
            (!hits.is_empty()).then_some(VulnerableNode {
                node: id,
                advisories: hits,
            })
        })
        .collect()
}

/// Distinct registry package names in the graph, sorted.
pub fn package_names(graph: &DepGraph) -> Vec<String> {
    let names: BTreeSet<String> = graph
        .nodes
        .iter()
        .filter(|n| n.registry)
        .map(|n| n.name.clone())
        .collect();
    names.into_iter().collect()
}

// ---- Sources ----------------------------------------------------------------------

/// Read every `*.json` file in `dir` (non-recursive) as one OSV record.
pub fn load_snapshot(dir: &Path) -> Result<Vec<OsvRecord>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading OSV snapshot dir {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json") && p.is_file())
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let text =
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("parsing OSV record {}", p.display()))
        })
        .collect()
}

/// Where advisories come from. Create once per run, reuse across projects
/// (and for rescans in verification).
pub enum Osv {
    /// Offline: a fixed set of records (`--osv-snapshot DIR`).
    Snapshot(Vec<OsvRecord>),
    /// osv.dev API. Records are cached on disk under `cache::cache_dir()/osv`
    /// and refetched when the API reports a newer `modified` timestamp.
    Live {
        /// API base URL without trailing slash.
        api: String,
        /// Cache root (`cache::cache_dir()`).
        cache: PathBuf,
        records: HashMap<String, OsvRecord>,
        /// `(osv ecosystem, package)` -> advisory ids.
        queried: HashMap<(String, String), Vec<String>>,
    },
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVuln>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BatchVuln {
    id: String,
    #[serde(default)]
    modified: Option<String>,
}

impl Osv {
    pub fn snapshot(dir: &Path) -> Result<Osv> {
        Ok(Osv::Snapshot(load_snapshot(dir)?))
    }

    /// The osv.dev API, or `$MENDR_OSV_API` when set and not empty.
    pub fn live() -> Osv {
        let api = std::env::var("MENDR_OSV_API")
            .ok()
            .filter(|v| !v.trim().is_empty());
        Osv::live_at(
            api.as_deref().unwrap_or(OSV_API),
            &crate::cache::cache_dir(),
        )
    }

    /// An OSV API at `api` (e.g. `https://api.osv.dev/v1`), caching records
    /// under `cache`.
    pub fn live_at(api: &str, cache: &Path) -> Osv {
        Osv::Live {
            api: api.trim().trim_end_matches('/').to_string(),
            cache: cache.to_path_buf(),
            records: HashMap::new(),
            queried: HashMap::new(),
        }
    }

    /// All relevant, deduped advisories of `packages` in `eco` (for every
    /// version, not only the installed ones: the planner needs them to pick
    /// safe targets). One advisory id may appear once per package.
    pub fn advisories(
        &mut self,
        eco: &dyn Ecosystem,
        packages: &[String],
    ) -> Result<Vec<Advisory>> {
        let records: Vec<OsvRecord> = match self {
            Osv::Snapshot(records) => records
                .iter()
                .filter(|r| packages.iter().any(|p| mentions(r, eco, p)))
                .cloned()
                .collect(),
            Osv::Live {
                api,
                cache,
                records,
                queried,
            } => {
                let osv_eco = eco.osv_ecosystem().to_string();
                let missing: Vec<String> = packages
                    .iter()
                    .filter(|p| !queried.contains_key(&(osv_eco.clone(), (*p).clone())))
                    .cloned()
                    .collect();
                let found = query_batch(api, &osv_eco, &missing)?;
                let wanted: BTreeMap<&str, Option<&str>> = found
                    .iter()
                    .flat_map(|(_, vulns)| vulns)
                    .filter(|v| !records.contains_key(&v.id))
                    .map(|v| (v.id.as_str(), v.modified.as_deref()))
                    .collect();
                let wanted: Vec<(&str, Option<&str>)> = wanted.into_iter().collect();
                records.extend(fetch_records(api, cache, &wanted)?);
                for (name, vulns) in found {
                    queried.insert(
                        (osv_eco.clone(), name),
                        vulns.into_iter().map(|v| v.id).collect(),
                    );
                }
                let mut ids: BTreeSet<&String> = BTreeSet::new();
                for p in packages {
                    if let Some(list) = queried.get(&(osv_eco.clone(), p.clone())) {
                        ids.extend(list);
                    }
                }
                ids.into_iter()
                    .filter_map(|id| records.get(id).cloned())
                    .collect()
            }
        };
        // Records may also name packages outside the scan (or ecosystem).
        let wanted: BTreeSet<&str> = packages.iter().map(String::as_str).collect();
        let mut advisories = dedupe(records);
        advisories.retain(|a| {
            a.package
                .as_ref()
                .is_some_and(|p| wanted.contains(p.name.as_str()) && a.is_for(eco, &p.name))
        });
        remember_ids(&advisories);
        Ok(advisories)
    }
}

/// `POST /v1/querybatch` with package-only queries (= all advisories for the
/// package), following `next_page_token`s.
fn query_batch(
    api: &str,
    osv_eco: &str,
    packages: &[String],
) -> Result<Vec<(String, Vec<BatchVuln>)>> {
    let mut out: Vec<(String, Vec<BatchVuln>)> =
        packages.iter().map(|p| (p.clone(), Vec::new())).collect();
    // (index into `out`, page token)
    let mut pending: Vec<(usize, Option<String>)> =
        (0..packages.len()).map(|i| (i, None)).collect();
    while !pending.is_empty() {
        let mut next = Vec::new();
        for chunk in pending.chunks(BATCH_SIZE) {
            let queries: Vec<serde_json::Value> = chunk
                .iter()
                .map(|(i, token)| {
                    let mut q = serde_json::json!({"package": {"name": packages[*i], "ecosystem": osv_eco}});
                    if let Some(t) = token {
                        q["page_token"] = serde_json::Value::String(t.clone());
                    }
                    q
                })
                .collect();
            let body = serde_json::json!({ "queries": queries });
            let text = crate::http::post_json(&format!("{api}/querybatch"), &body)?;
            let resp: BatchResponse =
                serde_json::from_str(&text).context("parsing OSV querybatch response")?;
            // Results match queries by position: a short answer would
            // silently drop packages (= missed vulnerabilities).
            if resp.results.len() != chunk.len() {
                anyhow::bail!(
                    "OSV querybatch returned {} results for {} queries",
                    resp.results.len(),
                    chunk.len()
                );
            }
            for ((i, _), result) in chunk.iter().zip(resp.results) {
                out[*i].1.extend(result.vulns);
                if let Some(t) = result.next_page_token.filter(|t| !t.is_empty()) {
                    next.push((*i, Some(t)));
                }
            }
        }
        pending = next;
    }
    Ok(out)
}

/// [`fetch_record`] for every `(id, modified)` with up to [`FETCH_WORKERS`]
/// threads. Results are in input order; on failure, the error of the first
/// failed id (in input order) is returned.
fn fetch_records(
    api: &str,
    cache: &Path,
    wanted: &[(&str, Option<&str>)],
) -> Result<Vec<(String, OsvRecord)>> {
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let results: Mutex<Vec<Option<Result<OsvRecord>>>> =
        Mutex::new(wanted.iter().map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..FETCH_WORKERS.min(wanted.len()) {
            s.spawn(|| {
                while !failed.load(atomic::Ordering::Relaxed) {
                    let i = next.fetch_add(1, atomic::Ordering::Relaxed);
                    let Some((id, modified)) = wanted.get(i) else {
                        break;
                    };
                    let result = fetch_record(api, cache, id, *modified);
                    if result.is_err() {
                        failed.store(true, atomic::Ordering::Relaxed);
                    }
                    results.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(result);
                }
            });
        }
    });
    let results = results.into_inner().unwrap_or_else(|e| e.into_inner());
    // Ids are claimed in order and claimed ids always finish, so every id
    // before the first failure has a result.
    let mut out = Vec::with_capacity(wanted.len());
    for ((id, _), result) in wanted.iter().zip(results) {
        match result {
            Some(record) => out.push((id.to_string(), record?)),
            None => anyhow::bail!("OSV record {id} was not fetched"),
        }
    }
    Ok(out)
}

/// `GET /v1/vulns/{id}`, using the disk cache when its `modified` matches.
fn fetch_record(api: &str, cache: &Path, id: &str, modified: Option<&str>) -> Result<OsvRecord> {
    if let Some(text) = crate::cache::read_in(cache, "osv", id, None)
        && let Ok(record) = serde_json::from_str::<OsvRecord>(&text)
        && modified.is_some()
        && record.modified.as_deref() == modified
    {
        return Ok(record);
    }
    let text = crate::http::get_string(&format!("{api}/vulns/{id}"), &[])?;
    let record: OsvRecord =
        serde_json::from_str(&text).with_context(|| format!("parsing OSV record {id}"))?;
    crate::cache::write_in(cache, "osv", id, &text);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::fake::Fake;

    fn record(json: serde_json::Value) -> OsvRecord {
        serde_json::from_value(json).unwrap()
    }

    fn v(s: &str) -> Version {
        Version::new(s)
    }

    fn ranged(id: &str, pkg: &str, events: serde_json::Value) -> OsvRecord {
        record(serde_json::json!({
            "id": id,
            "affected": [{
                "package": {"ecosystem": "Fake", "name": pkg},
                "ranges": [{"type": "SEMVER", "events": events}]
            }]
        }))
    }

    #[test]
    fn introduced_fixed_ranges() {
        let eco = Fake::new();
        let r = ranged(
            "A-1",
            "p",
            serde_json::json!([{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.1"}]),
        );
        for (ver, expected) in [
            ("0.1.0", true),
            ("1.1.9", true),
            ("1.2.0", false),
            ("1.9.0", false),
            ("2.0.0", true),
            ("2.3.0", true),
            ("2.3.1", false),
            ("3.0.0", false),
        ] {
            assert_eq!(is_affected(&r, &eco, "p", &v(ver)), expected, "{ver}");
        }
        assert!(!is_affected(&r, &eco, "other", &v("1.0.0")));
    }

    #[test]
    fn last_affected_and_limit() {
        let eco = Fake::new();
        let r = ranged(
            "A-2",
            "p",
            serde_json::json!([{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]),
        );
        assert!(!is_affected(&r, &eco, "p", &v("0.9.0")));
        assert!(is_affected(&r, &eco, "p", &v("1.4.0")));
        assert!(!is_affected(&r, &eco, "p", &v("1.4.1")));
        let r = ranged(
            "A-3",
            "p",
            serde_json::json!([{"introduced": "0"}, {"limit": "2.0.0"}]),
        );
        assert!(is_affected(&r, &eco, "p", &v("1.0.0")));
        assert!(!is_affected(&r, &eco, "p", &v("2.0.0")));
    }

    #[test]
    fn unsorted_events_and_explicit_versions() {
        let eco = Fake::new();
        // Event order in the file must not matter.
        let r = ranged(
            "A-4",
            "p",
            serde_json::json!([{"fixed": "1.10.0"}, {"introduced": "1.9.0"}]),
        );
        assert!(is_affected(&r, &eco, "p", &v("1.9.5")));
        assert!(!is_affected(&r, &eco, "p", &v("1.10.0")));
        assert!(!is_affected(&r, &eco, "p", &v("1.2.0")));
        let r = record(serde_json::json!({
            "id": "A-5",
            "affected": [{"package": {"ecosystem": "Fake", "name": "p"}, "versions": ["0.5.0"],
                          "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]
        }));
        assert!(is_affected(&r, &eco, "p", &v("0.5.0")));
        assert!(
            !is_affected(&r, &eco, "p", &v("0.5.1")),
            "GIT ranges are ignored"
        );
    }

    #[test]
    fn ecosystem_must_match() {
        let eco = Fake::new();
        let r = record(serde_json::json!({
            "id": "A-6",
            "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}]
        }));
        assert!(!is_affected(&r, &eco, "p", &v("1.0.0")));
        let r = record(serde_json::json!({
            "id": "A-7",
            "affected": [{"package": {"ecosystem": "Fake:sub", "name": "p"}, "versions": ["1.0.0"]}]
        }));
        assert!(is_affected(&r, &eco, "p", &v("1.0.0")));
    }

    #[test]
    fn dedupe_merges_aliases_and_drops_withdrawn() {
        let mut a = ranged(
            "RUSTSEC-2020-0001",
            "p",
            serde_json::json!([{"introduced": "0"}, {"fixed": "1.0.0"}]),
        );
        a.aliases = vec!["CVE-2020-1".into(), "GHSA-aaaa".into()];
        let mut b = ranged(
            "GHSA-aaaa",
            "p",
            serde_json::json!([{"introduced": "0"}, {"fixed": "1.0.0"}]),
        );
        b.aliases = vec!["CVE-2020-1".into()];
        b.summary = Some("bad".into());
        let mut c = ranged("CVE-2020-1", "p", serde_json::json!([]));
        c.aliases = vec![];
        let mut gone = ranged("GHSA-gone", "p", serde_json::json!([{"introduced": "0"}]));
        gone.withdrawn = Some("2021-01-01T00:00:00Z".into());
        let mut info = ranged(
            "RUSTSEC-2021-0002",
            "p",
            serde_json::json!([{"introduced": "0"}]),
        );
        info.affected[0].database_specific =
            Some(serde_json::json!({"informational": "unmaintained"}));
        let other = ranged("GHSA-zzzz", "q", serde_json::json!([{"introduced": "0"}]));

        let out = dedupe(vec![c, a, gone, b, info, other]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "GHSA-aaaa");
        assert_eq!(out[0].aliases, vec!["CVE-2020-1", "RUSTSEC-2020-0001"]);
        assert_eq!(out[0].summary.as_deref(), Some("bad"));
        assert_eq!(out[0].records.len(), 3);
        assert!(out[0].has_id("RUSTSEC-2020-0001"));
        assert_eq!(out[1].id, "GHSA-zzzz");
    }

    #[test]
    fn dedupe_merges_transitively() {
        let mut a = ranged("A", "p", serde_json::json!([]));
        a.aliases = vec!["X".into()];
        let mut b = ranged("B", "p", serde_json::json!([]));
        b.aliases = vec!["Y".into()];
        let mut c = ranged("C", "p", serde_json::json!([]));
        c.aliases = vec!["X".into(), "Y".into()];
        let out = dedupe(vec![a, b, c]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "A");
    }

    #[test]
    fn dedupe_keeps_packages_apart() {
        let eco = Fake::new();
        let events = serde_json::json!([{"introduced": "0"}]);
        let mut x = ranged("RUSTSEC-X", "x", events.clone());
        x.aliases = vec!["CVE-1".into()];
        x.summary = Some("x is bad".into());
        let mut y = ranged("RUSTSEC-Y", "y", events.clone());
        y.aliases = vec!["CVE-1".into()];
        y.summary = Some("y is bad".into());
        y.database_specific = Some(serde_json::json!({"severity": "LOW"}));
        // One record for both packages joins both groups.
        let mut both = ranged("GHSA-both", "x", events.clone());
        both.affected.push(both.affected[0].clone());
        both.affected[1].package.as_mut().unwrap().name = "y".into();
        both.aliases = vec!["CVE-2".into()];

        let out = dedupe(vec![x, y, both]);
        let summary: Vec<(&str, &str, Vec<&str>)> = out
            .iter()
            .map(|a| {
                (
                    a.id.as_str(),
                    a.package.as_ref().unwrap().name.as_str(),
                    a.aliases.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("GHSA-both", "x", vec!["CVE-2"]),
                ("GHSA-both", "y", vec!["CVE-2"]),
                ("RUSTSEC-X", "x", vec!["CVE-1"]),
                ("RUSTSEC-Y", "y", vec!["CVE-1"]),
            ]
        );
        let (adv_x, adv_y) = (&out[2], &out[3]);
        assert_eq!(adv_x.summary.as_deref(), Some("x is bad"));
        assert_eq!(adv_y.summary.as_deref(), Some("y is bad"));
        assert_eq!(adv_x.severity, None);
        assert_eq!(adv_y.severity.unwrap().level, SeverityLevel::Low);
        assert!(adv_x.affects(&eco, "x", &v("1.0.0")));
        assert!(!adv_x.affects(&eco, "y", &v("1.0.0")));
        assert!(!out[0].affects(&eco, "y", &v("1.0.0")), "x's copy");
        assert!(out[1].affects(&eco, "y", &v("1.0.0")));
        assert!(!adv_x.mentions(&eco, "y"));
        assert!(!adv_x.has_id("RUSTSEC-Y"));

        // An ignore for y's id leaves x alone.
        let rules = [crate::config::IgnoreRule {
            id: "RUSTSEC-Y".into(),
            reason: "not reachable".into(),
            expires: None,
        }];
        let today = jiff::civil::date(2026, 1, 1);
        use crate::rules::{IgnoreMatch, ignore_match};
        assert_eq!(ignore_match(adv_x, &rules, today), IgnoreMatch::None);
        assert_eq!(
            ignore_match(adv_y, &rules, today),
            IgnoreMatch::Active(&rules[0])
        );

        // Each vulnerable node gets its own package's advisories only.
        let mut g = DepGraph::new();
        let root = g.add_root("app", &v("0.1.0"));
        let nx = g.add_node("x", &v("1.0.0"), true, true);
        let ny = g.add_node("y", &v("1.0.0"), true, true);
        g.add_edge(root, nx, crate::model::VersionReq::new("^1"));
        g.add_edge(root, ny, crate::model::VersionReq::new("^1"));
        assert_eq!(
            vulnerabilities_for(&g, &eco, &out),
            vec![
                VulnerableNode {
                    node: nx,
                    advisories: vec![0, 2]
                },
                VulnerableNode {
                    node: ny,
                    advisories: vec![1, 3]
                },
            ]
        );
    }

    #[test]
    fn unmatched_ignore_rules() {
        let mut a = ranged("GHSA-abcd-efgh", "p", serde_json::json!([]));
        a.aliases = vec!["CVE-2020-1".into()];
        let advisories = dedupe(vec![a]);
        assert!(advisories[0].has_id(" ghsa-ABCD-efgh "));
        assert!(advisories[0].has_id("cve-2020-1"));
        assert!(!advisories[0].has_id("GHSA-abcd"));

        let mut seen = BTreeSet::new();
        for a in &advisories {
            seen.extend(
                std::iter::once(&a.id)
                    .chain(&a.aliases)
                    .map(|id| normalize_id(id)),
            );
        }
        let rule = |id: &str, expires: Option<jiff::civil::Date>| IgnoreRule {
            id: id.into(),
            reason: "r".into(),
            expires,
        };
        let today = jiff::civil::date(2026, 6, 1);
        let rules = [
            rule("ghsa-abcd-efgh", None),
            rule(" CVE-2020-1", None),
            rule("GHSA-typo", None),
            rule("GHSA-old", Some(jiff::civil::date(2026, 1, 1))),
        ];
        let unmatched: Vec<&str> = unmatched_ignores(&rules, &seen, today)
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(unmatched, vec!["GHSA-typo"], "expired rules warn elsewhere");
    }

    #[test]
    fn cvss_scores() {
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
            Some(7.5)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Some(6.1)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"),
            Some(1.8)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
        assert_eq!(
            cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            None
        );
        assert_eq!(cvss3_base_score("garbage"), None);
    }

    #[test]
    fn severity_sources() {
        let r = record(
            serde_json::json!({"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}),
        );
        assert_eq!(
            record_severity(&r),
            Some(Severity {
                level: SeverityLevel::High,
                score: Some(7.5)
            })
        );
        let r =
            record(serde_json::json!({"id": "X", "database_specific": {"severity": "MODERATE"}}));
        assert_eq!(record_severity(&r).unwrap().level, SeverityLevel::Medium);
        let r = record(
            serde_json::json!({"id": "X", "affected": [{"ecosystem_specific": {"severity": "LOW"}}]}),
        );
        assert_eq!(record_severity(&r).unwrap().level, SeverityLevel::Low);
        assert_eq!(
            record_severity(&record(serde_json::json!({"id": "X"}))),
            None
        );
    }

    #[test]
    #[ignore = "needs network (api.osv.dev)"]
    fn live_osv_smoke() {
        let mut eco = Fake::new();
        eco.osv_name = Some("crates.io");
        let mut osv = Osv::live();
        let adv = osv.advisories(&eco, &["smallvec".to_string()]).unwrap();
        let a = adv
            .iter()
            .find(|a| a.has_id("RUSTSEC-2021-0003"))
            .expect("smallvec advisory");
        assert!(a.affects(&eco, "smallvec", &v("1.6.0")));
        assert!(!a.affects(&eco, "smallvec", &v("1.6.1")));
    }

    /// A stub OSV API: `querybatch` answers from `vulns` (package -> pages
    /// of ids; page `n > 0` is requested with token `p<n>`), `vulns/{id}`
    /// returns a record with `modified` `m1` (status 400 for `BAD-*`).
    /// Every request is logged as `"<path> <body>"`.
    fn stub_osv(
        vulns: &'static [(&'static str, &'static [&'static [&'static str]])],
    ) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        let base = crate::http::stub::serve(move |req| {
            seen.lock()
                .unwrap()
                .push(format!("{} {}", req.path, req.body));
            if req.path == "/querybatch" {
                let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                let results: Vec<serde_json::Value> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        let name = q["package"]["name"].as_str().unwrap();
                        let page: usize = q["page_token"]
                            .as_str()
                            .map_or(0, |t| t[1..].parse().unwrap());
                        let pages = vulns.iter().find(|(n, _)| *n == name).map_or(&[][..], |v| v.1);
                        let ids = pages.get(page).copied().unwrap_or_default();
                        let mut r = serde_json::json!({
                            "vulns": ids.iter().map(|id| serde_json::json!({"id": id, "modified": "m1"})).collect::<Vec<_>>()
                        });
                        if page + 1 < pages.len() {
                            r["next_page_token"] = format!("p{}", page + 1).into();
                        }
                        r
                    })
                    .collect();
                return (
                    200,
                    vec![],
                    serde_json::json!({ "results": results }).to_string(),
                );
            }
            let id = req.path.trim_start_matches("/vulns/");
            if id.starts_with("BAD-") {
                return (400, vec![], "no such thing".into());
            }
            let pkg = vulns
                .iter()
                .find(|(_, pages)| pages.iter().any(|p| p.contains(&id)))
                .map_or("?", |v| v.0);
            let record = serde_json::json!({
                "id": id,
                "modified": "m1",
                "affected": [{"package": {"ecosystem": "Fake", "name": pkg}, "versions": ["1.0.0"]}]
            });
            (200, vec![], record.to_string())
        });
        (base, log)
    }

    #[test]
    fn query_batch_follows_page_tokens() {
        let (api, log) = stub_osv(&[("a", &[&["A-1", "A-2"], &["A-3"]]), ("b", &[])]);
        let out = query_batch(&api, "Fake", &["a".into(), "b".into(), "c".into()]).unwrap();
        let ids: Vec<(&str, Vec<&str>)> = out
            .iter()
            .map(|(p, v)| (p.as_str(), v.iter().map(|v| v.id.as_str()).collect()))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("a", vec!["A-1", "A-2", "A-3"]),
                ("b", vec![]),
                ("c", vec![])
            ]
        );
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 2, "{log:?}");
        let second: serde_json::Value =
            serde_json::from_str(log[1].split_once(' ').unwrap().1).unwrap();
        assert_eq!(
            second["queries"],
            serde_json::json!([{"package": {"name": "a", "ecosystem": "Fake"}, "page_token": "p1"}])
        );
    }

    #[test]
    fn query_batch_rejects_short_responses() {
        let api =
            crate::http::stub::serve(|_| (200, vec![], r#"{"results": [{"vulns": []}]}"#.into()));
        let err = query_batch(&api, "Fake", &["a".into(), "b".into()]).unwrap_err();
        assert!(
            err.to_string().contains("1 results for 2 queries"),
            "{err:#}"
        );
    }

    #[test]
    fn fetch_record_uses_cache_only_when_fresh() {
        let (api, log) = stub_osv(&[("p", &[&["X-1"]])]);
        let cache = tempfile::tempdir().unwrap();
        let cached = serde_json::json!({"id": "X-1", "modified": "m0", "summary": "cached"});
        crate::cache::write_in(cache.path(), "osv", "X-1", &cached.to_string());

        let r = fetch_record(&api, cache.path(), "X-1", Some("m0")).unwrap();
        assert_eq!(r.summary.as_deref(), Some("cached"));
        assert!(log.lock().unwrap().is_empty(), "served from cache");

        let r = fetch_record(&api, cache.path(), "X-1", Some("m1")).unwrap();
        assert_eq!(r.modified.as_deref(), Some("m1"));
        assert_eq!(log.lock().unwrap().len(), 1, "newer upstream: refetched");
        let r = fetch_record(&api, cache.path(), "X-1", Some("m1")).unwrap();
        assert_eq!(r.modified.as_deref(), Some("m1"));
        assert_eq!(log.lock().unwrap().len(), 1, "cache updated");

        fetch_record(&api, cache.path(), "X-1", None).unwrap();
        assert_eq!(log.lock().unwrap().len(), 2, "unknown modified: refetched");

        crate::cache::write_in(cache.path(), "osv", "X-1", "{ corrupt");
        let r = fetch_record(&api, cache.path(), "X-1", Some("m1")).unwrap();
        assert_eq!(r.id, "X-1");
        assert_eq!(log.lock().unwrap().len(), 3, "corrupt cache: refetched");
    }

    #[test]
    fn live_advisories_fetch_records_in_parallel() {
        // More ids than workers; the stub answers in any order.
        const IDS: &[&str] = &[
            "A-12", "A-01", "A-02", "A-03", "A-04", "A-05", "A-06", "A-07", "A-08", "A-09", "A-10",
            "A-11",
        ];
        let ids = IDS;
        let (api, log) = stub_osv(&[("p", &[IDS]), ("q", &[&["Q-1"]])]);
        let cache = tempfile::tempdir().unwrap();
        let mut osv = Osv::live_at(&format!("{api}/"), cache.path());
        let eco = Fake::new();
        let adv = osv
            .advisories(&eco, &["p".to_string(), "q".to_string()])
            .unwrap();
        let got: Vec<&str> = adv.iter().map(|a| a.id.as_str()).collect();
        let mut expected = ids.to_vec();
        expected.sort();
        expected.push("Q-1");
        assert_eq!(got, expected);
        assert!(adv.iter().all(|a| a.affects(
            &eco,
            if a.id == "Q-1" { "q" } else { "p" },
            &v("1.0.0")
        )));
        assert_eq!(log.lock().unwrap().len(), 1 + ids.len() + 1);

        // Already queried: no more requests.
        let again = osv.advisories(&eco, &["q".to_string()]).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(log.lock().unwrap().len(), 1 + ids.len() + 1);
    }

    #[test]
    fn live_advisories_report_fetch_errors() {
        let (api, _) = stub_osv(&[("p", &[&["A-1", "BAD-1", "BAD-2", "C-1"]])]);
        let cache = tempfile::tempdir().unwrap();
        let mut osv = Osv::live_at(&api, cache.path());
        let err = osv
            .advisories(&Fake::new(), &["p".to_string()])
            .unwrap_err();
        assert!(format!("{err:#}").contains("/vulns/BAD-1"), "{err:#}");
    }

    #[test]
    fn snapshot_loading_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let r = ranged(
            "GHSA-1",
            "p",
            serde_json::json!([{"introduced": "0"}, {"fixed": "1.0.1"}]),
        );
        std::fs::write(
            dir.path().join("GHSA-1.json"),
            serde_json::to_string(&r).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("README.txt"), "not json").unwrap();
        let mut osv = Osv::snapshot(dir.path()).unwrap();
        let eco = Fake::new();
        let adv = osv.advisories(&eco, &["p".to_string()]).unwrap();
        assert_eq!(adv.len(), 1);
        assert!(osv.advisories(&eco, &["q".to_string()]).unwrap().is_empty());

        let mut g = DepGraph::new();
        let root = g.add_root("app", &v("0.1.0"));
        let p = g.add_node("p", &v("1.0.0"), true, true);
        g.add_edge(root, p, crate::model::VersionReq::new("^1"));
        assert_eq!(package_names(&g), vec!["p"]);
        let vulns = vulnerabilities_for(&g, &eco, &adv);
        assert_eq!(
            vulns,
            vec![VulnerableNode {
                node: p,
                advisories: vec![0]
            }]
        );

        std::fs::write(dir.path().join("bad.json"), "{").unwrap();
        assert!(Osv::snapshot(dir.path()).is_err());
    }
}
