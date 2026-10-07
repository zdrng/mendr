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
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ecosystem::Ecosystem;
use crate::model::{DepGraph, NodeId, Version};

const OSV_API: &str = "https://api.osv.dev/v1";
const BATCH_SIZE: usize = 500;

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

/// One logical vulnerability: OSV records that alias each other, merged.
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
}

impl Advisory {
    /// Affected if any record of the group says so.
    pub fn affects(&self, eco: &dyn Ecosystem, package: &str, version: &Version) -> bool {
        self.records
            .iter()
            .any(|r| is_affected(r, eco, package, version))
    }

    pub fn mentions(&self, eco: &dyn Ecosystem, package: &str) -> bool {
        self.records.iter().any(|r| mentions(r, eco, package))
    }

    /// Whether `id` is the primary id or one of the aliases.
    pub fn has_id(&self, id: &str) -> bool {
        self.id == id || self.aliases.iter().any(|a| a == id)
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

/// Drop irrelevant records and merge records that share an id/alias.
/// Output is sorted by primary id.
pub fn dedupe(records: Vec<OsvRecord>) -> Vec<Advisory> {
    let mut groups: Vec<(BTreeSet<String>, Vec<OsvRecord>)> = Vec::new();
    for record in records.into_iter().filter(is_relevant) {
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
    let mut out: Vec<Advisory> = groups
        .into_iter()
        .map(|(ids, mut records)| {
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
            }
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
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

#[derive(Deserialize)]
struct BatchVuln {
    id: String,
    #[serde(default)]
    modified: Option<String>,
}

impl Osv {
    pub fn snapshot(dir: &Path) -> Result<Osv> {
        Ok(Osv::Snapshot(load_snapshot(dir)?))
    }

    pub fn live() -> Osv {
        Osv::Live {
            records: HashMap::new(),
            queried: HashMap::new(),
        }
    }

    /// All relevant, deduped advisories mentioning any of `packages` in
    /// `eco` (for every version, not only the installed ones: the planner
    /// needs them to pick safe targets).
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
            Osv::Live { records, queried } => {
                let osv_eco = eco.osv_ecosystem().to_string();
                let missing: Vec<String> = packages
                    .iter()
                    .filter(|p| !queried.contains_key(&(osv_eco.clone(), (*p).clone())))
                    .cloned()
                    .collect();
                let found = query_batch(&osv_eco, &missing)?;
                for (name, vulns) in found {
                    for v in &vulns {
                        if !records.contains_key(&v.id) {
                            records
                                .insert(v.id.clone(), fetch_record(&v.id, v.modified.as_deref())?);
                        }
                    }
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
        Ok(dedupe(records))
    }
}

/// `POST /v1/querybatch` with package-only queries (= all advisories for the
/// package), following `next_page_token`s.
fn query_batch(osv_eco: &str, packages: &[String]) -> Result<Vec<(String, Vec<BatchVuln>)>> {
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
            let text = crate::http::post_json(&format!("{OSV_API}/querybatch"), &body)?;
            let resp: BatchResponse =
                serde_json::from_str(&text).context("parsing OSV querybatch response")?;
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

/// `GET /v1/vulns/{id}`, using the disk cache when its `modified` matches.
fn fetch_record(id: &str, modified: Option<&str>) -> Result<OsvRecord> {
    if let Some(text) = crate::cache::read("osv", id, None)
        && let Ok(record) = serde_json::from_str::<OsvRecord>(&text)
        && modified.is_some()
        && record.modified.as_deref() == modified
    {
        return Ok(record);
    }
    let text = crate::http::get_string(&format!("{OSV_API}/vulns/{id}"), &[])?;
    let record: OsvRecord =
        serde_json::from_str(&text).with_context(|| format!("parsing OSV record {id}"))?;
    crate::cache::write("osv", id, &text);
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
