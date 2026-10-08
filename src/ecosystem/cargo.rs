//! Cargo adapter.
//!
//! - **Graph:** nodes and edges come from `Cargo.lock`; workspace members and
//!   their declared requirements from `cargo metadata --no-deps` (cheap: no
//!   resolution, no downloads, no build scripts). Requirements on edges from
//!   registry packages come from the sparse index. Only crates.io packages
//!   are `registry` nodes; path, git and alternative-registry packages are
//!   local, and their outgoing edges get the requirement `*` (their manifests
//!   are not read).
//! - **Registry:** the crates.io sparse index (`https://index.crates.io`),
//!   one JSON line per version with `deps`, `yanked` and `pubtime`. Versions
//!   without `pubtime` get their date from the crates.io API (rate limited to
//!   1 request/s). Both are cached (`cargo-index`, `crates-io` namespaces).
//! - **Apply:** relock = `cargo update -p name@from --precise to`. Direct
//!   bump = rewrite every workspace declaration of `package` that allows
//!   `from` (inherited `workspace = true` ones in the root's
//!   `[workspace.dependencies]`) to `=to`, run `cargo update --workspace`,
//!   then write the final requirement (`to`, keeping an explicit `=`/`~`/`^`).
//!   Neither runs build scripts. Overrides are unsupported: `[patch]` cannot
//!   force a semver-incompatible version.
//! - `ApplyOptions::release_cutoff` is ignored: stable Cargo cannot limit
//!   resolution by publish time. New transitive versions are checked by
//!   verification's release-age check on the lockfile diff.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use toml_edit::{DocumentMut, Item, TableLike, Value};

use super::{
    AdapterError, ApplyOptions, Commands, DeclaredDep, Ecosystem, Release, has_files, run,
    semver_bump_kind,
};
use crate::model::{BumpKind, Change, DepGraph, NodeId, Strategy, Version, VersionReq};

const INDEX_URL: &str = "https://index.crates.io";
const CRATES_IO_API: &str = "https://crates.io/api/v1/crates";
/// Registry responses older than this are fetched again.
const CACHE_TTL: Duration = Duration::from_secs(3600);
/// crates.io crawler policy: at most one API request per second.
const API_INTERVAL: Duration = Duration::from_secs(1);

pub struct Cargo {
    /// Parsed sparse-index files by crate name.
    index: RefCell<HashMap<String, Rc<Vec<IndexEntry>>>>,
}

impl Cargo {
    pub fn new() -> Self {
        Cargo {
            index: RefCell::new(HashMap::new()),
        }
    }

    /// All index entries of `name` (memoized, cached on disk).
    fn entries(&self, name: &str) -> Result<Rc<Vec<IndexEntry>>, AdapterError> {
        if let Some(e) = self.index.borrow().get(name) {
            return Ok(e.clone());
        }
        let entries = Rc::new(parse_index(&fetch_index(name)?)?);
        self.index
            .borrow_mut()
            .insert(name.to_string(), entries.clone());
        Ok(entries)
    }
}

impl Default for Cargo {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Sparse index ----------------------------------------------------------------

/// One line of a sparse-index file.
#[derive(Clone, Debug, Deserialize)]
struct IndexEntry {
    vers: String,
    #[serde(default)]
    deps: Vec<IndexDep>,
    #[serde(default)]
    yanked: bool,
    pubtime: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct IndexDep {
    /// The name the dependent uses (a rename if `package` is set).
    name: String,
    req: String,
    /// `"normal"` (also when absent), `"build"` or `"dev"`.
    kind: Option<String>,
    #[serde(default)]
    optional: bool,
    /// Real crate name when renamed.
    package: Option<String>,
}

impl IndexDep {
    fn real_name(&self) -> &str {
        self.package.as_deref().unwrap_or(&self.name)
    }

    fn is_dev(&self) -> bool {
        self.kind.as_deref() == Some("dev")
    }
}

/// Path of a crate's file in the sparse index (`se/rd/serde`, `3/l/log`).
fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

fn fetch_index(name: &str) -> Result<String, AdapterError> {
    // Crate names are ASCII; anything else cannot be on crates.io.
    if name.is_empty() || !name.is_ascii() {
        return Err(AdapterError::NotFound(name.to_string()));
    }
    let key = name.to_ascii_lowercase();
    if let Some(text) = crate::cache::read("cargo-index", &key, Some(CACHE_TTL)) {
        return Ok(text);
    }
    let text = crate::http::get_string(&format!("{INDEX_URL}/{}", index_path(name)), &[]).map_err(
        |e| match e {
            crate::http::HttpError::NotFound(_) => AdapterError::NotFound(name.to_string()),
            other => other.into(),
        },
    )?;
    crate::cache::write("cargo-index", &key, &text);
    Ok(text)
}

fn parse_index(text: &str) -> Result<Vec<IndexEntry>, AdapterError> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).map_err(|e| AdapterError::Parse {
                what: "sparse index entry".into(),
                message: e.to_string(),
            })
        })
        .collect()
}

fn parse_time(s: &str) -> Option<jiff::Timestamp> {
    s.parse().ok()
}

/// Publish dates of every version from the crates.io API (fallback for
/// index entries without `pubtime`).
fn crates_io_dates(name: &str) -> Result<HashMap<String, jiff::Timestamp>, AdapterError> {
    #[derive(Deserialize)]
    struct Page {
        versions: Vec<ApiVersion>,
        #[serde(default)]
        meta: Meta,
    }
    #[derive(Deserialize)]
    struct ApiVersion {
        num: String,
        created_at: String,
    }
    #[derive(Default, Deserialize)]
    struct Meta {
        next_page: Option<String>,
    }

    let parse = |text: &str| -> Option<HashMap<String, jiff::Timestamp>> {
        let raw: HashMap<String, String> = serde_json::from_str(text).ok()?;
        Some(
            raw.into_iter()
                .filter_map(|(v, t)| Some((v, parse_time(&t)?)))
                .collect(),
        )
    };
    if let Some(dates) =
        crate::cache::read("crates-io", name, Some(CACHE_TTL)).and_then(|t| parse(&t))
    {
        return Ok(dates);
    }
    let mut raw: HashMap<String, String> = HashMap::new();
    let mut query = "?per_page=100".to_string();
    loop {
        throttle_api();
        let url = format!("{CRATES_IO_API}/{name}/versions{query}");
        let page: Page =
            serde_json::from_str(&crate::http::get_string(&url, &[])?).map_err(|e| {
                AdapterError::Parse {
                    what: format!("crates.io versions of {name}"),
                    message: e.to_string(),
                }
            })?;
        raw.extend(page.versions.into_iter().map(|v| (v.num, v.created_at)));
        match page.meta.next_page {
            Some(next) if !next.is_empty() => query = next,
            _ => break,
        }
    }
    let text = serde_json::to_string(&raw).expect("string map serializes");
    crate::cache::write("crates-io", name, &text);
    Ok(parse(&text).unwrap_or_default())
}

/// Sleep so that crates.io API requests are at least `API_INTERVAL` apart.
fn throttle_api() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = *last {
        let elapsed = t.elapsed();
        if elapsed < API_INTERVAL {
            std::thread::sleep(API_INTERVAL - elapsed);
        }
    }
    *last = Some(Instant::now());
}

// ---- Version semantics --------------------------------------------------------------

fn semver(v: &str) -> Option<semver::Version> {
    semver::Version::parse(v).ok()
}

/// Cargo requirement semantics (bare versions are caret requirements;
/// prereleases only match comparators naming the same `major.minor.patch`).
fn req_matches(req: &str, version: &str) -> bool {
    match (semver::VersionReq::parse(req), semver(version)) {
        (Ok(r), Some(v)) => r.matches(&v),
        _ => false,
    }
}

fn compare_versions(a: &str, b: &str) -> Ordering {
    match (semver(a), semver(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

// ---- Lockfile + metadata --------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    /// `name`, `name version` or `name version (source)`.
    #[serde(default)]
    dependencies: Vec<String>,
}

impl LockPackage {
    fn is_crates_io(&self) -> bool {
        self.source.as_deref().is_some_and(is_crates_io)
    }
}

fn is_crates_io(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index"
        || source == "sparse+https://index.crates.io/"
}

fn read_lockfile(dir: &Path) -> Result<Lockfile, AdapterError> {
    let text = std::fs::read_to_string(dir.join("Cargo.lock"))?;
    toml::from_str(&text).map_err(|e| AdapterError::Parse {
        what: "Cargo.lock".into(),
        message: e.to_string(),
    })
}

/// Index into `packages` of the lockfile dependency `spec`.
fn find_locked(packages: &[LockPackage], spec: &str) -> Option<usize> {
    let mut parts = spec.splitn(3, ' ');
    let name = parts.next()?;
    let version = parts.next();
    let source = parts
        .next()
        .map(|s| s.trim_start_matches('(').trim_end_matches(')'));
    packages.iter().position(|p| {
        p.name == name
            && version.is_none_or(|v| p.version == v)
            && source.is_none_or(|s| p.source.as_deref() == Some(s))
    })
}

/// `cargo metadata --no-deps` output (the parts we use).
#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<MetaPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MetaPackage {
    id: String,
    name: String,
    version: String,
    manifest_path: PathBuf,
    dependencies: Vec<MetaDep>,
}

#[derive(Debug, Deserialize)]
struct MetaDep {
    /// Real crate name (renames are in `rename`).
    name: String,
    req: String,
}

impl Metadata {
    fn members(&self) -> impl Iterator<Item = &MetaPackage> {
        self.packages
            .iter()
            .filter(|p| self.workspace_members.contains(&p.id))
    }
}

fn metadata(dir: &Path) -> Result<Metadata, AdapterError> {
    let out = run(Command::new("cargo")
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(dir))?;
    serde_json::from_str(&out).map_err(|e| AdapterError::Parse {
        what: "cargo metadata output".into(),
        message: e.to_string(),
    })
}

/// Pick the declared requirement for an edge to `version`: the first
/// declaration that allows it, else the first one, else `*`.
fn pick_req<'r>(mut reqs: impl Iterator<Item = &'r str> + Clone, version: &str) -> VersionReq {
    let req = reqs
        .clone()
        .find(|r| req_matches(r, version))
        .or_else(|| reqs.next())
        .unwrap_or("*");
    VersionReq::new(req)
}

/// Declared dependencies of a registry package (`Ecosystem::dependencies_of`).
type DepsOf<'a> = dyn FnMut(&str, &Version) -> Result<Vec<DeclaredDep>, AdapterError> + 'a;

/// Build the graph: BFS over the lockfile from the workspace members.
fn build_graph(
    lock: &Lockfile,
    meta: &Metadata,
    deps_of: &mut DepsOf,
) -> Result<DepGraph, AdapterError> {
    let pkgs = &lock.package;
    let mut graph = DepGraph::new();
    let mut ids: HashMap<usize, NodeId> = HashMap::new();
    let mut members: HashMap<usize, &MetaPackage> = HashMap::new();
    let mut queue = VecDeque::new();
    for m in meta.members() {
        let idx = pkgs
            .iter()
            .position(|p| p.name == m.name && p.version == m.version && p.source.is_none())
            .ok_or_else(|| AdapterError::Parse {
                what: "Cargo.lock".into(),
                message: format!(
                    "workspace member {}@{} is missing (lockfile out of date?)",
                    m.name, m.version
                ),
            })?;
        ids.insert(idx, graph.add_root(&m.name, &Version::new(&m.version)));
        members.insert(idx, m);
        queue.push_back(idx);
    }
    while let Some(idx) = queue.pop_front() {
        let parent = &pkgs[idx];
        let from = ids[&idx];
        let declared = if parent.is_crates_io() {
            deps_of(&parent.name, &Version::new(&parent.version))?
        } else {
            Vec::new()
        };
        for spec in &parent.dependencies {
            let child_idx = find_locked(pkgs, spec).ok_or_else(|| AdapterError::Parse {
                what: "Cargo.lock".into(),
                message: format!("dependency `{spec}` of {} is not locked", parent.name),
            })?;
            let child = &pkgs[child_idx];
            let req = if parent.is_crates_io() {
                let reqs = declared.iter().filter(|d| d.name == child.name);
                pick_req(reqs.map(|d| d.req.as_str()), &child.version)
            } else if let Some(m) = members.get(&idx) {
                let reqs = m.dependencies.iter().filter(|d| d.name == child.name);
                pick_req(reqs.map(|d| d.req.as_str()), &child.version)
            } else {
                VersionReq::new("*")
            };
            // Direct: a registry crate declared by a local package.
            let direct = !parent.is_crates_io() && child.is_crates_io();
            let to = match ids.get(&child_idx) {
                Some(&id) => {
                    graph.nodes[id].direct |= direct;
                    id
                }
                None => {
                    let id = graph.add_node(
                        &child.name,
                        &Version::new(&child.version),
                        direct,
                        child.is_crates_io(),
                    );
                    ids.insert(child_idx, id);
                    queue.push_back(child_idx);
                    id
                }
            };
            graph.add_edge(from, to, req);
        }
    }
    Ok(graph)
}

// ---- Manifest editing ------------------------------------------------------------------

const DEP_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// The final requirement for a bump to `to`: `to`, keeping an explicit
/// single `=`, `~` or `^` operator of `old`.
fn bumped_req(old: &str, to: &str) -> String {
    let old = old.trim();
    for op in ["=", "~", "^"] {
        if let Some(rest) = old.strip_prefix(op)
            && !rest.contains(',')
        {
            return format!("{op}{to}");
        }
    }
    to.to_string()
}

/// Replace a string value, keeping its surrounding whitespace/comments.
fn set_string(v: &mut Value, s: &str) {
    let decor = v.decor().clone();
    *v = Value::from(s);
    *v.decor_mut() = decor;
}

/// Rewrite, in one dependency table, every registry declaration of
/// `package` whose requirement allows `from`. Returns (edited count,
/// whether some declaration is inherited with `workspace = true`).
fn edit_dep_table(
    table: &mut dyn TableLike,
    package: &str,
    from: &str,
    new_req: &dyn Fn(&str) -> String,
) -> (usize, bool) {
    let (mut edited, mut inherited) = (0, false);
    for (key, item) in table.iter_mut() {
        let real = item
            .get("package")
            .and_then(Item::as_str)
            .unwrap_or(key.get())
            .to_string();
        if real != package {
            continue;
        }
        if let Some(v) = item.as_value_mut()
            && let Some(req) = v.as_str()
        {
            if req_matches(req, from) {
                let req = new_req(req);
                set_string(v, &req);
                edited += 1;
            }
            continue;
        }
        let Some(t) = item.as_table_like_mut() else {
            continue;
        };
        if t.get("workspace").and_then(Item::as_bool) == Some(true) {
            inherited = true;
            continue;
        }
        if ["path", "git", "registry"]
            .iter()
            .any(|k| t.contains_key(k))
        {
            continue;
        }
        if let Some(v) = t.get_mut("version").and_then(Item::as_value_mut)
            && let Some(req) = v.as_str()
            && req_matches(req, from)
        {
            let req = new_req(req);
            set_string(v, &req);
            edited += 1;
        }
    }
    (edited, inherited)
}

/// Edit the dependency tables of one member manifest (incl. `[target.*]`).
fn edit_member(
    doc: &mut DocumentMut,
    package: &str,
    from: &str,
    new_req: &dyn Fn(&str) -> String,
) -> (usize, bool) {
    let (mut edited, mut inherited) = (0, false);
    let mut visit = |t: &mut dyn TableLike| {
        for name in DEP_TABLES {
            if let Some(deps) = t.get_mut(name).and_then(Item::as_table_like_mut) {
                let (e, i) = edit_dep_table(deps, package, from, new_req);
                edited += e;
                inherited |= i;
            }
        }
    };
    visit(doc.as_table_mut());
    if let Some(targets) = doc.get_mut("target").and_then(Item::as_table_like_mut) {
        for (_, target) in targets.iter_mut() {
            if let Some(t) = target.as_table_like_mut() {
                visit(t);
            }
        }
    }
    (edited, inherited)
}

/// New contents of every manifest that declares `package` allowing `from`.
/// `originals` maps manifest paths to their text and must contain every
/// member manifest and the workspace root manifest `root`.
fn edit_manifests(
    originals: &BTreeMap<PathBuf, String>,
    members: &[PathBuf],
    root: &Path,
    package: &str,
    from: &str,
    new_req: &dyn Fn(&str) -> String,
) -> Result<BTreeMap<PathBuf, String>, AdapterError> {
    let mut docs: BTreeMap<PathBuf, DocumentMut> = BTreeMap::new();
    let doc = |path: &Path, docs: &mut BTreeMap<PathBuf, DocumentMut>| {
        if !docs.contains_key(path) {
            let text = originals.get(path).map(String::as_str).unwrap_or_default();
            let parsed = text.parse::<DocumentMut>().map_err(|e| {
                AdapterError::ManifestNotEditable(format!("{}: {e}", path.display()))
            })?;
            docs.insert(path.to_path_buf(), parsed);
        }
        Ok::<_, AdapterError>(())
    };
    let (mut edited, mut inherited) = (0, false);
    for m in members {
        doc(m, &mut docs)?;
        let (e, i) = edit_member(docs.get_mut(m).expect("loaded"), package, from, new_req);
        edited += e;
        inherited |= i;
    }
    if inherited {
        doc(root, &mut docs)?;
        let ws = docs
            .get_mut(root)
            .expect("loaded")
            .get_mut("workspace")
            .and_then(|w| w.get_mut("dependencies"))
            .and_then(Item::as_table_like_mut);
        let e = ws.map_or(0, |t| edit_dep_table(t, package, from, new_req).0);
        if e == 0 {
            return Err(AdapterError::ManifestNotEditable(format!(
                "`{package}` is inherited with `workspace = true` but [workspace.dependencies] in {} has no declaration allowing {from}",
                root.display()
            )));
        }
        edited += e;
    }
    if edited == 0 {
        return Err(AdapterError::ManifestNotEditable(format!(
            "no manifest in the workspace declares `{package}` with a requirement allowing {from}"
        )));
    }
    Ok(docs
        .into_iter()
        .map(|(p, d)| (p, d.to_string()))
        .filter(|(p, text)| originals.get(p) != Some(text))
        .collect())
}

fn write_files(files: &BTreeMap<PathBuf, String>) -> Result<(), AdapterError> {
    for (path, text) in files {
        std::fs::write(path, text)?;
    }
    Ok(())
}

/// Run `cargo update ...` in `dir`; resolver failures become
/// `ResolutionConflict`.
fn cargo_update(dir: &Path, args: &[&str]) -> Result<(), AdapterError> {
    match run(Command::new("cargo")
        .arg("update")
        .args(args)
        .current_dir(dir))
    {
        Ok(_) => Ok(()),
        Err(AdapterError::Command { stderr_tail, .. })
            if stderr_tail.contains("failed to select a version")
                || stderr_tail.contains("conflict") =>
        {
            Err(AdapterError::ResolutionConflict(stderr_tail))
        }
        Err(e) => Err(e),
    }
}

/// Error unless `Cargo.lock` in `dir` now locks `package@version`.
fn ensure_locked(dir: &Path, package: &str, version: &Version) -> Result<(), AdapterError> {
    let lock = read_lockfile(dir)?;
    if lock
        .package
        .iter()
        .any(|p| p.name == package && p.version == version.as_str())
    {
        Ok(())
    } else {
        Err(AdapterError::ResolutionConflict(format!(
            "Cargo did not lock {package}@{version}"
        )))
    }
}

fn direct_bump(
    workdir: &Path,
    package: &str,
    from: &Version,
    to: &Version,
) -> Result<(), AdapterError> {
    let meta = metadata(workdir)?;
    let base = workdir.canonicalize()?;
    // Only manifests inside the copy are ours to edit.
    let inside = |p: &Path| p.canonicalize().is_ok_and(|p| p.starts_with(&base));
    let members: Vec<PathBuf> = meta
        .members()
        .map(|m| m.manifest_path.clone())
        .filter(|p| inside(p))
        .collect();
    let root = meta.workspace_root.join("Cargo.toml");
    let mut originals = BTreeMap::new();
    for p in members.iter().chain(inside(&root).then_some(&root)) {
        originals.insert(p.clone(), std::fs::read_to_string(p)?);
    }
    let exact = edit_manifests(&originals, &members, &root, package, from.as_str(), &|_| {
        format!("={to}")
    })?;
    let fin = edit_manifests(
        &originals,
        &members,
        &root,
        package,
        from.as_str(),
        &|old| bumped_req(old, to.as_str()),
    )?;
    // Pin exactly so the resolver picks `to`, then write the final requirement
    // (the lockfile stays valid: `to` satisfies it).
    write_files(&exact)?;
    let result =
        cargo_update(workdir, &["--workspace"]).and_then(|_| ensure_locked(workdir, package, to));
    if let Err(e) = result {
        let restore: BTreeMap<PathBuf, String> = exact
            .keys()
            .map(|p| (p.clone(), originals[p].clone()))
            .collect();
        write_files(&restore)?;
        return Err(e);
    }
    write_files(&fin)
}

// ---- Trait -------------------------------------------------------------------------------

impl Ecosystem for Cargo {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "crates.io"
    }

    fn detect(&self, dir: &Path) -> bool {
        has_files(dir, &["Cargo.toml", "Cargo.lock"])
    }

    fn supports(&self, strategy: Strategy) -> bool {
        strategy != Strategy::Override
    }

    fn shared_copies(&self) -> bool {
        true
    }

    fn compare(&self, a: &Version, b: &Version) -> Ordering {
        compare_versions(a.as_str(), b.as_str())
    }

    fn satisfies(&self, req: &VersionReq, version: &Version) -> bool {
        req_matches(req.as_str(), version.as_str())
    }

    fn bump_kind(&self, from: &Version, to: &Version) -> BumpKind {
        match (semver(from.as_str()), semver(to.as_str())) {
            (Some(a), Some(b)) => {
                semver_bump_kind((a.major, a.minor, a.patch), (b.major, b.minor, b.patch))
            }
            _ => BumpKind::Major,
        }
    }

    fn is_prerelease(&self, version: &Version) -> bool {
        semver(version.as_str()).is_some_and(|v| !v.pre.is_empty())
    }

    fn resolve_graph(&self, project_dir: &Path) -> Result<DepGraph, AdapterError> {
        let lock = read_lockfile(project_dir)?;
        let meta = metadata(project_dir)?;
        build_graph(&lock, &meta, &mut |name, version| {
            self.dependencies_of(name, version)
        })
    }

    fn apply(
        &self,
        workdir: &Path,
        change: &Change,
        _opts: &ApplyOptions,
    ) -> Result<(), AdapterError> {
        // On failure leave the lockfile as it was (manifests: see `direct_bump`).
        let lock_path = workdir.join("Cargo.lock");
        let lock = std::fs::read_to_string(&lock_path)?;
        let result = match change {
            Change::Relock { package, from, to } => {
                let spec = format!("{package}@{from}");
                cargo_update(workdir, &["-p", &spec, "--precise", to.as_str()])
                    .and_then(|_| ensure_locked(workdir, package, to))
            }
            Change::DirectBump {
                package, from, to, ..
            } => direct_bump(workdir, package, from, to),
            Change::Override { .. } => Err(AdapterError::Unsupported(
                "Cargo has no override mechanism for semver-incompatible versions".into(),
            )),
        };
        if result.is_err() {
            std::fs::write(&lock_path, lock)?;
        }
        result
    }

    fn default_commands(&self, _project_dir: &Path) -> Commands {
        Commands {
            install: None,
            build: Some("cargo build --locked --all-targets".into()),
            test: Some("cargo test --locked".into()),
        }
    }

    fn copy_excludes(&self) -> &'static [&'static str] {
        &["target"]
    }

    fn releases(&self, package: &str) -> Result<Vec<Release>, AdapterError> {
        let entries = self.entries(package)?;
        let mut dates = HashMap::new();
        if entries.iter().any(|e| e.pubtime.is_none()) {
            match crates_io_dates(package) {
                Ok(d) => dates = d,
                Err(e) => crate::progress::warn(format!("no publish dates for {package}: {e}")),
            }
        }
        Ok(entries
            .iter()
            .map(|e| Release {
                version: Version::new(&e.vers),
                published_at: e
                    .pubtime
                    .as_deref()
                    .and_then(parse_time)
                    .or_else(|| dates.get(&e.vers).copied()),
                yanked: e.yanked,
            })
            .collect())
    }

    fn dependencies_of(
        &self,
        package: &str,
        version: &Version,
    ) -> Result<Vec<DeclaredDep>, AdapterError> {
        let entries = self.entries(package)?;
        let entry = entries
            .iter()
            .find(|e| e.vers == version.as_str())
            .ok_or_else(|| AdapterError::NotFound(format!("{package}@{version}")))?;
        Ok(entry
            .deps
            .iter()
            .filter(|d| !d.is_dev())
            .map(|d| DeclaredDep {
                name: d.real_name().to_string(),
                req: VersionReq::new(&d.req),
                optional: d.optional,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::new(s)
    }

    fn sat(req: &str, version: &str) -> bool {
        Cargo::new().satisfies(&VersionReq::new(req), &v(version))
    }

    #[test]
    fn index_paths() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("cc"), "2/cc");
        assert_eq!(index_path("log"), "3/l/log");
        assert_eq!(index_path("Serde"), "se/rd/serde");
        assert_eq!(index_path("smallvec"), "sm/al/smallvec");
    }

    #[test]
    fn requirements_follow_cargo() {
        assert!(sat("1.2", "1.9.0"));
        assert!(!sat("1.2", "2.0.0"));
        assert!(sat("^0.2.3", "0.2.9"));
        assert!(!sat("0.2.3", "0.3.0"));
        assert!(!sat("0.0.3", "0.0.4"));
        assert!(sat("~1.2.3", "1.2.9"));
        assert!(!sat("~1.2.3", "1.3.0"));
        assert!(sat("=1.0.0", "1.0.0"));
        assert!(sat(">=0.52, <0.62", "0.59.0"));
        assert!(!sat(">=0.52, <0.62", "0.62.0"));
        assert!(sat("*", "7.0.0"));
        assert!(!sat("^1", "1.1.0-beta.1"));
        assert!(sat("^1.1.0-beta.1", "1.1.0-beta.2"));
        assert!(!sat("not a req", "1.0.0"));
        assert!(!sat("1", "garbage"));
    }

    #[test]
    fn ordering_and_bumps() {
        let c = Cargo::new();
        assert_eq!(c.compare(&v("1.10.0"), &v("1.9.0")), Ordering::Greater);
        assert_eq!(c.compare(&v("1.0.0-rc.1"), &v("1.0.0")), Ordering::Less);
        assert_eq!(c.compare(&v("0.0.0-0"), &v("0.0.1")), Ordering::Less);
        assert_eq!(c.compare(&v("1.0.0"), &v("x")), Ordering::Less);
        let bump = |a, b| c.bump_kind(&v(a), &v(b));
        assert_eq!(bump("1.0.0", "1.0.1"), BumpKind::Patch);
        assert_eq!(bump("3.3.0", "3.4.0"), BumpKind::Minor);
        assert_eq!(bump("1.9.0", "2.0.0"), BumpKind::Major);
        assert_eq!(bump("0.1.0", "0.1.5"), BumpKind::Patch);
        assert_eq!(bump("0.1.9", "0.2.0"), BumpKind::Major);
        assert_eq!(bump("0.0.1", "0.0.2"), BumpKind::Major);
        assert!(c.is_prerelease(&v("2.0.0-beta.2")));
        assert!(!c.is_prerelease(&v("2.0.0")));
    }

    const INDEX: &str = r#"
{"name":"foo","vers":"1.0.0","deps":[{"name":"bar","req":"^0.5","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal"},{"name":"cc","req":"^1","features":[],"optional":false,"default_features":true,"target":null,"kind":"build"},{"name":"quickcheck","req":"^1","features":[],"optional":false,"default_features":true,"target":null,"kind":"dev"}],"cksum":"00","features":{},"yanked":false,"pubtime":"2020-01-01T00:00:00Z"}
{"name":"foo","vers":"1.1.0","deps":[{"name":"bar2","req":"^0.8","features":[],"optional":true,"default_features":true,"target":"cfg(windows)","kind":"normal","package":"bar"}],"cksum":"00","features":{},"yanked":true,"pubtime":"2021-06-01T12:30:00Z","v":2}
"#;

    #[test]
    fn registry_from_index_lines() {
        let c = Cargo::new();
        c.index
            .borrow_mut()
            .insert("foo".into(), Rc::new(parse_index(INDEX).unwrap()));
        let releases = c.releases("foo").unwrap();
        assert_eq!(releases.len(), 2);
        assert_eq!(releases[0].version, v("1.0.0"));
        assert_eq!(
            releases[0].published_at,
            Some("2020-01-01T00:00:00Z".parse().unwrap())
        );
        assert!(!releases[0].yanked && releases[1].yanked);

        let deps = c.dependencies_of("foo", &v("1.0.0")).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["bar", "cc"]); // dev-dependency dropped
        let deps = c.dependencies_of("foo", &v("1.1.0")).unwrap();
        assert_eq!(
            deps,
            [DeclaredDep {
                name: "bar".into(), // real name of the rename
                req: VersionReq::new("^0.8"),
                optional: true,
            }]
        );
        assert!(matches!(
            c.dependencies_of("foo", &v("9.9.9")),
            Err(AdapterError::NotFound(_))
        ));
        assert!(parse_index("{not json").is_err());
    }

    const LOCK: &str = r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "bar 0.5.1",
 "foo",
 "gitdep",
 "util",
]

[[package]]
name = "bar"
version = "0.5.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "bar"
version = "0.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "cc"
version = "1.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "bar 0.5.1",
 "cc",
]

[[package]]
name = "gitdep"
version = "0.3.0"
source = "git+https://example.com/gitdep#abc"
dependencies = [
 "bar 0.8.0",
]

[[package]]
name = "unused"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "util"
version = "0.2.0"
dependencies = [
 "bar 0.8.0",
]
"#;

    const METADATA: &str = r#"{
      "packages": [
        {"id": "path+file:///ws#app@0.1.0", "name": "app", "version": "0.1.0",
         "manifest_path": "/ws/Cargo.toml",
         "dependencies": [
           {"name": "bar", "req": "^0.5", "kind": "dev", "rename": null, "source": "registry+https://github.com/rust-lang/crates.io-index"},
           {"name": "foo", "req": "^1.0", "kind": null, "rename": "f", "source": "registry+https://github.com/rust-lang/crates.io-index"},
           {"name": "gitdep", "req": "*", "kind": null, "source": "git+https://example.com/gitdep"},
           {"name": "util", "req": "*", "kind": null, "source": null, "path": "/ws/util"}
         ]},
        {"id": "path+file:///ws/util#0.2.0", "name": "util", "version": "0.2.0",
         "manifest_path": "/ws/util/Cargo.toml",
         "dependencies": [
           {"name": "bar", "req": "^0.8.0", "kind": null, "source": "registry+https://github.com/rust-lang/crates.io-index"}
         ]}
      ],
      "workspace_members": ["path+file:///ws#app@0.1.0", "path+file:///ws/util#0.2.0"],
      "workspace_root": "/ws"
    }"#;

    fn graph() -> DepGraph {
        let lock: Lockfile = toml::from_str(LOCK).unwrap();
        let meta: Metadata = serde_json::from_str(METADATA).unwrap();
        let index = parse_index(INDEX).unwrap();
        build_graph(&lock, &meta, &mut |name, version| {
            assert!(
                ["foo", "bar", "cc"].contains(&name),
                "only registry packages are looked up, not {name}"
            );
            if name != "foo" {
                return Ok(Vec::new());
            }
            let e = index.iter().find(|e| e.vers == version.as_str()).unwrap();
            Ok(e.deps
                .iter()
                .filter(|d| !d.is_dev())
                .map(|d| DeclaredDep {
                    name: d.real_name().into(),
                    req: VersionReq::new(&d.req),
                    optional: d.optional,
                })
                .collect())
        })
        .unwrap()
    }

    fn req(g: &DepGraph, from: (&str, &str), to: (&str, &str)) -> String {
        let a = g.find(from.0, &v(from.1)).unwrap();
        let b = g.find(to.0, &v(to.1)).unwrap();
        let edge = g.edges.iter().find(|e| e.from == a && e.to == b).unwrap();
        edge.req.to_string()
    }

    #[test]
    fn graph_from_lockfile_and_metadata() {
        let g = graph();
        let roots: Vec<String> = g.roots.iter().map(|&r| g.label(r)).collect();
        assert_eq!(roots, ["app@0.1.0", "util@0.2.0"]);
        // `unused` is not reachable, so it is not in the graph.
        assert!(g.find("unused", &v("1.0.0")).is_none());
        let node = |n: &str, ver: &str| g.node(g.find(n, &v(ver)).unwrap()).clone();
        assert!(node("foo", "1.0.0").registry && node("foo", "1.0.0").direct);
        assert!(node("bar", "0.5.1").direct); // dev-dependency of app
        assert!(node("bar", "0.8.0").direct); // declared by util and a git dep
        assert!(node("cc", "1.2.0").registry && !node("cc", "1.2.0").direct);
        assert!(!node("gitdep", "0.3.0").registry);
        assert!(!node("util", "0.2.0").registry);

        assert_eq!(req(&g, ("app", "0.1.0"), ("foo", "1.0.0")), "^1.0");
        assert_eq!(req(&g, ("app", "0.1.0"), ("bar", "0.5.1")), "^0.5");
        assert_eq!(req(&g, ("foo", "1.0.0"), ("bar", "0.5.1")), "^0.5");
        assert_eq!(req(&g, ("foo", "1.0.0"), ("cc", "1.2.0")), "^1");
        assert_eq!(req(&g, ("util", "0.2.0"), ("bar", "0.8.0")), "^0.8.0");
        assert_eq!(req(&g, ("gitdep", "0.3.0"), ("bar", "0.8.0")), "*");
        assert_eq!(req(&g, ("app", "0.1.0"), ("util", "0.2.0")), "*");
    }

    #[test]
    fn stale_lockfile_is_an_error() {
        let lock: Lockfile = toml::from_str("version = 4\n").unwrap();
        let meta: Metadata = serde_json::from_str(METADATA).unwrap();
        let err = build_graph(&lock, &meta, &mut |_, _| Ok(Vec::new())).unwrap_err();
        assert!(err.to_string().contains("app@0.1.0"), "{err}");
    }

    #[test]
    fn lockfile_dependency_specs() {
        let lock: Lockfile = toml::from_str(
            r#"
[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "a"
version = "1.0.0"
source = "git+https://example.com/a#x"
[[package]]
name = "a"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
"#,
        )
        .unwrap();
        let p = &lock.package;
        assert_eq!(find_locked(p, "a"), Some(0));
        assert_eq!(find_locked(p, "a 2.0.0"), Some(2));
        assert_eq!(
            find_locked(p, "a 1.0.0 (git+https://example.com/a#x)"),
            Some(1)
        );
        assert_eq!(find_locked(p, "b"), None);
        assert!(p[0].is_crates_io() && !p[1].is_crates_io() && p[2].is_crates_io());
    }

    // ---- Manifest editing ----

    fn edit(
        files: &[(&str, &str)],
        members: &[&str],
        package: &str,
    ) -> Result<BTreeMap<PathBuf, String>, AdapterError> {
        let originals = files
            .iter()
            .map(|(p, t)| (PathBuf::from(p), t.to_string()))
            .collect();
        let members: Vec<PathBuf> = members.iter().map(PathBuf::from).collect();
        edit_manifests(
            &originals,
            &members,
            Path::new("/ws/Cargo.toml"),
            package,
            "3.3.0",
            &|old| bumped_req(old, "3.4.0"),
        )
    }

    #[test]
    fn edits_every_declaration_form_and_keeps_formatting() {
        let manifest = r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
tempfile = "3.3"   # keep me
other = { version = "3.3", package = "tempfile", features = ["x"] }
unrelated = "1"
local = { path = "../local", package = "tempfile" }

[dependencies.tf]
package = "tempfile"
version = "=3.3.0"

[dev-dependencies]
tempfile = { version = "~3.3.0" }

[target.'cfg(unix)'.build-dependencies]
tempfile = "^3"

[build-dependencies]
tempfile = "2"   # another major: untouched
"#;
        let files = [("/ws/Cargo.toml", manifest)];
        let out = edit(&files, &["/ws/Cargo.toml"], "tempfile").unwrap();
        let expected = manifest
            .replace(r#""3.3"   # keep me"#, r#""3.4.0"   # keep me"#)
            .replace(r#"{ version = "3.3","#, r#"{ version = "3.4.0","#)
            .replace(r#""=3.3.0""#, r#""=3.4.0""#)
            .replace(r#""~3.3.0""#, r#""~3.4.0""#)
            .replace(r#""^3""#, r#""^3.4.0""#);
        assert_eq!(out[Path::new("/ws/Cargo.toml")], expected);
    }

    #[test]
    fn edits_inherited_workspace_dependencies() {
        let root = r#"[workspace]
members = ["a"]

[workspace.dependencies]
tempfile = { version = "3.3.0", default-features = false }
"#;
        let member = "[package]\nname = \"a\"\n\n[dependencies]\ntempfile.workspace = true\n";
        let files = [("/ws/Cargo.toml", root), ("/ws/a/Cargo.toml", member)];
        let out = edit(&files, &["/ws/a/Cargo.toml"], "tempfile").unwrap();
        assert_eq!(out.len(), 1, "member manifest is unchanged");
        assert_eq!(
            out[Path::new("/ws/Cargo.toml")],
            root.replace("\"3.3.0\"", "\"3.4.0\"")
        );

        // Inherited, but the root does not declare it.
        let files = [
            ("/ws/Cargo.toml", "[workspace]\n"),
            ("/ws/a/Cargo.toml", member),
        ];
        let err = edit(&files, &["/ws/a/Cargo.toml"], "tempfile").unwrap_err();
        assert!(matches!(err, AdapterError::ManifestNotEditable(_)), "{err}");
    }

    #[test]
    fn missing_declaration_is_not_editable() {
        let manifest =
            "[dependencies]\ntempfile = \"2\"\nlocal = { path = \"x\", package = \"tempfile\" }\n";
        let err = edit(
            &[("/ws/Cargo.toml", manifest)],
            &["/ws/Cargo.toml"],
            "tempfile",
        )
        .unwrap_err();
        assert!(matches!(err, AdapterError::ManifestNotEditable(_)), "{err}");
    }

    #[test]
    fn bumped_requirements() {
        assert_eq!(bumped_req("3.3", "3.4.0"), "3.4.0");
        assert_eq!(bumped_req("^3.3", "3.4.0"), "^3.4.0");
        assert_eq!(bumped_req("=3.3.0", "3.4.0"), "=3.4.0");
        assert_eq!(bumped_req("~3.3", "3.4.0"), "~3.4.0");
        assert_eq!(bumped_req(">=3.3, <4", "3.4.0"), "3.4.0");
        assert_eq!(bumped_req("3.*", "3.4.0"), "3.4.0");
    }

    #[test]
    fn detection_and_capabilities() {
        let c = Cargo::new();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        assert!(!c.detect(dir.path()));
        std::fs::write(dir.path().join("Cargo.lock"), "").unwrap();
        assert!(c.detect(dir.path()));
        assert!(c.supports(Strategy::Relock) && c.supports(Strategy::DirectBump));
        assert!(!c.supports(Strategy::Override));
        let change = Change::Override {
            package: "a".into(),
            from: v("1.0.0"),
            to: v("2.0.0"),
        };
        let err = c
            .apply(dir.path(), &change, &ApplyOptions::default())
            .unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
        assert_eq!(c.copy_excludes(), ["target"]);
    }

    #[test]
    #[ignore = "needs network"]
    fn live_registry_smoke() {
        let c = Cargo::new();
        let releases = c.releases("smallvec").unwrap();
        let r = releases.iter().find(|r| r.version == v("1.6.1")).unwrap();
        let published: jiff::Timestamp = "2021-01-08T17:34:20Z".parse().unwrap();
        assert_eq!(r.published_at, Some(published));
        // Fallback source (paginated, > 100 versions for serde).
        let dates = crates_io_dates("smallvec").unwrap();
        assert_eq!(dates["1.6.1"].as_second(), published.as_second());
        assert!(crates_io_dates("serde").unwrap().len() > 100);
    }

    /// Applies real changes to copies of the fixtures (needs `cargo` and
    /// network): `nix develop -c cargo test cargo::tests::apply -- --ignored`.
    #[test]
    #[ignore = "needs cargo and network"]
    fn apply_on_fixture_copies() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-projects/cargo");
        let copy = |name: &str| {
            let dir = tempfile::tempdir().unwrap();
            for f in ["Cargo.toml", "Cargo.lock"] {
                std::fs::copy(fixtures.join(name).join(f), dir.path().join(f)).unwrap();
            }
            std::fs::create_dir(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
            dir
        };
        let locked = |dir: &Path, name: &str| -> Vec<String> {
            let lock = read_lockfile(dir).unwrap();
            lock.package
                .into_iter()
                .filter(|p| p.name == name)
                .map(|p| p.version)
                .collect()
        };
        let c = Cargo::new();
        let opts = ApplyOptions::default();

        let dir = copy("relock");
        let g = c.resolve_graph(dir.path()).unwrap();
        assert!(g.find("smallvec", &v("1.6.0")).is_some());
        let relock = Change::Relock {
            package: "smallvec".into(),
            from: v("1.6.0"),
            to: v("1.6.1"),
        };
        c.apply(dir.path(), &relock, &opts).unwrap();
        assert_eq!(locked(dir.path(), "smallvec"), ["1.6.1"]);
        // A version the parent's requirement excludes is a resolution conflict.
        let bad = Change::Relock {
            package: "smallvec".into(),
            from: v("1.6.1"),
            to: v("2.0.0-beta.2"),
        };
        let err = c.apply(dir.path(), &bad, &opts).unwrap_err();
        assert!(matches!(err, AdapterError::ResolutionConflict(_)), "{err}");
        assert_eq!(locked(dir.path(), "smallvec"), ["1.6.1"]);

        let dir = copy("direct-bump");
        let bump = Change::DirectBump {
            package: "tempfile".into(),
            from: v("3.3.0"),
            to: v("3.4.0"),
            bump: BumpKind::Minor,
        };
        c.apply(dir.path(), &bump, &opts).unwrap();
        assert_eq!(locked(dir.path(), "tempfile"), ["3.4.0"]);
        assert!(locked(dir.path(), "remove_dir_all").is_empty());
        let manifest = std::fs::read_to_string(dir.path().join("Cargo.toml")).unwrap();
        assert!(manifest.contains("tempfile = \"3.4.0\""), "{manifest}");
        // The lockfile still matches the final manifest.
        run(Command::new("cargo")
            .args(["update", "--workspace", "--locked"])
            .current_dir(dir.path()))
        .unwrap();
        let g = c.resolve_graph(dir.path()).unwrap();
        assert!(g.find("tempfile", &v("3.4.0")).is_some());
    }
}
