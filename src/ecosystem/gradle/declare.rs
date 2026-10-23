//! Where a Gradle build declares each module (`group:artifact`) and with
//! which version, and the direct-bump rewrite of those versions.
//!
//! Small hand-rolled scanners (no Gradle run) read Groovy (`*.gradle`) and
//! Kotlin (`*.gradle.kts`) scripts, version catalogs
//! (`gradle/*.versions.toml`) and every `gradle.properties`. Recognized:
//! - string notation `"g:a:v[:classifier][@ext]"` in any string literal
//!   outside comments (dependency calls, `platform(..)`, `constraints {}`,
//!   `ext` maps, ...); `"g:a"` without a version may be followed by a
//!   `{ version { strictly/require/prefer } }` block;
//! - map notation `group: 'g', name: 'a', version: 'v'` (Kotlin: `=`);
//! - one level of indirection when the version is a variable (`$x`, `${x}`,
//!   `${libs.versions.x.get()}`, a bare `x` in map notation): `val`/`def`,
//!   `ext`/`extra` properties, `set("x", ..)`, `by extra(..)`,
//!   `gradle.properties` and catalog `[versions]`. Script variables are
//!   matched by name, in the referencing file first, then in every other
//!   scanned file (shallowest first);
//! - catalog `[libraries]` in every form, `version.ref` into `[versions]`.
//!
//! Edits are textual: only the version literal changes (`1.0!!` keeps its
//! `!!`); catalogs are edited with `toml_edit` to keep their formatting.
//! Ranges and dynamic versions (`[1.0,2.0)`, `1.+`, `latest.release`) and
//! versions computed from several parts are declarations without an
//! editable version.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, TableLike, Value};

use crate::ecosystem::AdapterError;

/// Directory names never scanned.
const SKIP_DIRS: [&str; 7] = [
    "build",
    ".gradle",
    ".git",
    "node_modules",
    ".idea",
    "out",
    ".kotlin",
];
/// Builds whose `src` holds convention plugins (scanned, unlike other `src`).
const PLUGIN_BUILDS: [&str; 2] = ["buildSrc", "build-logic"];
/// Map-notation keys (and project coordinates): never version variables.
const RESERVED: [&str; 3] = ["group", "name", "version"];
/// Stands for one `$x` / `${x}` interpolation in a scanned string.
const HOLE: char = '\u{1}';

/// Where the version of one declaration lives.
#[derive(Clone, Debug)]
pub struct Declaration {
    /// File relative to the project root.
    pub file: PathBuf,
    /// The declared version (after following one level of indirection),
    /// `None` when declared without a version (managed by a platform/BOM or
    /// plugin) or when the version is a range, dynamic or computed in a way
    /// mendr cannot rewrite.
    pub version: Option<String>,
    /// The literal holding `version`; `Some` iff `version` is.
    site: Option<Literal>,
    /// The version text or expression mendr cannot rewrite (for messages).
    raw: Option<String>,
}

/// A version literal as written (possibly a range, or with `!!`) and where.
#[derive(Clone, Debug)]
struct Literal {
    /// File relative to the project root.
    file: PathBuf,
    place: Place,
    text: String,
}

#[derive(Clone, Debug)]
enum Place {
    /// At byte `start` of a script or properties file.
    Text { start: usize },
    /// At byte `start` of the string `value` at `keys` in a TOML catalog.
    Toml {
        keys: Vec<String>,
        value: String,
        start: usize,
    },
}

impl Literal {
    fn same_place(&self, other: &Literal) -> bool {
        self.file == other.file
            && match (&self.place, &other.place) {
                (Place::Text { start: a }, Place::Text { start: b }) => a == b,
                (Place::Toml { keys: a, .. }, Place::Toml { keys: b, .. }) => a == b,
                _ => false,
            }
    }
}

/// All declarations in the project, by module (`group:artifact`).
#[derive(Debug, Default)]
pub struct Declarations {
    by_module: BTreeMap<String, Vec<Declaration>>,
}

impl Declarations {
    pub fn get(&self, module: &str) -> &[Declaration] {
        self.by_module.get(module).map_or(&[], Vec::as_slice)
    }

    /// The lowest editable declared version of `module` (`cmp` = version
    /// order), `None` if not declared or only without an editable version.
    pub fn version(&self, module: &str, cmp: &dyn Fn(&str, &str) -> Ordering) -> Option<&str> {
        self.get(module)
            .iter()
            .filter_map(|d| d.version.as_deref())
            .min_by(|a, b| cmp(a, b))
    }

    pub fn contains(&self, module: &str) -> bool {
        self.by_module.contains_key(module)
    }

    /// Other modules whose version is written in the same place as one of
    /// `module`'s (a shared catalog `version.ref`, script variable or
    /// property), so bumping `module` bumps them too. Sorted, empty if none.
    pub fn shared_ref_modules(&self, module: &str) -> Vec<String> {
        let sites: Vec<&Literal> = self
            .get(module)
            .iter()
            .filter_map(|d| d.site.as_ref())
            .collect();
        self.by_module
            .iter()
            .filter(|(m, decls)| {
                *m != module
                    && decls
                        .iter()
                        .filter_map(|d| d.site.as_ref())
                        .any(|s| sites.iter().any(|t| t.same_place(s)))
            })
            .map(|(m, _)| m.clone())
            .collect()
    }
}

/// Scan every build script and catalog of the Gradle build rooted at `root`.
pub fn scan(root: &Path) -> Result<Declarations, AdapterError> {
    let mut files = Vec::new();
    walk(root, Path::new(""), false, &mut files)?;
    files.sort_by_key(|f| (f.components().count(), f.clone()));

    let mut defs = Defs::default();
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(root.join(file))?;
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "gradle.properties" {
            scan_properties(file, &text, &mut defs);
        } else if let Some(catalog) = name.strip_suffix(".versions.toml") {
            scan_catalog(file, catalog, &text, &mut defs, &mut found)?;
        } else {
            scan_script(file, &text, name.ends_with(".kts"), &mut defs, &mut found);
        }
    }

    let mut decls = Declarations::default();
    for (module, file, source) in found {
        let decl = resolve(file, source, &defs);
        decls.by_module.entry(module).or_default().push(decl);
    }
    Ok(decls)
}

/// Direct bump: rewrite every editable declaration of `module` whose
/// version is lower than `to` (per `cmp`) to `to`. `ManifestNotEditable`
/// if nothing was rewritten.
pub fn bump(
    root: &Path,
    module: &str,
    to: &str,
    cmp: &dyn Fn(&str, &str) -> Ordering,
) -> Result<(), AdapterError> {
    let decls = scan(root)?;
    let all = decls.get(module);
    let mut sites: Vec<&Literal> = Vec::new();
    for d in all {
        if let (Some(v), Some(site)) = (&d.version, &d.site)
            && cmp(v, to) == Ordering::Less
            && !sites.iter().any(|s| s.same_place(site))
        {
            sites.push(site);
        }
    }
    if sites.is_empty() {
        return Err(AdapterError::ManifestNotEditable(not_bumped(
            module, all, to,
        )));
    }
    let mut by_file: BTreeMap<&Path, Vec<&Literal>> = BTreeMap::new();
    for s in sites {
        by_file.entry(s.file.as_path()).or_default().push(s);
    }
    for (file, lits) in by_file {
        let path = root.join(file);
        let text = std::fs::read_to_string(&path)?;
        let new = if file.extension().is_some_and(|e| e == "toml") {
            rewrite_toml(&text, &lits, to)
        } else {
            rewrite_text(&text, &lits, to)
        }
        .map_err(|e| AdapterError::ManifestNotEditable(format!("{}: {e}", file.display())))?;
        std::fs::write(&path, new)?;
    }
    Ok(())
}

/// Why `bump` found nothing to rewrite.
fn not_bumped(module: &str, all: &[Declaration], to: &str) -> String {
    if all.is_empty() {
        return format!("no declaration of {module} found");
    }
    if all.iter().any(|d| d.version.is_some()) {
        return format!("no declaration of {module} has a version lower than {to}");
    }
    match all.iter().find(|d| d.raw.is_some()) {
        Some(d) => format!(
            "{module} is declared in {} with version `{}`, which mendr cannot rewrite (a range, dynamic or computed version)",
            d.file.display(),
            d.raw.as_deref().unwrap_or_default()
        ),
        None => format!(
            "{module} is declared without a version in {} (managed by a platform or plugin)",
            all[0].file.display()
        ),
    }
}

/// The editable version in a literal's text: `1.0` for `1.0` and `1.0!!`,
/// `None` for ranges, dynamic and empty versions.
fn editable(text: &str) -> Option<&str> {
    let v = text.strip_suffix("!!").unwrap_or(text);
    let dynamic = v.is_empty()
        || v.starts_with("latest.")
        || v.contains(|c: char| c.is_whitespace() || "[]()+,!$:@{}\"'".contains(c) || c == HOLE);
    (!dynamic).then_some(v)
}

fn rewrite_text(text: &str, lits: &[&Literal], to: &str) -> Result<String, String> {
    let mut edits: Vec<(usize, &str)> = lits
        .iter()
        .filter_map(|l| match l.place {
            Place::Text { start } => Some((start, editable(&l.text)?)),
            Place::Toml { .. } => None,
        })
        .collect();
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out = text.to_string();
    for (start, old) in edits {
        if out.get(start..start + old.len()) != Some(old) {
            return Err(format!("expected `{old}` at byte {start}"));
        }
        out.replace_range(start..start + old.len(), to);
    }
    Ok(out)
}

fn rewrite_toml(text: &str, lits: &[&Literal], to: &str) -> Result<String, String> {
    let mut doc = text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
    for lit in lits {
        let (Place::Toml { keys, value, start }, Some(old)) = (&lit.place, editable(&lit.text))
        else {
            continue;
        };
        let new = format!("{}{to}{}", &value[..*start], &value[start + old.len()..]);
        let mut item = doc.as_item_mut();
        for k in keys {
            item = item.get_mut(k.as_str()).ok_or(format!("missing `{k}`"))?;
        }
        let v = item
            .as_value_mut()
            .filter(|v| v.as_str() == Some(value.as_str()))
            .ok_or(format!("`{}` changed", keys.join(".")))?;
        let decor = v.decor().clone();
        *v = Value::from(new);
        *v.decor_mut() = decor;
    }
    Ok(doc.to_string())
}

// ---- Files -----------------------------------------------------------------------------

/// Collect build scripts, catalogs and properties under `root/rel`.
fn walk(
    root: &Path,
    rel: &Path,
    plugins: bool,
    out: &mut Vec<PathBuf>,
) -> Result<(), AdapterError> {
    let mut entries: Vec<_> = std::fs::read_dir(root.join(rel))?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let ty = entry.file_type()?;
        let path = rel.join(name);
        if ty.is_dir() {
            if SKIP_DIRS.contains(&name) || (name == "src" && !plugins) {
                continue;
            }
            walk(root, &path, plugins || PLUGIN_BUILDS.contains(&name), out)?;
        } else if ty.is_file()
            && (name.ends_with(".gradle")
                || name.ends_with(".gradle.kts")
                || name == "gradle.properties"
                || (name.ends_with(".versions.toml")
                    && rel.file_name().is_some_and(|d| d == "gradle")))
        {
            out.push(path);
        }
    }
    Ok(())
}

// ---- Variables -------------------------------------------------------------------------

/// Version variables found while scanning.
#[derive(Default)]
struct Defs {
    /// Script variables and properties by name, in scan order.
    vars: HashMap<String, Vec<Literal>>,
    /// Catalog `[versions]` by (catalog name, key with `.` separators).
    catalog: HashMap<(String, String), Literal>,
}

/// A reference to a version variable.
#[derive(Debug, PartialEq)]
enum VarRef {
    Name(String),
    /// `<catalog>.versions.<key>`.
    Catalog(String, String),
}

/// How a declaration's version is given, before resolving variables.
enum Source {
    None,
    Literal(Literal),
    Ref { expr: String, var: VarRef },
    Computed(String),
}

impl Defs {
    fn lookup(&self, var: &VarRef, file: &Path) -> Option<&Literal> {
        match var {
            VarRef::Name(name) => {
                let defs = self.vars.get(name)?;
                defs.iter().find(|d| d.file == file).or(defs.first())
            }
            VarRef::Catalog(c, k) => self.catalog.get(&(c.clone(), catalog_key(k))),
        }
    }
}

/// Catalog accessor form of a key: `jackson-core` -> `jackson.core`.
fn catalog_key(key: &str) -> String {
    key.replace(['-', '_'], ".")
}

fn resolve(file: PathBuf, source: Source, defs: &Defs) -> Declaration {
    let lit = match source {
        Source::None => None,
        Source::Computed(raw) => Some(Err(raw)),
        Source::Literal(lit) => Some(Ok(lit)),
        Source::Ref { expr, var } => Some(defs.lookup(&var, &file).cloned().ok_or(expr)),
    };
    let (version, site, raw) = match lit {
        None => (None, None, None),
        Some(Err(raw)) => (None, None, Some(raw)),
        Some(Ok(lit)) => match editable(&lit.text) {
            Some(v) => (Some(v.to_string()), Some(lit), None),
            None => (None, None, Some(lit.text)),
        },
    };
    Declaration {
        file,
        version,
        site,
        raw,
    }
}

/// The variable an expression like `x`, `ext.x`, `rootProject.extra["x"]`,
/// `property("x")` or `libs.versions.x.get()` refers to.
fn var_ref(expr: &str) -> Option<VarRef> {
    let mut e = expr.trim();
    loop {
        let before = e;
        for suffix in [".get()", "!!", ".toString()", "?.toString()", "as String"] {
            e = e.strip_suffix(suffix).unwrap_or(e).trim_end();
        }
        if e == before {
            break;
        }
    }
    if let Some(inner) = e.strip_suffix(')').or_else(|| e.strip_suffix(']')) {
        let inner = inner.trim_end();
        let q = inner.chars().last().filter(|c| *c == '"' || *c == '\'')?;
        let body = &inner[..inner.len() - 1];
        let name = &body[body.rfind(q)? + 1..];
        return (!name.is_empty()).then(|| VarRef::Name(name.to_string()));
    }
    let segs: Vec<&str> = e.split('.').collect();
    if !segs.iter().all(|s| is_ident(s)) {
        return None;
    }
    if segs.len() >= 3 && segs[1] == "versions" {
        return Some(VarRef::Catalog(segs[0].to_string(), segs[2..].join(".")));
    }
    Some(VarRef::Name(segs.last()?.to_string()))
}

fn is_ident(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && s.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
}

// ---- gradle.properties -------------------------------------------------------------------

fn scan_properties(file: &Path, text: &str, defs: &mut Defs) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let body = line.trim_end_matches(['\n', '\r']);
        let trimmed = body.trim_start();
        if trimmed.is_empty() || trimmed.starts_with(['#', '!']) || body.ends_with('\\') {
            continue;
        }
        let Some(sep) = body.find(['=', ':']) else {
            continue;
        };
        let key = body[..sep].trim();
        let after = &body[sep + 1..];
        let value = after.trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        let at = start + sep + 1 + (after.len() - after.trim_start().len());
        defs.vars.entry(key.to_string()).or_default().push(Literal {
            file: file.to_path_buf(),
            place: Place::Text { start: at },
            text: value.to_string(),
        });
    }
}

// ---- Version catalogs ------------------------------------------------------------------

fn scan_catalog(
    file: &Path,
    catalog: &str,
    text: &str,
    defs: &mut Defs,
    found: &mut Vec<(String, PathBuf, Source)>,
) -> Result<(), AdapterError> {
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| AdapterError::Parse {
            what: file.display().to_string(),
            message: e.to_string(),
        })?;
    let lit = |keys: Vec<&str>, value: &str, start: usize, len: usize| Literal {
        file: file.to_path_buf(),
        place: Place::Toml {
            keys: keys.into_iter().map(String::from).collect(),
            value: value.to_string(),
            start,
        },
        text: value[start..start + len].to_string(),
    };
    if let Some(versions) = doc.get("versions").and_then(Item::as_table_like) {
        for (key, item) in versions.iter() {
            if let Some((which, v)) = rich_toml(item) {
                let keys = [vec!["versions", key], which.into_iter().collect()].concat();
                defs.catalog.insert(
                    (catalog.to_string(), catalog_key(key)),
                    lit(keys, v, 0, v.len()),
                );
            }
        }
    }
    let Some(libraries) = doc.get("libraries").and_then(Item::as_table_like) else {
        return Ok(());
    };
    for (alias, item) in libraries.iter() {
        if let Some(s) = item.as_str() {
            let Some(c) = parse_coord(s) else { continue };
            let source = match c.version {
                Some((a, b)) => Source::Literal(lit(vec!["libraries", alias], s, a, b - a)),
                None => Source::None,
            };
            found.push((c.module, file.to_path_buf(), source));
            continue;
        }
        let Some(t) = item.as_table_like() else {
            continue;
        };
        let module = match (
            t.get("module").and_then(Item::as_str),
            str_of(t, "group"),
            str_of(t, "name"),
        ) {
            (Some(m), _, _) => m.to_string(),
            (None, Some(g), Some(n)) => format!("{g}:{n}"),
            _ => continue,
        };
        let source = match t.get("version") {
            None => Source::None,
            Some(v) => match v.as_table_like().and_then(|v| str_of(v, "ref")) {
                Some(r) => Source::Ref {
                    expr: format!("version.ref = \"{r}\""),
                    var: VarRef::Catalog(catalog.to_string(), r.to_string()),
                },
                None => match rich_toml(v) {
                    Some((which, s)) => {
                        let keys = [
                            vec!["libraries", alias, "version"],
                            which.into_iter().collect(),
                        ]
                        .concat();
                        Source::Literal(lit(keys, s, 0, s.len()))
                    }
                    None => Source::Computed(v.to_string().trim().to_string()),
                },
            },
        };
        found.push((module, file.to_path_buf(), source));
    }
    Ok(())
}

fn str_of<'t>(t: &'t dyn TableLike, key: &str) -> Option<&'t str> {
    t.get(key).and_then(Item::as_str)
}

/// A catalog version: a string, or the `strictly` / `require` / `prefer`
/// entry of a rich version table (the key, if any, and the string).
fn rich_toml(item: &Item) -> Option<(Option<&'static str>, &str)> {
    if let Some(s) = item.as_str() {
        return Some((None, s));
    }
    let t = item.as_table_like()?;
    ["strictly", "require", "prefer"]
        .into_iter()
        .find_map(|k| Some((Some(k), str_of(t, k)?)))
}

// ---- Coordinates ---------------------------------------------------------------------------

/// A parsed `group:artifact[:version[:classifier]][@ext]`.
struct Coord {
    module: String,
    /// Byte range of the version in the parsed text.
    version: Option<(usize, usize)>,
}

fn parse_coord(text: &str) -> Option<Coord> {
    let main = match text.rsplit_once('@') {
        Some((main, ext)) if !ext.is_empty() && ext.chars().all(|c| c.is_ascii_alphanumeric()) => {
            main
        }
        Some(_) => return None,
        None => text,
    };
    let parts: Vec<&str> = main.split(':').collect();
    let (group, artifact) = (parts[0], *parts.get(1)?);
    let name_char = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    let valid = parts.len() <= 4
        && group.starts_with(|c: char| c.is_ascii_alphabetic())
        && group.chars().all(name_char)
        && artifact.starts_with(|c: char| c.is_ascii_alphanumeric())
        && artifact.chars().all(name_char)
        && (parts.len() > 2 || group.contains('.'))
        && parts[2..]
            .iter()
            .all(|p| !p.contains(|c: char| c.is_whitespace() || c == '/'));
    if !valid {
        return None;
    }
    let version = parts.get(2).filter(|v| !v.is_empty()).map(|v| {
        let start = group.len() + artifact.len() + 2;
        (start, start + v.len())
    });
    Some(Coord {
        module: format!("{group}:{artifact}"),
        version,
    })
}

// ---- Build scripts ---------------------------------------------------------------------------

#[derive(Debug)]
enum Tok {
    Ident(String),
    Str(Str),
    Punct(u8),
    Other,
}

#[derive(Debug)]
struct Token {
    tok: Tok,
    start: usize,
    end: usize,
}

/// A single-line string literal without escapes. `text` has each
/// interpolation replaced by [`HOLE`] (`exprs` holds them in order);
/// `offsets[i]` is the file offset of byte `i` of `text`.
#[derive(Debug)]
struct Str {
    text: String,
    offsets: Vec<usize>,
    exprs: Vec<String>,
    /// File offset just after the opening quote.
    content: usize,
}

impl Str {
    /// Byte `i` of `text` as a file offset (`content` for the empty string).
    fn offset(&self, i: usize) -> usize {
        self.offsets.get(i).copied().unwrap_or(self.content)
    }

    /// The whole string used as a version (`strictly("1.0")`, `version: "$v"`).
    fn source(&self, file: &Path, src: &str, tok: &Token) -> Source {
        version_source(self, file, src, tok, 0, self.text.len())
    }
}

/// The version given by `s.text[a..b]`.
fn version_source(s: &Str, file: &Path, src: &str, tok: &Token, a: usize, b: usize) -> Source {
    let text = &s.text[a..b];
    if text == HOLE.to_string() {
        let expr = s.exprs[s.text[..a].matches(HOLE).count()].clone();
        return match var_ref(&expr) {
            Some(var) => Source::Ref { expr, var },
            None => Source::Computed(expr),
        };
    }
    if text.contains(HOLE) {
        return Source::Computed(src[tok.start..tok.end].to_string());
    }
    Source::Literal(Literal {
        file: file.to_path_buf(),
        place: Place::Text { start: s.offset(a) },
        text: text.to_string(),
    })
}

fn scan_script(
    file: &Path,
    src: &str,
    kotlin: bool,
    defs: &mut Defs,
    found: &mut Vec<(String, PathBuf, Source)>,
) {
    let toks = lex(src, kotlin);
    let mut map_end = 0;
    for (i, tok) in toks.iter().enumerate() {
        match &tok.tok {
            Tok::Str(s) => {
                if s.exprs.is_empty()
                    && let Some(name) = def_name(&toks, i)
                {
                    defs.vars.entry(name).or_default().push(Literal {
                        file: file.to_path_buf(),
                        place: Place::Text { start: s.content },
                        text: s.text.clone(),
                    });
                }
                if let Some(c) = parse_coord(&s.text) {
                    let source = match c.version {
                        Some((a, b)) => version_source(s, file, src, tok, a, b),
                        None => rich_version(&toks, i + 1, file, src).unwrap_or(Source::None),
                    };
                    found.push((c.module, file.to_path_buf(), source));
                }
            }
            Tok::Ident(key) if i >= map_end && RESERVED.contains(&key.as_str()) => {
                if let Some((entries, end)) = map_entries(&toks, i, src) {
                    map_end = end;
                    if let Some(found_decl) = map_declaration(&entries, &toks, end, file, src) {
                        found.push(found_decl);
                    }
                }
            }
            _ => {}
        }
    }
}

fn punct(toks: &[Token], i: usize) -> Option<u8> {
    match toks.get(i)?.tok {
        Tok::Punct(c) => Some(c),
        _ => None,
    }
}

fn ident(toks: &[Token], i: usize) -> Option<&str> {
    match &toks.get(i)?.tok {
        Tok::Ident(s) => Some(s),
        _ => None,
    }
}

fn plain_str(toks: &[Token], i: usize) -> Option<&str> {
    match &toks.get(i)?.tok {
        Tok::Str(s) if s.exprs.is_empty() => Some(&s.text),
        _ => None,
    }
}

/// The variable a string literal at `i` defines: `x = ".."`, `val x: String
/// = ".."`, `extra["x"] = ".."`, `x: '..'` (Groovy maps), `set("x", "..")`,
/// `val x by extra("..")`.
fn def_name(toks: &[Token], i: usize) -> Option<String> {
    let back = |n: usize| i.checked_sub(n);
    let p = |n: usize| back(n).and_then(|j| punct(toks, j));
    let id = |n: usize| back(n).and_then(|j| ident(toks, j));
    let st = |n: usize| back(n).and_then(|j| plain_str(toks, j));
    // `name` or `name: Type` ending at `n` tokens back.
    let declared = |n: usize| match (id(n), p(n + 1), id(n + 2)) {
        (Some(_), Some(b':'), Some(name)) => Some(name),
        (name, ..) => name,
    };
    let name = match p(1)? {
        b'=' => match p(2) {
            Some(b']') if p(4) == Some(b'[') => st(3),
            Some(_) => None,
            None => declared(2),
        },
        b':' if matches!(p(3), Some(b'[' | b',' | b'(')) => id(2).or(st(2)),
        b',' if p(3) == Some(b'(') && id(4) == Some("set") => st(2),
        b'(' if id(2) == Some("extra") && id(3) == Some("by") => declared(4),
        _ => None,
    }?;
    (!name.is_empty() && !RESERVED.contains(&name)).then(|| name.to_string())
}

/// Index of the token closing the bracket opened at `open`.
fn closing(toks: &[Token], open: usize) -> Option<usize> {
    let (o, c) = match punct(toks, open)? {
        b'{' => (b'{', b'}'),
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        _ => return None,
    };
    let mut depth = 0;
    for (j, t) in toks.iter().enumerate().skip(open) {
        match t.tok {
            Tok::Punct(x) if x == o => depth += 1,
            Tok::Punct(x) if x == c => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}

/// A `{ version { strictly(..) / require(..) / prefer(..) } }` block right
/// after a version-less coordinate ending before token `j`.
fn rich_version(toks: &[Token], j: usize, file: &Path, src: &str) -> Option<Source> {
    let open = if punct(toks, j) == Some(b')') {
        j + 1
    } else {
        j
    };
    let close = closing(toks, open).filter(|_| punct(toks, open) == Some(b'{'))?;
    let v = (open + 1..close)
        .find(|&m| ident(toks, m) == Some("version") && punct(toks, m + 1) == Some(b'{'))?;
    let end = closing(toks, v + 1)?;
    ["strictly", "require", "prefer"]
        .into_iter()
        .find_map(|which| {
            (v + 2..end).find_map(|m| {
                if ident(toks, m) != Some(which) {
                    return None;
                }
                let at = if punct(toks, m + 1) == Some(b'(') {
                    m + 2
                } else {
                    m + 1
                };
                match &toks.get(at)?.tok {
                    Tok::Str(s) => Some(s.source(file, src, &toks[at])),
                    _ => None,
                }
            })
        })
}

/// One map-notation value.
enum MapValue<'t> {
    Str(&'t Str, &'t Token),
    Expr(String),
}

/// `key: value, key: value, ...` (Kotlin `key = value`) starting at `i`.
/// Returns the entries and the index of the first token after them.
fn map_entries<'t>(
    toks: &'t [Token],
    i: usize,
    src: &str,
) -> Option<(HashMap<&'t str, MapValue<'t>>, usize)> {
    if i > 0 && punct(toks, i - 1) == Some(b'.') {
        return None;
    }
    let mut entries = HashMap::new();
    let mut k = i;
    loop {
        let key = ident(toks, k)?;
        if !matches!(punct(toks, k + 1), Some(b':' | b'=')) || punct(toks, k + 2) == Some(b'=') {
            break;
        }
        let (value, next) = match toks.get(k + 2).map(|t| &t.tok) {
            Some(Tok::Str(s)) => (MapValue::Str(s, &toks[k + 2]), k + 3),
            Some(Tok::Ident(_)) => {
                let end = expr_end(toks, k + 2);
                (
                    MapValue::Expr(src[toks[k + 2].start..toks[end - 1].end].to_string()),
                    end,
                )
            }
            _ => break,
        };
        entries.insert(key, value);
        k = next;
        if punct(toks, k) != Some(b',') || ident(toks, k + 1).is_none() {
            break;
        }
        k += 1;
    }
    (!entries.is_empty()).then_some((entries, k))
}

/// End (exclusive) of a property-path expression starting with an
/// identifier at `i`: `a.b`, `x["k"]`, `f("k")`, `x.get()`, `x!!`.
fn expr_end(toks: &[Token], i: usize) -> usize {
    let mut k = i + 1;
    loop {
        k += match (
            punct(toks, k),
            toks.get(k + 1).map(|t| &t.tok),
            punct(toks, k + 2),
        ) {
            (Some(b'.'), Some(Tok::Ident(_)), _) => 2,
            (Some(b'['), Some(Tok::Str(_)), Some(b']'))
            | (Some(b'('), Some(Tok::Str(_)), Some(b')')) => 3,
            (Some(b'('), Some(Tok::Punct(b')')), _) | (Some(b'!'), Some(Tok::Punct(b'!')), _) => 2,
            _ => return k,
        };
    }
}

fn map_declaration(
    entries: &HashMap<&str, MapValue>,
    toks: &[Token],
    end: usize,
    file: &Path,
    src: &str,
) -> Option<(String, PathBuf, Source)> {
    let plain = |key: &str| match entries.get(key)? {
        MapValue::Str(s, _) if s.exprs.is_empty() => Some(s.text.as_str()),
        _ => None,
    };
    let module = format!("{}:{}", plain("group")?, plain("name")?);
    let source = match entries.get("version") {
        Some(MapValue::Str(s, tok)) => s.source(file, src, tok),
        Some(MapValue::Expr(expr)) => match var_ref(expr) {
            Some(var) => Source::Ref {
                expr: expr.clone(),
                var,
            },
            None => Source::Computed(expr.clone()),
        },
        None => rich_version(toks, end, file, src).unwrap_or(Source::None),
    };
    Some((module, file.to_path_buf(), source))
}

// ---- Lexer -----------------------------------------------------------------------------------

/// Tokens of a Groovy/Kotlin script, without comments and whitespace.
/// Triple-quoted and escaped strings become `Other`.
fn lex(src: &str, kotlin: bool) -> Vec<Token> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        let c = b[i];
        let tok = match c {
            _ if c.is_ascii_whitespace() => {
                i += 1;
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i = memchr(b, i, b'\n').unwrap_or(b.len());
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
                continue;
            }
            b'"' | b'\'' => {
                let (tok, end) = lex_str(src, i, kotlin);
                i = end;
                tok
            }
            _ if c == b'_' || c.is_ascii_alphabetic() => {
                while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                Tok::Ident(src[start..i].to_string())
            }
            _ if c.is_ascii_digit() => {
                while i < b.len() && (b[i] == b'_' || b[i] == b'.' || b[i].is_ascii_alphanumeric())
                {
                    i += 1;
                }
                Tok::Other
            }
            _ if c.is_ascii_punctuation() => {
                i += 1;
                Tok::Punct(c)
            }
            _ => {
                i += 1;
                Tok::Other
            }
        };
        toks.push(Token { tok, start, end: i });
    }
    toks
}

fn memchr(b: &[u8], from: usize, c: u8) -> Option<usize> {
    b[from..].iter().position(|&x| x == c).map(|p| from + p)
}

/// The string literal starting at quote `i`, and the offset after it.
fn lex_str(src: &str, i: usize, kotlin: bool) -> (Tok, usize) {
    let b = src.as_bytes();
    let q = b[i];
    if b.get(i + 1) == Some(&q) && b.get(i + 2) == Some(&q) {
        let triple = if q == b'"' { "\"\"\"" } else { "'''" };
        let end = src[i + 3..].find(triple).map_or(b.len(), |e| i + 3 + e + 3);
        return (Tok::Other, end);
    }
    let mut text = Vec::new();
    let mut offsets = Vec::new();
    let mut exprs = Vec::new();
    let mut escaped = false;
    let mut j = i + 1;
    loop {
        match b.get(j) {
            None | Some(b'\n') => return (Tok::Other, j),
            Some(&c) if c == q => break,
            Some(b'\\') => {
                escaped = true;
                j += 2;
            }
            Some(b'$') if q == b'"' && b.get(j + 1) == Some(&b'{') => {
                let Some(close) = close_interpolation(b, j + 2) else {
                    return (Tok::Other, memchr(b, j, b'\n').unwrap_or(b.len()));
                };
                exprs.push(src[j + 2..close].trim().to_string());
                text.push(HOLE as u8);
                offsets.push(j);
                j = close + 1;
            }
            Some(b'$')
                if q == b'"'
                    && b.get(j + 1)
                        .is_some_and(|c| *c == b'_' || c.is_ascii_alphabetic()) =>
            {
                let mut k = j + 1;
                loop {
                    while k < b.len() && (b[k] == b'_' || b[k].is_ascii_alphanumeric()) {
                        k += 1;
                    }
                    // Groovy reads `$a.b` as a property path, Kotlin as `$a` + ".b".
                    let more = !kotlin
                        && b.get(k) == Some(&b'.')
                        && b.get(k + 1)
                            .is_some_and(|c| *c == b'_' || c.is_ascii_alphabetic());
                    if !more {
                        break;
                    }
                    k += 1;
                }
                exprs.push(src[j + 1..k].to_string());
                text.push(HOLE as u8);
                offsets.push(j);
                j = k;
            }
            Some(&c) => {
                text.push(c);
                offsets.push(j);
                j += 1;
            }
        }
    }
    let end = j + 1;
    if escaped {
        return (Tok::Other, end);
    }
    let text = String::from_utf8(text).expect("copied from a str, split at ASCII");
    (
        Tok::Str(Str {
            text,
            offsets,
            exprs,
            content: i + 1,
        }),
        end,
    )
}

/// Offset of the `}` closing a `${` whose body starts at `j`.
fn close_interpolation(b: &[u8], mut j: usize) -> Option<usize> {
    let mut depth = 1;
    while let Some(&c) = b.get(j) {
        match c {
            b'\n' => return None,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            b'"' | b'\'' => {
                j = memchr(b, j + 1, c)?;
            }
            _ => {}
        }
        j += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dotted numeric order, enough for the tests.
    fn cmp(a: &str, b: &str) -> Ordering {
        let parts =
            |s: &str| -> Vec<u64> { s.split(['.', '-']).filter_map(|p| p.parse().ok()).collect() };
        parts(a).cmp(&parts(b))
    }

    fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn read(dir: &tempfile::TempDir, name: &str) -> String {
        std::fs::read_to_string(dir.path().join(name)).unwrap()
    }

    /// Versions of every declaration of `module` (`-` = not editable).
    fn versions(decls: &Declarations, module: &str) -> Vec<String> {
        decls
            .get(module)
            .iter()
            .map(|d| d.version.clone().unwrap_or("-".into()))
            .collect()
    }

    fn modules(decls: &Declarations) -> Vec<&str> {
        decls.by_module.keys().map(String::as_str).collect()
    }

    fn not_editable(err: AdapterError) -> String {
        match err {
            AdapterError::ManifestNotEditable(m) => m,
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Bump every `(module, to, old, new)` in turn and check that `file`
    /// equals `original` with each `old` (unique) replaced by `new`.
    fn check_bumps(
        dir: &tempfile::TempDir,
        file: &str,
        original: &str,
        cases: &[(&str, &str, &str, &str)],
    ) {
        let mut expected = original.to_string();
        for (module, to, old, new) in cases {
            bump(dir.path(), module, to, &cmp).unwrap();
            assert_eq!(expected.matches(old).count(), 1, "{old}");
            expected = expected.replace(old, new);
            assert_eq!(read(dir, file), expected, "{module}");
        }
    }

    const GROOVY: &str = r#"buildscript {
    ext.kotlin_version = '1.9.0'
    dependencies {
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
    }
}
def jackson = "2.15.0"
ext {
    guavaVersion = '31.0-jre'
    libs = [okio: 'com.squareup.okio:okio:3.2.0', snakeVersion: '1.33']
}
ext.set("nettyVersion", "4.1.90.Final")
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.12.0'
    implementation "com.fasterxml.jackson.core:jackson-databind:${jackson}"
    implementation "com.fasterxml.jackson.core:jackson-annotations:$jackson"
    implementation "com.google.guava:guava:$guavaVersion"
    implementation "io.netty:netty-all:${rootProject.ext.nettyVersion}"
    implementation "org.yaml:snakeyaml:$libs.snakeVersion"
    implementation libs.okio
    runtimeOnly group: 'org.postgresql', name: 'postgresql', version: '42.5.0'
    api(group: "org.slf4j", name: "slf4j-api", version: slf4jVersion)
    implementation platform('org.springframework.boot:spring-boot-dependencies:3.1.0')
    implementation 'org.springframework:spring-core'
    testImplementation 'junit:junit:4.12@jar'
    implementation "org.bouncycastle:bcprov-jdk18on:1.70:sources"
    implementation 'com.example:strict:1.0!!'
    implementation 'com.example:ranged:[1.0,2.0)'
    implementation 'com.example:dynamic:1.+'
    implementation 'com.example:latest:latest.release'
    implementation "com.example:computed:1.${minor}"
    implementation "com.example:unknown:$nowhere"
    implementation('com.example:rich') { version { strictly '2.0' } }
    // implementation 'com.example:commented:1.0'
    /* implementation 'com.example:block:1.0'
       implementation 'com.example:block2:1.0' */
    constraints {
        implementation('com.example:constrained:3.0') { because 'x' }
    }
}
"#;

    const PROPS: &str = "# slf4jVersion=0.0.1\nslf4jVersion = 2.0.7 \norg.gradle.jvmargs=-Xmx2g\n";

    #[test]
    fn groovy_forms() {
        let dir = project(&[("build.gradle", GROOVY), ("gradle.properties", PROPS)]);
        let d = scan(dir.path()).unwrap();
        let expect = [
            ("org.jetbrains.kotlin:kotlin-gradle-plugin", "1.9.0"),
            ("org.apache.commons:commons-lang3", "3.12.0"),
            ("com.fasterxml.jackson.core:jackson-databind", "2.15.0"),
            ("com.fasterxml.jackson.core:jackson-annotations", "2.15.0"),
            ("com.google.guava:guava", "31.0-jre"),
            ("io.netty:netty-all", "4.1.90.Final"),
            ("org.yaml:snakeyaml", "1.33"),
            ("com.squareup.okio:okio", "3.2.0"),
            ("org.postgresql:postgresql", "42.5.0"),
            ("org.slf4j:slf4j-api", "2.0.7"),
            ("org.springframework.boot:spring-boot-dependencies", "3.1.0"),
            ("org.springframework:spring-core", "-"),
            ("junit:junit", "4.12"),
            ("org.bouncycastle:bcprov-jdk18on", "1.70"),
            ("com.example:strict", "1.0"),
            ("com.example:ranged", "-"),
            ("com.example:dynamic", "-"),
            ("com.example:latest", "-"),
            ("com.example:computed", "-"),
            ("com.example:unknown", "-"),
            ("com.example:rich", "2.0"),
            ("com.example:constrained", "3.0"),
        ];
        for (module, version) in expect {
            assert_eq!(versions(&d, module), [version], "{module}");
        }
        assert_eq!(d.by_module.len(), expect.len(), "{:?}", modules(&d));
        assert_eq!(
            d.get("org.slf4j:slf4j-api")[0].file,
            Path::new("build.gradle")
        );
        assert_eq!(
            d.shared_ref_modules("com.fasterxml.jackson.core:jackson-databind"),
            ["com.fasterxml.jackson.core:jackson-annotations"]
        );
        assert!(d.shared_ref_modules("com.google.guava:guava").is_empty());
    }

    #[test]
    fn groovy_bumps_rewrite_only_the_literal() {
        let dir = project(&[("build.gradle", GROOVY), ("gradle.properties", PROPS)]);
        check_bumps(
            &dir,
            "build.gradle",
            GROOVY,
            &[
                (
                    "org.apache.commons:commons-lang3",
                    "3.14.0",
                    "lang3:3.12.0'",
                    "lang3:3.14.0'",
                ),
                (
                    "com.fasterxml.jackson.core:jackson-databind",
                    "2.15.3",
                    "def jackson = \"2.15.0\"",
                    "def jackson = \"2.15.3\"",
                ),
                (
                    "com.google.guava:guava",
                    "32.0-jre",
                    "'31.0-jre'",
                    "'32.0-jre'",
                ),
                (
                    "io.netty:netty-all",
                    "4.1.100.Final",
                    "\"4.1.90.Final\")",
                    "\"4.1.100.Final\")",
                ),
                (
                    "org.yaml:snakeyaml",
                    "2.0",
                    "snakeVersion: '1.33'",
                    "snakeVersion: '2.0'",
                ),
                (
                    "com.squareup.okio:okio",
                    "3.4.0",
                    "okio:3.2.0'",
                    "okio:3.4.0'",
                ),
                (
                    "org.postgresql:postgresql",
                    "42.7.2",
                    "version: '42.5.0'",
                    "version: '42.7.2'",
                ),
                (
                    "org.jetbrains.kotlin:kotlin-gradle-plugin",
                    "1.9.10",
                    "'1.9.0'",
                    "'1.9.10'",
                ),
                (
                    "org.springframework.boot:spring-boot-dependencies",
                    "3.1.5",
                    ":3.1.0'",
                    ":3.1.5'",
                ),
                ("junit:junit", "4.13.2", "4.12@jar", "4.13.2@jar"),
                (
                    "org.bouncycastle:bcprov-jdk18on",
                    "1.78",
                    "1.70:sources",
                    "1.78:sources",
                ),
                ("com.example:strict", "1.1", "strict:1.0!!", "strict:1.1!!"),
                (
                    "com.example:rich",
                    "2.1",
                    "strictly '2.0'",
                    "strictly '2.1'",
                ),
                (
                    "com.example:constrained",
                    "3.1",
                    "constrained:3.0'",
                    "constrained:3.1'",
                ),
            ],
        );
        assert_eq!(read(&dir, "gradle.properties"), PROPS);
        let script = read(&dir, "build.gradle");
        bump(dir.path(), "org.slf4j:slf4j-api", "2.0.9", &cmp).unwrap();
        assert_eq!(
            read(&dir, "gradle.properties"),
            PROPS.replace("= 2.0.7 ", "= 2.0.9 ")
        );
        assert_eq!(read(&dir, "build.gradle"), script);
        let d = scan(dir.path()).unwrap();
        assert_eq!(
            versions(&d, "com.fasterxml.jackson.core:jackson-annotations"),
            ["2.15.3"]
        );
    }

    #[test]
    fn not_editable_messages() {
        let dir = project(&[("build.gradle", GROOVY), ("gradle.properties", PROPS)]);
        let err = |m: &str| not_editable(bump(dir.path(), m, "9.9", &cmp).unwrap_err());
        assert_eq!(
            err("org.springframework:spring-core"),
            "org.springframework:spring-core is declared without a version in build.gradle (managed by a platform or plugin)"
        );
        assert_eq!(
            err("com.example:ranged"),
            "com.example:ranged is declared in build.gradle with version `[1.0,2.0)`, which mendr cannot rewrite (a range, dynamic or computed version)"
        );
        assert!(err("com.example:dynamic").contains("`1.+`"));
        assert!(err("com.example:latest").contains("`latest.release`"));
        assert!(err("com.example:computed").contains("`\"com.example:computed:1.${minor}\"`"));
        assert!(err("com.example:unknown").contains("`nowhere`"));
        assert_eq!(
            err("com.example:nope"),
            "no declaration of com.example:nope found"
        );
        let low = not_editable(bump(dir.path(), "junit:junit", "4.12", &cmp).unwrap_err());
        assert_eq!(
            low,
            "no declaration of junit:junit has a version lower than 4.12"
        );
        assert_eq!(read(&dir, "build.gradle"), GROOVY);
    }

    const KOTLIN: &str = r#"val jacksonVersion = "2.15.0"
val guavaVersion: String by project
val nettyVersion by extra("4.1.90.Final")
extra["okioVersion"] = "3.2.0"
val slf4j: String = "2.0.7"
version = "0.1.0"
dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.google.guava:guava:${guavaVersion}")
    implementation("io.netty:netty-all:$nettyVersion")
    implementation("com.squareup.okio:okio:${rootProject.extra["okioVersion"]}")
    implementation("org.slf4j:slf4j-api:${slf4j}")
    implementation(group = "org.postgresql", name = "postgresql", version = "42.5.0")
    implementation(group = "org.yaml", name = "snakeyaml", version = jacksonVersion)
    implementation("com.example:catalog:${libs.versions.shared.get()}")
    implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.1.0"))
    implementation("org.springframework:spring-core")
    implementation("com.example:own:$version")
    implementation("com.example:rich") {
        version {
            strictly("2.0")
            prefer("2.1")
        }
    }
    implementation("com.example:required") { version { require("[1.0,2.0)") } }
    implementation('c')
    implementation("com.example:strict:1.0!!")
    // implementation("com.example:commented:1.0")
    testImplementation(kotlin("test"))
}
"#;

    #[test]
    fn kotlin_forms() {
        let dir = project(&[
            ("build.gradle.kts", KOTLIN),
            ("gradle.properties", "guavaVersion=31.0-jre\n"),
            (
                "gradle/libs.versions.toml",
                "[versions]\nshared = \"1.0.0\"\n",
            ),
        ]);
        let d = scan(dir.path()).unwrap();
        let expect = [
            ("com.fasterxml.jackson.core:jackson-databind", "2.15.0"),
            ("com.google.guava:guava", "31.0-jre"),
            ("io.netty:netty-all", "4.1.90.Final"),
            ("com.squareup.okio:okio", "3.2.0"),
            ("org.slf4j:slf4j-api", "2.0.7"),
            ("org.postgresql:postgresql", "42.5.0"),
            ("org.yaml:snakeyaml", "2.15.0"),
            ("com.example:catalog", "1.0.0"),
            ("org.springframework.boot:spring-boot-dependencies", "3.1.0"),
            ("org.springframework:spring-core", "-"),
            ("com.example:own", "-"),
            ("com.example:rich", "2.0"),
            ("com.example:required", "-"),
            ("com.example:strict", "1.0"),
        ];
        for (module, version) in expect {
            assert_eq!(versions(&d, module), [version], "{module}");
        }
        assert_eq!(d.by_module.len(), expect.len(), "{:?}", modules(&d));
        assert_eq!(
            d.shared_ref_modules("org.yaml:snakeyaml"),
            ["com.fasterxml.jackson.core:jackson-databind"]
        );

        check_bumps(
            &dir,
            "build.gradle.kts",
            KOTLIN,
            &[
                (
                    "com.fasterxml.jackson.core:jackson-databind",
                    "2.15.3",
                    "jacksonVersion = \"2.15.0\"",
                    "jacksonVersion = \"2.15.3\"",
                ),
                (
                    "io.netty:netty-all",
                    "4.1.100.Final",
                    "(\"4.1.90.Final\")",
                    "(\"4.1.100.Final\")",
                ),
                (
                    "com.squareup.okio:okio",
                    "3.4.0",
                    "] = \"3.2.0\"",
                    "] = \"3.4.0\"",
                ),
                (
                    "org.slf4j:slf4j-api",
                    "2.0.9",
                    "String = \"2.0.7\"",
                    "String = \"2.0.9\"",
                ),
                (
                    "org.postgresql:postgresql",
                    "42.7.2",
                    "\"42.5.0\"",
                    "\"42.7.2\"",
                ),
                (
                    "org.springframework.boot:spring-boot-dependencies",
                    "3.1.5",
                    ":3.1.0\"",
                    ":3.1.5\"",
                ),
                (
                    "com.example:rich",
                    "2.0.1",
                    "strictly(\"2.0\")",
                    "strictly(\"2.0.1\")",
                ),
                ("com.example:strict", "1.1", "1.0!!", "1.1!!"),
            ],
        );
        let script = read(&dir, "build.gradle.kts");
        bump(dir.path(), "com.google.guava:guava", "32.0-jre", &cmp).unwrap();
        assert_eq!(read(&dir, "gradle.properties"), "guavaVersion=32.0-jre\n");
        bump(dir.path(), "com.example:catalog", "1.0.1", &cmp).unwrap();
        assert_eq!(
            read(&dir, "gradle/libs.versions.toml"),
            "[versions]\nshared = \"1.0.1\"\n"
        );
        assert_eq!(read(&dir, "build.gradle.kts"), script);
        let err = not_editable(bump(dir.path(), "com.example:own", "1.0", &cmp).unwrap_err());
        assert!(err.contains("`version`"), "{err}");
    }

    const CATALOG: &str = r#"[versions]
# netty = "0.0.1"
jackson = "2.15.0"
netty = { strictly = "4.1.90.Final" }
okio = { require = "3.2.0" }
shared = "1.0.0" # used by scripts too

[libraries]
lang3 = "org.apache.commons:commons-lang3:3.12.0"
managed = "org.springframework:spring-core"
databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
annotations = { module = "com.fasterxml.jackson.core:jackson-annotations", version.ref = "jackson" }
netty = { group = "io.netty", name = "netty-all", version.ref = "netty" }
okio = { module = "com.squareup.okio:okio", version = { ref = "okio" } }
guava = { module = "com.google.guava:guava", version = "31.0-jre" }
slf4j = { module = "org.slf4j:slf4j-api", version = { strictly = "2.0.7", prefer = "2.0.9" } }
snake = { module = "org.yaml:snakeyaml", version = { prefer = "1.33" } }
ranged = { module = "com.example:ranged", version = "[1.0,2.0)" }
nover = { module = "com.example:nover" }
other = { module = "com.example:other", version.ref = "shared" }

[libraries.tablelib]
module = "com.example:tablelib"
version = "0.9"

[plugins]
spring = { id = "org.springframework.boot", version = "3.1.0" }
"#;

    #[test]
    fn catalogs() {
        let script = "dependencies {\n    implementation(\"com.example:script:${libs.versions.shared.get()}\")\n}\n";
        let dir = project(&[
            ("gradle/libs.versions.toml", CATALOG),
            ("build.gradle.kts", script),
        ]);
        let d = scan(dir.path()).unwrap();
        let expect = [
            ("org.apache.commons:commons-lang3", "3.12.0"),
            ("org.springframework:spring-core", "-"),
            ("com.fasterxml.jackson.core:jackson-databind", "2.15.0"),
            ("com.fasterxml.jackson.core:jackson-annotations", "2.15.0"),
            ("io.netty:netty-all", "4.1.90.Final"),
            ("com.squareup.okio:okio", "3.2.0"),
            ("com.google.guava:guava", "31.0-jre"),
            ("org.slf4j:slf4j-api", "2.0.7"),
            ("org.yaml:snakeyaml", "1.33"),
            ("com.example:ranged", "-"),
            ("com.example:nover", "-"),
            ("com.example:other", "1.0.0"),
            ("com.example:tablelib", "0.9"),
            ("com.example:script", "1.0.0"),
        ];
        for (module, version) in expect {
            assert_eq!(versions(&d, module), [version], "{module}");
        }
        assert_eq!(d.by_module.len(), expect.len(), "{:?}", modules(&d));
        assert_eq!(
            d.get("com.example:other")[0].file,
            Path::new("gradle/libs.versions.toml")
        );
        assert_eq!(
            d.shared_ref_modules("com.fasterxml.jackson.core:jackson-databind"),
            ["com.fasterxml.jackson.core:jackson-annotations"]
        );
        assert_eq!(
            d.shared_ref_modules("com.example:script"),
            ["com.example:other"]
        );
        assert!(d.shared_ref_modules("com.google.guava:guava").is_empty());

        check_bumps(
            &dir,
            "gradle/libs.versions.toml",
            CATALOG,
            &[
                (
                    "org.apache.commons:commons-lang3",
                    "3.14.0",
                    ":3.12.0\"",
                    ":3.14.0\"",
                ),
                (
                    "com.fasterxml.jackson.core:jackson-databind",
                    "2.15.3",
                    "jackson = \"2.15.0\"",
                    "jackson = \"2.15.3\"",
                ),
                (
                    "io.netty:netty-all",
                    "4.1.100.Final",
                    "\"4.1.90.Final\"",
                    "\"4.1.100.Final\"",
                ),
                ("com.squareup.okio:okio", "3.4.0", "\"3.2.0\"", "\"3.4.0\""),
                (
                    "com.google.guava:guava",
                    "32.0-jre",
                    "\"31.0-jre\"",
                    "\"32.0-jre\"",
                ),
                ("org.slf4j:slf4j-api", "2.0.8", "\"2.0.7\"", "\"2.0.8\""),
                ("org.yaml:snakeyaml", "2.0", "\"1.33\"", "\"2.0\""),
                ("com.example:tablelib", "1.0", "\"0.9\"", "\"1.0\""),
                ("com.example:script", "1.0.1", "\"1.0.0\"", "\"1.0.1\""),
            ],
        );
        assert_eq!(read(&dir, "build.gradle.kts"), script);
        let d = scan(dir.path()).unwrap();
        assert_eq!(
            versions(&d, "com.fasterxml.jackson.core:jackson-annotations"),
            ["2.15.3"]
        );
        assert_eq!(versions(&d, "com.example:other"), ["1.0.1"]);
        let err = not_editable(bump(dir.path(), "com.example:nover", "1.0", &cmp).unwrap_err())
            .replace('\\', "/");
        assert!(
            err.contains("without a version in gradle/libs.versions.toml"),
            "{err}"
        );
        let err = not_editable(bump(dir.path(), "com.example:ranged", "3.0", &cmp).unwrap_err());
        assert!(err.contains("`[1.0,2.0)`"), "{err}");
    }

    #[test]
    fn bumps_only_lower_versions() {
        let dir = project(&[
            ("settings.gradle", "include 'app', 'lib'\n"),
            (
                "app/build.gradle",
                "dependencies { implementation 'g.x:a:1.0' }\n",
            ),
            (
                "lib/build.gradle",
                "dependencies { implementation 'g.x:a:2.0' }\n",
            ),
            (
                "lib/extra.gradle",
                "dependencies { implementation 'g.x:a:1.2' }",
            ),
        ]);
        let d = scan(dir.path()).unwrap();
        assert_eq!(d.version("g.x:a", &cmp), Some("1.0"));
        assert_eq!(d.version("g.x:b", &cmp), None);
        assert!(d.contains("g.x:a"));
        bump(dir.path(), "g.x:a", "1.5", &cmp).unwrap();
        assert_eq!(
            read(&dir, "app/build.gradle"),
            "dependencies { implementation 'g.x:a:1.5' }\n"
        );
        assert_eq!(
            read(&dir, "lib/build.gradle"),
            "dependencies { implementation 'g.x:a:2.0' }\n"
        );
        assert_eq!(
            read(&dir, "lib/extra.gradle"),
            "dependencies { implementation 'g.x:a:1.5' }"
        );
    }

    #[test]
    fn variables_prefer_the_same_file() {
        let dir = project(&[
            ("build.gradle", "ext.v = '1.0'\n"),
            (
                "app/build.gradle",
                "def v = '2.0'\ndependencies { implementation \"g.x:a:$v\" }\n",
            ),
            (
                "lib/build.gradle",
                "dependencies { implementation \"g.x:b:$v\" }\n",
            ),
        ]);
        let d = scan(dir.path()).unwrap();
        assert_eq!(versions(&d, "g.x:a"), ["2.0"]);
        assert_eq!(versions(&d, "g.x:b"), ["1.0"]);
        assert!(d.shared_ref_modules("g.x:a").is_empty());
    }

    #[test]
    fn walks_build_files_only() {
        let decl = |m: &str| format!("dependencies {{ implementation '{m}:1.0' }}\n");
        let files = [
            ("build.gradle", "g.x:root"),
            ("app/build.gradle.kts", "g.x:app"),
            ("gradle/deps.gradle", "g.x:applied"),
            ("buildSrc/src/main/groovy/conv.gradle", "g.x:convention"),
            (
                "build-logic/conv/src/main/kotlin/conv.gradle.kts",
                "g.x:logic",
            ),
            ("app/src/test/resources/fixture.gradle", "g.x:fixture"),
            ("app/build/tmp/x.gradle", "g.x:build-dir"),
            ("buildSrc/build/x.gradle", "g.x:buildsrc-build"),
            (".gradle/x.gradle", "g.x:dot-gradle"),
            ("node_modules/x/build.gradle", "g.x:node"),
            ("app/build.gradle.bak", "g.x:bak"),
        ];
        let texts: Vec<(&str, String)> = files.iter().map(|(f, m)| (*f, decl(m))).collect();
        let mut files: Vec<(&str, &str)> = texts.iter().map(|(f, t)| (*f, t.as_str())).collect();
        files.push((
            "other/libs.versions.toml",
            "[libraries]\nx = \"g.x:toml:1.0\"\n",
        ));
        let dir = project(&files);
        let d = scan(dir.path()).unwrap();
        assert_eq!(
            modules(&d),
            [
                "g.x:app",
                "g.x:applied",
                "g.x:convention",
                "g.x:logic",
                "g.x:root"
            ]
        );
    }

    #[test]
    fn strings_that_are_not_coordinates() {
        let text = r#"
tasks.register("x") { dependsOn(":app:assemble") }
val url = "https://repo.example.com:8080/maven"
val opt = "-Xlint:deprecation"
val title = "Implementation-Title: x"
val x = "UTF-8"
val esc = "g.x:escaped:1.0\n"
val raw = """g.x:raw:1.0"""
val two = "nodot:artifact"
val unterminated = "g.x:open:1.0
"#;
        let dir = project(&[("build.gradle.kts", text)]);
        assert!(modules(&scan(dir.path()).unwrap()).is_empty());
    }

    #[test]
    fn var_refs() {
        let name = |s: &str| Some(VarRef::Name(s.into()));
        assert_eq!(var_ref("x"), name("x"));
        assert_eq!(var_ref("rootProject.ext.x"), name("x"));
        assert_eq!(var_ref("rootProject.extra[\"x\"]"), name("x"));
        assert_eq!(var_ref("project.property('x') as String"), name("x"));
        assert_eq!(var_ref("Versions.jackson"), name("jackson"));
        assert_eq!(
            var_ref("libs.versions.jackson.core.get()"),
            Some(VarRef::Catalog("libs".into(), "jackson.core".into()))
        );
        assert_eq!(var_ref("a + b"), None);
        assert_eq!(var_ref("f(x)"), None);
    }
}
