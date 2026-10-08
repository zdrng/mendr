//! node-semver rules, which pnpm resolves ranges with (a focused port,
//! strict mode, without `includePrerelease`): version parsing and ordering,
//! and range matching with `^`, `~`, x-ranges (`1.x`, `*`), hyphen ranges
//! (`1 - 2`), `||` and the prerelease rule.
//!
//! The `node-semver` crate is not used: it disagrees with node-semver on
//! `<=1.2` / `<=1` and rejects the empty range. The unit tests below are a
//! matrix generated with the `semver` package itself.

use std::cmp::Ordering;

/// One prerelease identifier. Numeric identifiers sort before alphanumeric.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Num(u64),
    Alpha(String),
}

/// A parsed `MAJOR.MINOR.PATCH[-PRE][+BUILD]` version (build metadata is
/// dropped: it never affects ordering).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ver {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pre: Vec<Ident>,
}

impl Ver {
    fn new(major: u64, minor: u64, patch: u64, pre: Vec<Ident>) -> Self {
        Ver {
            major,
            minor,
            patch,
            pre,
        }
    }

    /// Strict parse; a leading `v` or `=` and surrounding whitespace are
    /// allowed, as in `new SemVer(...)`.
    pub fn parse(s: &str) -> Option<Ver> {
        let p = parse_partial(s.trim().trim_start_matches(['v', '=']))?;
        match p {
            Partial {
                major: Some(major),
                minor: Some(minor),
                patch: Some(patch),
                pre,
            } => Some(Ver::new(major, minor, patch, pre)),
            _ => None,
        }
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    fn tuple(&self) -> (u64, u64, u64) {
        (self.major, self.minor, self.patch)
    }
}

impl Ord for Ver {
    fn cmp(&self, other: &Self) -> Ordering {
        self.tuple().cmp(&other.tuple()).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                // Lexicographic on identifiers; a shorter prefix sorts first.
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for Ver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `1`, `1.2`, `1.x`, `1.2.3-pre`: missing or `x`/`X`/`*` parts are `None`
/// (and so is everything after them).
#[derive(Debug, PartialEq)]
struct Partial {
    major: Option<u64>,
    minor: Option<u64>,
    patch: Option<u64>,
    pre: Vec<Ident>,
}

fn numeric(s: &str) -> Option<u64> {
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn parse_partial(s: &str) -> Option<Partial> {
    let (s, build) = match s.split_once('+') {
        Some((s, b)) => (s, Some(b)),
        None => (s, None),
    };
    if let Some(b) = build
        && !b.split('.').all(valid_ident)
    {
        return None;
    }
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3 || (pre.is_some() && parts.len() != 3) {
        return None;
    }
    let mut nums = [None; 3];
    let mut wild = false;
    for (i, part) in parts.iter().enumerate() {
        if matches!(*part, "x" | "X" | "*") {
            wild = true;
        } else {
            let n = numeric(part)?;
            if !wild {
                nums[i] = Some(n);
            }
        }
    }
    let mut idents = Vec::new();
    if let Some(pre) = pre {
        for id in pre.split('.') {
            if !valid_ident(id) {
                return None;
            }
            if id.bytes().all(|b| b.is_ascii_digit()) {
                // Numeric identifiers must not have leading zeros.
                match numeric(id) {
                    Some(n) => idents.push(Ident::Num(n)),
                    None if id.len() > 1 && id.starts_with('0') => return None,
                    None => idents.push(Ident::Alpha(id.to_string())),
                }
            } else {
                idents.push(Ident::Alpha(id.to_string()));
            }
        }
    }
    Some(Partial {
        major: nums[0],
        minor: nums[1],
        patch: nums[2],
        // A prerelease only counts on a full version (`1.2.x-pre` drops it).
        pre: if nums[2].is_some() {
            idents
        } else {
            Vec::new()
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Clone, Debug, PartialEq)]
struct Comparator {
    op: Op,
    ver: Ver,
}

impl Comparator {
    fn test(&self, v: &Ver) -> bool {
        let ord = v.cmp(&self.ver);
        match self.op {
            Op::Lt => ord.is_lt(),
            Op::Le => ord.is_le(),
            Op::Gt => ord.is_gt(),
            Op::Ge => ord.is_ge(),
            Op::Eq => ord.is_eq(),
        }
    }
}

fn ge(major: u64, minor: u64, patch: u64, pre: Vec<Ident>) -> Comparator {
    Comparator {
        op: Op::Ge,
        ver: Ver::new(major, minor, patch, pre),
    }
}

/// `<M.m.p-0`: excludes `M.m.p` and its prereleases.
fn lt0(major: u64, minor: u64, patch: u64) -> Comparator {
    Comparator {
        op: Op::Lt,
        ver: Ver::new(major, minor, patch, vec![Ident::Num(0)]),
    }
}

/// Matches nothing (`<0.0.0-0`).
fn nothing() -> Vec<Comparator> {
    vec![lt0(0, 0, 0)]
}

/// A parsed range: `||`-separated sets of comparators (an empty set
/// matches any non-prerelease version).
#[derive(Clone, Debug, PartialEq)]
pub struct Range {
    sets: Vec<Vec<Comparator>>,
}

impl Range {
    /// `None` for anything that is not a semver range (tags, URLs,
    /// `workspace:` / `catalog:` specs, ...).
    pub fn parse(s: &str) -> Option<Range> {
        let sets = s.split("||").map(parse_set).collect::<Option<Vec<_>>>()?;
        Some(Range { sets })
    }

    pub fn satisfies(&self, v: &Ver) -> bool {
        self.sets.iter().any(|set| {
            set.iter().all(|c| c.test(v))
                // A prerelease only matches if some comparator in the set
                // names a prerelease of the same MAJOR.MINOR.PATCH.
                && (!v.is_prerelease()
                    || set
                        .iter()
                        .any(|c| c.ver.is_prerelease() && c.ver.tuple() == v.tuple()))
        })
    }
}

const OPS: [&str; 8] = ["<=", ">=", "~>", "<", ">", "=", "~", "^"];

fn parse_set(s: &str) -> Option<Vec<Comparator>> {
    // Tokens, with a lone operator glued to the next token (`>= 1.2`).
    let mut tokens: Vec<String> = Vec::new();
    let mut pending = String::new();
    for t in s.split_whitespace() {
        if OPS.contains(&t) {
            pending.push_str(t);
        } else {
            tokens.push(std::mem::take(&mut pending) + t);
        }
    }
    if !pending.is_empty() {
        tokens.push(pending);
    }

    if let [from, dash, to] = tokens.as_slice()
        && dash == "-"
    {
        return hyphen(from, to);
    }
    let mut out = Vec::new();
    for t in &tokens {
        out.extend(comparator(t)?);
    }
    Some(out)
}

fn strip_v(s: &str) -> &str {
    s.trim_start_matches(['v', '='])
}

/// `A - B` -> `>=A <=B`, with partial versions widened as node-semver does.
fn hyphen(from: &str, to: &str) -> Option<Vec<Comparator>> {
    let a = parse_partial(strip_v(from))?;
    let b = parse_partial(strip_v(to))?;
    let mut out = Vec::new();
    if let Some(ma) = a.major {
        out.push(ge(ma, a.minor.unwrap_or(0), a.patch.unwrap_or(0), a.pre));
    }
    match (b.major, b.minor, b.patch) {
        (None, _, _) => {}
        (Some(ma), None, _) => out.push(lt0(ma + 1, 0, 0)),
        (Some(ma), Some(mi), None) => out.push(lt0(ma, mi + 1, 0)),
        (Some(ma), Some(mi), Some(pa)) => out.push(Comparator {
            op: Op::Le,
            ver: Ver::new(ma, mi, pa, b.pre),
        }),
    }
    Some(out)
}

/// One comparator token (`^1.2`, `~1`, `>=1.2.3`, `1.x`, `*`) expanded into
/// primitive comparators.
fn comparator(t: &str) -> Option<Vec<Comparator>> {
    let (op, rest) = OPS
        .iter()
        .find_map(|op| t.strip_prefix(op).map(|r| (*op, r)))
        .unwrap_or(("", t));
    let p = parse_partial(strip_v(rest))?;
    let Some(ma) = p.major else {
        // `*`, `x`, `^*`, `>=*`: anything; `>*`, `<*`: nothing.
        return Some(if matches!(op, "<" | ">") {
            nothing()
        } else {
            Vec::new()
        });
    };
    Some(match op {
        "^" => match (p.minor, p.patch) {
            (None, _) => vec![ge(ma, 0, 0, vec![]), lt0(ma + 1, 0, 0)],
            (Some(mi), None) if ma == 0 => vec![ge(0, mi, 0, vec![]), lt0(0, mi + 1, 0)],
            (Some(mi), None) => vec![ge(ma, mi, 0, vec![]), lt0(ma + 1, 0, 0)],
            (Some(mi), Some(pa)) => {
                let upper = if ma > 0 {
                    lt0(ma + 1, 0, 0)
                } else if mi > 0 {
                    lt0(0, mi + 1, 0)
                } else {
                    lt0(0, 0, pa + 1)
                };
                vec![ge(ma, mi, pa, p.pre), upper]
            }
        },
        "~" | "~>" => match (p.minor, p.patch) {
            (None, _) => vec![ge(ma, 0, 0, vec![]), lt0(ma + 1, 0, 0)],
            (Some(mi), None) => vec![ge(ma, mi, 0, vec![]), lt0(ma, mi + 1, 0)],
            (Some(mi), Some(pa)) => vec![ge(ma, mi, pa, p.pre), lt0(ma, mi + 1, 0)],
        },
        _ => {
            let op = match op {
                "<" => Op::Lt,
                "<=" => Op::Le,
                ">" => Op::Gt,
                ">=" => Op::Ge,
                _ => Op::Eq,
            };
            match (p.minor, p.patch) {
                (Some(mi), Some(pa)) => vec![Comparator {
                    op,
                    ver: Ver::new(ma, mi, pa, p.pre),
                }],
                // Partial version (`1`, `1.2`): a block of releases from
                // `ma.mi.0` up to (excluding) `next`.
                (minor, _) => {
                    let mi = minor.unwrap_or(0);
                    let (nma, nmi) = if minor.is_none() {
                        (ma + 1, 0)
                    } else {
                        (ma, mi + 1)
                    };
                    match op {
                        Op::Gt => vec![ge(nma, nmi, 0, vec![])],
                        Op::Le => vec![lt0(nma, nmi, 0)],
                        Op::Lt => vec![lt0(ma, mi, 0)],
                        Op::Ge => vec![ge(ma, mi, 0, vec![])],
                        Op::Eq => vec![ge(ma, mi, 0, vec![]), lt0(nma, nmi, 0)],
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sat(range: &str, v: &str) -> bool {
        Range::parse(range).is_some_and(|r| r.satisfies(&Ver::parse(v).unwrap()))
    }

    /// Versions checked against every range in [`MATRIX`].
    #[rustfmt::skip]
    const VERSIONS: &[&str] = &[
        "0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2",
        "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0",
        "1.2.3-beta.2", "1.2.3-beta.3", "1.2.4-beta.1", "1.2.3-alpha.4", "2.0.0-rc.1",
        "1.2.3-rc.1", "1.0.0-0",
    ];

    /// `(range, the VERSIONS that semver.satisfies accepts)`, generated with
    /// the `semver` package (v7).
    #[rustfmt::skip]
    const MATRIX: &[(&str, &[&str])] = &[
        ("^1.2.3", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("~1.2.3", &["1.2.3", "1.2.4"]),
        ("^0.2.3", &["0.2.3", "0.2.9"]),
        ("^0.0.3", &["0.0.3"]),
        ("^0", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0"]),
        ("^0.0", &["0.0.0", "0.0.3", "0.0.4"]),
        ("^1.x", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("^0.x", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0"]),
        ("1.x", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("1.2.x", &["1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        ("1.x.3", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        (">=1.2.3 <2.0.0", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("1.2.3 - 2.3.4", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4"]),
        ("1.2 - 2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0"]),
        ("1.2.3 - 2", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0"]),
        ("1 - 2.3.4", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4"]),
        ("* - 2", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0"]),
        ("<1.2.3 || >=2.0.0", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("~1", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("~0.2", &["0.2.3", "0.2.9"]),
        ("~1.2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        ("^1.2.3-beta.2", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "1.2.3-beta.2", "1.2.3-beta.3", "1.2.3-rc.1"]),
        ("~1.2.3-beta", &["1.2.3", "1.2.4", "1.2.3-beta.2", "1.2.3-beta.3", "1.2.3-rc.1"]),
        (">1.2.3-alpha.3", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0", "1.2.3-beta.2", "1.2.3-beta.3", "1.2.3-alpha.4", "1.2.3-rc.1"]),
        ("=1.2.3", &["1.2.3"]),
        ("v1.2.3", &["1.2.3"]),
        ("1.2.3", &["1.2.3"]),
        ("1.2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        ("1", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        (">= 1.2.3", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("^ 1.2.3", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("~ 1.2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        ("~>1.2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        ("^v1.2.3", &["1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("latest", &[]),
        ("github:foo/bar", &[]),
        ("file:../x", &[]),
        ("npm:foo@^1.0.0", &[]),
        (">=1.0.0-0", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0", "1.0.0-0"]),
        ("<2.0.0-0", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        ("1.2.3 || 2.x", &["1.2.3", "2.0.0", "2.3.4", "2.3.5", "2.4.0"]),
        ("^1.2.3 >=1.4", &["1.4.0", "1.9.9"]),
        ("0.0.x", &["0.0.0", "0.0.3", "0.0.4"]),
        ("^0.0.0", &["0.0.0"]),
        ("1.2.3-rc.1", &["1.2.3-rc.1"]),
        (">=1.2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("<1.2", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9"]),
        (">1.2", &["1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("<=1.2", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        (">1", &["2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("<1", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0"]),
        ("<=1", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9"]),
        (">=1", &["1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("=1.2", &["1.2.0", "1.2.2", "1.2.3", "1.2.4"]),
        (">*", &[]),
        ("<*", &[]),
        (">=*", &["0.0.0", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.1.9", "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.4.0", "1.9.9", "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0"]),
        ("1.2.3 - 2.3.4 >=1", &[]),
        ("01.2.3", &[]),
        ("1.2.3.4", &[]),
    ];

    #[test]
    fn matches_node_semver() {
        for (range, accepted) in MATRIX {
            for v in VERSIONS {
                assert_eq!(
                    sat(range, v),
                    accepted.contains(v),
                    "satisfies({v:?}, {range:?})"
                );
            }
        }
        // Any-ranges match every release but no prerelease.
        for range in ["*", "", "x", ">=0.0.0", "1.2.3 || 2.x || *"] {
            assert!(sat(range, "3.0.0"), "{range}");
            assert!(!sat(range, "2.0.0-rc.1"), "{range}");
        }
    }

    #[test]
    fn ordering() {
        let v = |s| Ver::parse(s).unwrap();
        let sorted = [
            "0.0.1",
            "1.2.3-0",
            "1.2.3-1",
            "1.2.3-9",
            "1.2.3-10",
            "1.2.3-a",
            "1.2.3-beta",
            "1.2.3-beta.2",
            "1.2.3-beta.10",
            "1.2.3-beta.a",
            "1.2.3",
            "1.2.10",
            "1.10.0",
            "10.0.0",
        ];
        for w in sorted.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
        assert_eq!(v("1.2.3+build.5").cmp(&v("v1.2.3")), Ordering::Equal);
        for bad in [
            "1.2", "01.2.3", "1.2.3-01", "1.2.3-", "x.y.z", "1.2.3.4", "",
        ] {
            assert_eq!(Ver::parse(bad), None, "{bad}");
        }
    }
}
