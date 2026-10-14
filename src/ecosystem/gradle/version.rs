//! Maven/Gradle version rules: ordering (a port of Maven 3.9's
//! `org.apache.maven.artifact.versioning.ComparableVersion`), prerelease
//! detection, bump size, and matching against Gradle version notation
//! (plain versions, `!!` strict versions, Maven ranges, `1.+` prefixes and
//! `latest.*` selectors).
//!
//! The ordering tests include the vectors from Maven's own
//! `ComparableVersionTest`. One deliberate deviation: only ASCII digits
//! count as digits (Java's `Character.isDigit` accepts any Unicode digit).

use std::cmp::Ordering;

use crate::model::BumpKind;

/// One parse event. Maven builds a tree where every new sub-list is the
/// last element of the current list and becomes the current list, so the
/// tree is fully described by a flat sequence of items and "open" markers.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    /// Digits with leading zeros stripped (`"0"` for zero).
    Int(String),
    /// A qualifier after Maven's aliasing (`a1` -> `alpha`, `cr` -> `rc`,
    /// `ga`/`final`/`release` -> `""`).
    Str(String),
    /// Start a nested list; everything after it belongs to that list.
    Open,
}

/// A `ComparableVersion` item.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Item {
    Int(String),
    Str(String),
    List(Vec<Item>),
}

fn int_tok(digits: &str) -> Tok {
    let s = digits.trim_start_matches('0');
    Tok::Int(if s.is_empty() { "0" } else { s }.to_string())
}

/// Maven's `StringItem` constructor.
fn str_tok(s: &str, followed_by_digit: bool) -> Tok {
    let s = match s {
        "a" if followed_by_digit => "alpha",
        "b" if followed_by_digit => "beta",
        "m" if followed_by_digit => "milestone",
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        s => s,
    };
    Tok::Str(s.to_string())
}

fn item_tok(is_digit: bool, s: &str) -> Tok {
    if is_digit {
        int_tok(s)
    } else {
        str_tok(s, false)
    }
}

/// Whether the innermost list built so far has any items.
fn cur_list_nonempty(toks: &[Tok]) -> bool {
    toks.last().is_some_and(|t| *t != Tok::Open)
}

/// Maven's `parseVersion`, emitting a flat token stream.
fn tokenize(version: &str) -> Vec<Tok> {
    let v = version.to_lowercase();
    let mut toks = Vec::new();
    let mut is_digit = false;
    let mut start = 0;
    for (i, c) in v.char_indices() {
        if c == '.' || c == '-' {
            let t = if i == start {
                int_tok("0")
            } else {
                item_tok(is_digit, &v[start..i])
            };
            toks.push(t);
            start = i + 1;
            if c == '-' {
                toks.push(Tok::Open);
            }
        } else if c.is_ascii_digit() {
            if !is_digit && i > start {
                // MNG-7644: `.X1` is treated like `-X1`.
                if cur_list_nonempty(&toks) {
                    toks.push(Tok::Open);
                }
                toks.push(str_tok(&v[start..i], true));
                start = i;
                toks.push(Tok::Open);
            }
            is_digit = true;
        } else {
            if is_digit && i > start {
                toks.push(int_tok(&v[start..i]));
                start = i;
                toks.push(Tok::Open);
            }
            is_digit = false;
        }
    }
    if v.len() > start {
        if !is_digit && cur_list_nonempty(&toks) {
            toks.push(Tok::Open);
        }
        toks.push(item_tok(is_digit, &v[start..]));
    }
    toks
}

/// Maven's `ListItem.normalize`: drop trailing null items, looking through
/// (but keeping) non-null sub-lists.
fn normalize(list: &mut Vec<Item>) {
    for i in (0..list.len()).rev() {
        if is_null(&list[i]) {
            list.remove(i);
        } else if !matches!(list[i], Item::List(_)) {
            break;
        }
    }
}

/// The normalized item tree of `version`.
fn parse(version: &str) -> Vec<Item> {
    let mut list = Vec::new();
    for tok in tokenize(version).into_iter().rev() {
        match tok {
            Tok::Int(s) => list.push(Item::Int(s)),
            Tok::Str(s) => list.push(Item::Str(s)),
            Tok::Open => {
                list.reverse();
                normalize(&mut list);
                list = vec![Item::List(list)];
            }
        }
    }
    list.reverse();
    normalize(&mut list);
    list
}

fn is_null(item: &Item) -> bool {
    match item {
        Item::Int(s) => s == "0",
        Item::Str(s) => s.is_empty(),
        Item::List(l) => l.is_empty(),
    }
}

/// Qualifier order: known qualifiers by index, unknown ones after `sp`,
/// lexically among themselves.
fn qualifier_rank(s: &str) -> (u8, &str) {
    match s {
        "alpha" => (0, ""),
        "beta" => (1, ""),
        "milestone" => (2, ""),
        "rc" => (3, ""),
        "snapshot" => (4, ""),
        "" => (5, ""),
        "sp" => (6, ""),
        s => (7, s),
    }
}

fn cmp_digits(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// `a.compareTo(b)` where `None` is Maven's `null` padding item.
fn cmp_item(a: &Item, b: Option<&Item>) -> Ordering {
    use Item::*;
    match (a, b) {
        (Int(x), None) => {
            if x == "0" {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (Int(x), Some(Int(y))) => cmp_digits(x, y),
        (Int(_), Some(_)) => Ordering::Greater,
        (Str(x), None) => qualifier_rank(x).cmp(&qualifier_rank("")),
        (Str(x), Some(Str(y))) => qualifier_rank(x).cmp(&qualifier_rank(y)),
        (Str(_), Some(_)) => Ordering::Less,
        (List(l), None) => l
            .iter()
            .map(|i| cmp_item(i, None))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal),
        (List(_), Some(Int(_))) => Ordering::Less,
        (List(_), Some(Str(_))) => Ordering::Greater,
        (List(l), Some(List(r))) => cmp_lists(l, r),
    }
}

fn cmp_lists(l: &[Item], r: &[Item]) -> Ordering {
    for i in 0..l.len().max(r.len()) {
        let o = match (l.get(i), r.get(i)) {
            (Some(a), b) => cmp_item(a, b),
            (None, Some(b)) => cmp_item(b, None).reverse(),
            (None, None) => Ordering::Equal,
        };
        if o.is_ne() {
            return o;
        }
    }
    Ordering::Equal
}

/// Maven's version order (`org.apache.maven.artifact.versioning.ComparableVersion`,
/// Maven 3.9 semantics). Total and deterministic for any input.
pub fn compare(a: &str, b: &str) -> Ordering {
    cmp_lists(&parse(a), &parse(b))
}

/// Whether `v` carries a pre-release qualifier.
pub fn is_prerelease(v: &str) -> bool {
    tokenize(v).iter().any(|t| {
        matches!(t, Tok::Str(s) if matches!(
            s.as_str(),
            "alpha" | "beta" | "milestone" | "rc" | "snapshot" | "preview" | "pre" | "ea"
                | "dev" | "eap" | "nightly" | "incubating"
        ))
    })
}

/// The leading numeric components of `v` (`24.1.1-jre` -> `[24, 1, 1]`),
/// as digit strings without leading zeros.
fn numeric_prefix(v: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for part in v.split('.') {
        let end = part
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(part.len());
        if end == 0 {
            break;
        }
        let digits = part[..end].trim_start_matches('0');
        out.push(if digits.is_empty() { "0" } else { digits });
        if end < part.len() {
            break;
        }
    }
    out
}

/// Size of `from -> to`: first numeric component differs -> Major, second
/// -> Minor, else Patch. Missing components count as 0 (`1.2` vs `1.2.1`
/// -> Patch). Non-numeric leading component on either side -> Major. No
/// 0.x caret rule (Maven has none).
pub fn bump_kind(from: &str, to: &str) -> BumpKind {
    let (f, t) = (numeric_prefix(from), numeric_prefix(to));
    if f.is_empty() || t.is_empty() {
        return BumpKind::Major;
    }
    let at = |v: &[&str], i: usize| v.get(i).copied().unwrap_or("0").to_string();
    if at(&f, 0) != at(&t, 0) {
        BumpKind::Major
    } else if at(&f, 1) != at(&t, 1) {
        BumpKind::Minor
    } else {
        BumpKind::Patch
    }
}

/// One `[lo,hi)`-style range; `None` bounds are unbounded.
struct Range<'a> {
    lo: Option<&'a str>,
    lo_incl: bool,
    hi: Option<&'a str>,
    hi_incl: bool,
}

impl Range<'_> {
    fn contains(&self, v: &str) -> bool {
        let lo_ok = self.lo.is_none_or(|lo| match compare(v, lo) {
            Ordering::Greater => true,
            Ordering::Equal => self.lo_incl,
            Ordering::Less => false,
        });
        let hi_ok = self.hi.is_none_or(|hi| match compare(v, hi) {
            Ordering::Less => true,
            Ordering::Equal => self.hi_incl,
            Ordering::Greater => false,
        });
        lo_ok && hi_ok
    }
}

/// A trimmed range bound; empty means unbounded.
fn bound(s: &str) -> Option<&str> {
    let s = s.trim();
    (!s.is_empty()).then_some(s)
}

/// Parse a union of Maven/Gradle ranges (`[1,2),[3,)`, `]1,2[`, `[1.0]`).
fn parse_ranges(req: &str) -> Option<Vec<Range<'_>>> {
    let mut out = Vec::new();
    let mut rest = req.trim();
    while !rest.is_empty() {
        let lo_incl = match rest.as_bytes()[0] {
            b'[' => true,
            b'(' | b']' => false,
            _ => return None,
        };
        let body_end = rest[1..].find([']', ')', '['])? + 1;
        let hi_incl = rest.as_bytes()[body_end] == b']';
        let body = &rest[1..body_end];
        let range = match body.split_once(',') {
            Some((lo, hi)) => {
                if hi.contains(',') {
                    return None;
                }
                Range {
                    lo: bound(lo),
                    lo_incl,
                    hi: bound(hi),
                    hi_incl,
                }
            }
            None => {
                // `[1.0]`: exactly this version.
                let v = bound(body)?;
                if !(lo_incl && hi_incl) {
                    return None;
                }
                Range {
                    lo: Some(v),
                    lo_incl,
                    hi: Some(v),
                    hi_incl,
                }
            }
        };
        if range
            .lo
            .or(range.hi)
            .is_some_and(|b| b.contains(char::is_whitespace))
        {
            return None;
        }
        out.push(range);
        rest = rest[body_end + 1..].trim_start();
        if let Some(r) = rest.strip_prefix(',') {
            rest = r.trim_start();
            if rest.is_empty() {
                return None;
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Whether `version` satisfies the requirement `req` written in Gradle
/// notation: empty (anything), a plain or strict (`1.2!!`, `1.2!!1.5`)
/// version (exact match), Maven ranges and unions (also with Gradle's
/// `]1,2[` brackets), prefixes (`1.+`, `+`) and `latest.release` /
/// `latest.integration` / `latest.milestone`. Unparseable -> false.
pub fn satisfies(req: &str, version: &str) -> bool {
    let req = req.trim();
    if req.is_empty() {
        return true;
    }
    if let Some((strict, _prefer)) = req.split_once("!!") {
        // `a!!b`: strictly `a`, prefer `b`.
        return !strict.trim().is_empty() && satisfies(strict, version);
    }
    if req.starts_with(['[', '(', ']']) {
        return parse_ranges(req).is_some_and(|rs| rs.iter().any(|r| r.contains(version)));
    }
    match req {
        "latest.release" => return !is_prerelease(version),
        "latest.integration" | "latest.milestone" => return true,
        _ => {}
    }
    if let Some(prefix) = req.strip_suffix('+') {
        return !prefix.contains(['+', '[', ']', '(', ')', ',']) && version.starts_with(prefix);
    }
    if req.contains(|c: char| c.is_whitespace() || "[](),".contains(c)) {
        return false;
    }
    compare(req, version) == Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strictly increasing (Maven's `ComparableVersionTest.VERSIONS_QUALIFIER`).
    #[rustfmt::skip]
    const VERSIONS_QUALIFIER: &[&str] = &[
        "1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11",
        "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc",
        "1-def", "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123",
    ];

    /// Strictly increasing (Maven's `ComparableVersionTest.VERSIONS_NUMBER`).
    #[rustfmt::skip]
    const VERSIONS_NUMBER: &[&str] = &[
        "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
        "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11",
        "11.a", "11b", "11c", "11m",
    ];

    fn check_order(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Less, "{a} < {b}");
        assert_eq!(compare(b, a), Ordering::Greater, "{b} > {a}");
    }

    fn check_equal(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Equal, "{a} = {b}");
        assert_eq!(compare(b, a), Ordering::Equal, "{b} = {a}");
    }

    fn check_sorted(versions: &[&str]) {
        for (i, a) in versions.iter().enumerate() {
            assert_eq!(compare(a, a), Ordering::Equal, "{a} = {a}");
            for b in &versions[i + 1..] {
                check_order(a, b);
            }
        }
    }

    #[test]
    fn maven_qualifier_order() {
        check_sorted(VERSIONS_QUALIFIER);
    }

    #[test]
    fn maven_number_order() {
        check_sorted(VERSIONS_NUMBER);
    }

    #[test]
    fn maven_equal() {
        for (a, b) in [
            ("1", "1"),
            ("1", "1.0"),
            ("1", "1.0.0"),
            ("1.0", "1.0.0"),
            ("1", "1-0"),
            ("1", "1.0-0"),
            ("1.0", "1.0-0"),
            // no separator between number and character
            ("1a", "1-a"),
            ("1a", "1.0-a"),
            ("1a", "1.0.0-a"),
            ("1.0a", "1-a"),
            ("1.0.0a", "1-a"),
            ("1x", "1-x"),
            ("1x", "1.0-x"),
            ("1x", "1.0.0-x"),
            ("1.0x", "1-x"),
            ("1.0.0x", "1-x"),
            // aliases
            ("1ga", "1"),
            ("1ga", "1-ga"),
            ("1ga", "1.ga"),
            ("1ga", "1final"),
            ("1ga", "1release"),
            ("1release", "1"),
            ("1final", "1"),
            ("1cr", "1rc"),
            // special "aliases" a, b and m for alpha, beta and milestone
            ("1a1", "1-alpha-1"),
            ("1b2", "1-beta-2"),
            ("1m3", "1-milestone-3"),
            // case insensitive
            ("1X", "1x"),
            ("1A", "1a"),
            ("1B", "1b"),
            ("1M", "1m"),
            ("1Ga", "1"),
            ("1GA", "1"),
            ("1RELEASE", "1"),
            ("1release", "1"),
            ("1RELeaSE", "1"),
            ("1Final", "1"),
            ("1FinaL", "1"),
            ("1FINAL", "1"),
            ("1Cr", "1Rc"),
            ("1cR", "1rC"),
            ("1m3", "1Milestone3"),
            ("1m3", "1MileStone3"),
            ("1m3", "1MILESTONE3"),
            // real-world release qualifiers
            ("1.0.Final", "1.0"),
            ("5.3.0.RELEASE", "5.3.0"),
        ] {
            check_equal(a, b);
        }
    }

    #[test]
    fn maven_order() {
        for (a, b) in [
            ("1", "2"),
            ("1.5", "2"),
            ("1", "2.5"),
            ("1.0", "1.1"),
            ("1.1", "1.2"),
            ("1.0.0", "1.1"),
            ("1.0.1", "1.1"),
            ("1.1", "1.2.0"),
            ("1.0-alpha-1", "1.0"),
            ("1.0-alpha-1", "1.0-alpha-2"),
            ("1.0-alpha-1", "1.0-beta-1"),
            ("1.0-beta-1", "1.0-SNAPSHOT"),
            ("1.0-SNAPSHOT", "1.0"),
            ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
            ("1.0", "1.0-1"),
            ("1.0-1", "1.0-2"),
            ("1.0.0", "1.0-1"),
            ("2.0-1", "2.0.1"),
            ("2.0.1-klm", "2.0.1-lmn"),
            ("2.0.1", "2.0.1-xyz"),
            ("2.0.1", "2.0.1-123"),
            ("2.0.1-xyz", "2.0.1-123"),
        ] {
            check_order(a, b);
        }
    }

    #[test]
    fn maven_regressions() {
        // MNG-5568
        check_order("6.1.0rc3", "6.1.0");
        check_order("6.1.0", "6.1H.5-beta");
        check_order("6.1.0rc3", "6.1H.5-beta");
        // MNG-6572: integers of any size
        check_order("20190126.230843", "1234567890.12345");
        check_order("1234567890.12345", "123456789012345.1H.5-beta");
        check_order(
            "123456789012345.1H.5-beta",
            "12345678901234567890.1H.5-beta",
        );
        check_order("12345678901234567890.1", "123456789012345678901234567890");
        check_equal(
            "000123456789012345678901234567890",
            "123456789012345678901234567890",
        );
        // MNG-6964
        check_order("1-0.alpha", "1");
        check_order("1-0.beta", "1");
        check_order("1-0.alpha", "1-0.beta");
        // MNG-7644: 1.0.0.X1 < 1.0.0-X2, and 2-X = 2.0.X = 2.0.0.X
        for x in [
            "abc",
            "alpha",
            "a",
            "beta",
            "b",
            "def",
            "milestone",
            "m",
            "RC",
        ] {
            check_order(&format!("1.0.0.{x}1"), &format!("1.0.0-{x}2"));
            check_equal(&format!("2-{x}"), &format!("2.0.{x}"));
            check_equal(&format!("2-{x}"), &format!("2.0.0.{x}"));
            check_equal(&format!("2.0.{x}"), &format!("2.0.0.{x}"));
        }
    }

    #[test]
    fn real_versions() {
        for (lo, hi) in [
            ("2.9.10", "2.9.10.8"),
            ("24.1.1-android", "24.1.1-jre"),
            ("24.1.1-jre", "31.1-jre"),
            ("2.13.4", "2.13.4.1"),
            ("1.9", "1.10.0"),
            ("r03", "19.0"),
            ("5.0.0-RC2", "5.0.0"),
            ("1.0-M1", "1.0-RC1"),
            ("2.0-SNAPSHOT", "2.0"),
            ("1.0.0.Beta1", "1.0.0.CR1"),
            ("1.0.0.CR1", "1.0.0.Final"),
        ] {
            check_order(lo, hi);
        }
    }

    #[test]
    fn odd_inputs_are_total() {
        for v in [
            "", ".", "-", "..", "--", "-1", ".1", "1..2", "1--2", "a", "é1ü", "1.0+x",
        ] {
            assert_eq!(compare(v, v), Ordering::Equal, "{v:?}");
        }
        check_equal("", "0");
        check_equal("1..2", "1.0.2");
    }

    #[test]
    fn prerelease() {
        for v in [
            "1.0-M1",
            "5.0.0-RC2",
            "1.0.0.Beta1",
            "2.0-SNAPSHOT",
            "1.0a1",
            "1.0-alpha",
            "1.0.0-cr1",
            "1.0-preview",
            "1.0-pre2",
            "17-ea",
            "1.0-dev",
            "2023.1-eap",
            "1.0-nightly",
            "0.9-incubating",
        ] {
            assert!(is_prerelease(v), "{v}");
        }
        for v in [
            "24.1.1-jre",
            "2.13.4.1",
            "1.0.Final",
            "1.0.RELEASE",
            "1.0-sp1",
            "1.0",
            "1.0-a",
            "1.0-m",
            "r03",
            "",
        ] {
            assert!(!is_prerelease(v), "{v}");
        }
    }

    #[test]
    fn bump() {
        use BumpKind::*;
        for (from, to, kind) in [
            ("1.2.3", "1.2.4", Patch),
            ("1.2.3", "1.3.0", Minor),
            ("1.2.3", "2.0.0", Major),
            ("1.2", "1.2.1", Patch),
            ("1", "1.0.1", Patch),
            ("1", "1.1", Minor),
            ("0.1.0", "0.2.0", Minor),
            ("2.9.10", "2.9.10.8", Patch),
            ("2.13.4", "2.13.4.1", Patch),
            ("24.1.1-jre", "31.1-jre", Major),
            ("31.0-jre", "31.1-jre", Minor),
            ("1.0-M1", "1.0", Patch),
            ("1.9", "1.10.0", Minor),
            ("01.2", "1.2.5", Patch),
            ("r03", "19.0", Major),
            ("1.0", "final", Major),
            ("123456789012345678901.0", "123456789012345678901.1", Minor),
        ] {
            assert_eq!(bump_kind(from, to), kind, "{from} -> {to}");
        }
    }

    #[test]
    fn satisfies_plain_and_strict() {
        assert!(satisfies("", "1.0"));
        assert!(satisfies("  ", "anything"));
        assert!(satisfies("1.2.3", "1.2.3"));
        assert!(satisfies("1.2", "1.2.0"));
        assert!(satisfies("24.1.1-jre", "24.1.1-jre"));
        assert!(!satisfies("24.1.1-jre", "24.1.1-android"));
        assert!(!satisfies("1.2.3", "1.2.4"));
        assert!(satisfies("1.2.3!!", "1.2.3"));
        assert!(!satisfies("1.2.3!!", "1.2.4"));
        assert!(satisfies("1.2!!1.5", "1.2"));
        assert!(!satisfies("1.2!!1.5", "1.5"));
        assert!(satisfies("[1.0,2.0)!!1.5", "1.7"));
        assert!(!satisfies("!!1.5", "1.5"));
    }

    #[test]
    fn satisfies_ranges() {
        let cases: &[(&str, &str, bool)] = &[
            ("[1.0,2.0)", "1.0", true),
            ("[1.0,2.0)", "1.5", true),
            ("[1.0,2.0)", "2.0", false),
            ("[1.0,2.0)", "2.0-SNAPSHOT", true),
            ("[1.0,2.0)", "0.9", false),
            ("(1.0,2.0]", "1.0", false),
            ("(1.0,2.0]", "2.0", true),
            ("(1.0,2.0]", "2.0.0", true),
            ("[1.0,)", "99", true),
            ("[1.0,)", "0.9", false),
            ("(,1.0]", "0.1", true),
            ("(,1.0]", "1.0.1", false),
            ("[1.0]", "1.0", true),
            ("[1.0]", "1.0.0", true),
            ("[1.0]", "1.1", false),
            ("[1.0,2.0),[3.0,)", "1.5", true),
            ("[1.0,2.0),[3.0,)", "2.5", false),
            ("[1.0,2.0),[3.0,)", "3.1", true),
            ("[1.0,2.0), [3.0,)", "3.1", true),
            ("]1.0,2.0[", "1.0", false),
            ("]1.0,2.0[", "1.5", true),
            ("]1.0,2.0[", "2.0", false),
            ("]1.0,2.0]", "2.0", true),
            ("[1.0,2.0[", "1.0", true),
            ("[1.0,2.0[", "2.0", false),
            ("[ 1.0 , 2.0 )", "1.5", true),
            // unparseable
            ("[1.0", "1.0", false),
            ("[1.0,2.0", "1.0", false),
            ("(1.0)", "1.0", false),
            ("[]", "1.0", false),
            ("[1,2,3]", "2", false),
            ("[1.0,2.0),", "1.5", false),
            ("[1.0,2.0) x", "1.5", false),
            ("[1 0,2)", "1.5", false),
        ];
        for &(req, v, want) in cases {
            assert_eq!(satisfies(req, v), want, "{req} ~ {v}");
        }
    }

    #[test]
    fn satisfies_dynamic() {
        assert!(satisfies("+", "1.0"));
        assert!(satisfies("1.+", "1.9.3"));
        assert!(!satisfies("1.+", "2.0"));
        assert!(!satisfies("1.+", "10.0"));
        assert!(satisfies("1.2.+", "1.2.0"));
        assert!(!satisfies("1.2.+", "1.3.0"));
        assert!(satisfies("latest.release", "1.0"));
        assert!(!satisfies("latest.release", "1.0-RC1"));
        assert!(satisfies("latest.integration", "1.0-SNAPSHOT"));
        assert!(satisfies("latest.milestone", "1.0-M1"));
        assert!(!satisfies("1.0 2.0", "1.0"));
        assert!(!satisfies("1.0,2.0", "1.0"));
    }
}
