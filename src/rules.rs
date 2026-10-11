//! Policy rules as plain functions. `now` is always passed in so results are
//! deterministic in tests.

use std::time::Duration;

use jiff::Timestamp;
use jiff::civil::Date;

use crate::config::{IgnoreRule, Policy};
use crate::model::BumpKind;
use crate::osv::{Advisory, Severity, SeverityLevel};

/// Whether a version published at `published_at` is old enough.
///
/// A zero `min_age` disables the rule. An unknown publish date (`None`) is a
/// violation whenever the rule is enabled: the rule protects against freshly
/// published malicious releases, so mendr fails closed. Adapters should
/// therefore always try to report publish dates.
pub fn release_age_ok(published_at: Option<Timestamp>, min_age: Duration, now: Timestamp) -> bool {
    if min_age.is_zero() {
        return true;
    }
    let Some(published) = published_at else {
        return false;
    };
    let age = now.as_second().saturating_sub(published.as_second());
    age >= 0 && age as u64 >= min_age.as_secs()
}

/// Whether a bump of this size is allowed by policy.
pub fn bump_allowed(bump: BumpKind, policy: &Policy) -> bool {
    bump != BumpKind::Major || policy.allow_major
}

/// Whether an advisory with `severity` meets the threshold. Unknown severity
/// always passes (better to over-report than to hide).
pub fn severity_ok(severity: Option<Severity>, min: SeverityLevel) -> bool {
    severity.is_none_or(|s| s.level >= min)
}

/// Result of matching an advisory against the ignore list.
#[derive(Debug, PartialEq)]
pub enum IgnoreMatch<'a> {
    /// No rule matches.
    None,
    /// A rule matches and applies today.
    Active(&'a IgnoreRule),
    /// A rule matches but expired; the advisory is handled normally (`main`
    /// warns once per expired rule, see [`ignore_expired`]).
    Expired(&'a IgnoreRule),
}

/// Match by advisory id or any alias. `expires` is inclusive.
pub fn ignore_match<'a>(
    advisory: &Advisory,
    ignores: &'a [IgnoreRule],
    today: Date,
) -> IgnoreMatch<'a> {
    let mut expired = None;
    for rule in ignores.iter().filter(|r| advisory.has_id(&r.id)) {
        if !ignore_expired(rule, today) {
            return IgnoreMatch::Active(rule);
        }
        expired = expired.or(Some(rule));
    }
    expired.map_or(IgnoreMatch::None, IgnoreMatch::Expired)
}

/// Whether `rule` no longer applies on `today` (`expires` is inclusive).
pub fn ignore_expired(rule: &IgnoreRule, today: Date) -> bool {
    rule.expires.is_some_and(|d| d < today)
}

/// Today's date in UTC (used for ignore expiry).
pub fn today(now: Timestamp) -> Date {
    now.to_zoned(jiff::tz::TimeZone::UTC).date()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn release_age() {
        let now = ts("2026-10-07T00:00:00Z");
        let week = Duration::from_secs(7 * 86_400);
        assert!(release_age_ok(Some(ts("2026-09-30T00:00:00Z")), week, now));
        assert!(!release_age_ok(Some(ts("2026-09-30T00:00:01Z")), week, now));
        assert!(
            !release_age_ok(None, week, now),
            "unknown date fails closed"
        );
        assert!(release_age_ok(None, Duration::ZERO, now), "zero disables");
        assert!(
            !release_age_ok(Some(ts("2027-01-01T00:00:00Z")), week, now),
            "future date"
        );
    }

    #[test]
    fn major_bumps() {
        let mut p = Policy::default();
        assert!(bump_allowed(BumpKind::Minor, &p));
        assert!(!bump_allowed(BumpKind::Major, &p));
        p.allow_major = true;
        assert!(bump_allowed(BumpKind::Major, &p));
    }

    #[test]
    fn severity_threshold() {
        let high = Severity {
            level: SeverityLevel::High,
            score: Some(7.5),
        };
        assert!(severity_ok(Some(high), SeverityLevel::Medium));
        assert!(severity_ok(Some(high), SeverityLevel::High));
        assert!(!severity_ok(Some(high), SeverityLevel::Critical));
        assert!(severity_ok(None, SeverityLevel::Critical));
    }

    #[test]
    fn ignore_list() {
        let adv = Advisory {
            id: "GHSA-1".into(),
            aliases: vec!["CVE-1".into()],
            summary: None,
            severity: None,
            records: vec![],
            package: None,
        };
        let rules = vec![
            IgnoreRule {
                id: "CVE-1".into(),
                reason: "old".into(),
                expires: Some(jiff::civil::date(2026, 1, 1)),
            },
            IgnoreRule {
                id: "OTHER".into(),
                reason: "x".into(),
                expires: None,
            },
        ];
        let today = jiff::civil::date(2026, 1, 1);
        assert_eq!(
            ignore_match(&adv, &rules, today),
            IgnoreMatch::Active(&rules[0])
        );
        let later = jiff::civil::date(2026, 1, 2);
        assert_eq!(
            ignore_match(&adv, &rules, later),
            IgnoreMatch::Expired(&rules[0])
        );
        assert_eq!(ignore_match(&adv, &rules[1..], later), IgnoreMatch::None);
        let mut forever = rules.clone();
        forever.push(IgnoreRule {
            id: "GHSA-1".into(),
            reason: "forever".into(),
            expires: None,
        });
        assert_eq!(
            ignore_match(&adv, &forever, later),
            IgnoreMatch::Active(&forever[2])
        );
        assert!(!ignore_expired(&rules[0], today), "inclusive");
        assert!(ignore_expired(&rules[0], later));
        assert!(!ignore_expired(&rules[1], later), "no expiry");
        assert_eq!(
            today_from("2026-03-04T23:59:59Z"),
            jiff::civil::date(2026, 3, 4)
        );
    }

    fn today_from(s: &str) -> Date {
        today(ts(s))
    }
}
