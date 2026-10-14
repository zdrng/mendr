//! Maven package data (`group:artifact`) from the deps.dev v3 API
//! (<https://docs.deps.dev/api/v3/>), cached on disk under the `deps-dev`
//! namespace:
//!
//! - GetPackage: every version with its publish date. Maven repositories
//!   have no yanking.
//! - GetRequirements: the dependencies one version's POM declares. deps.dev
//!   lists dependencies inherited from a parent POM without their scope, and
//!   declared ones without the scope `dependencyManagement` gives them, so
//!   the parent chain is fetched too (see [`Pom`]). Published versions are
//!   immutable, so these never expire.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ecosystem::{AdapterError, DeclaredDep, Release};
use crate::model::{Version, VersionReq};

pub const DEFAULT_API: &str = "https://api.deps.dev/v3";

const NAMESPACE: &str = "deps-dev";
/// How long a cached version list is trusted.
const MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// Part of the cache keys; bump when [`Release`], [`Pom`] or their parsing
/// changes.
const CACHE_FORMAT: u32 = 1;
/// Longest parent chain followed (guards against cycles).
const MAX_PARENTS: usize = 16;

/// All versions of `package` with publish dates (GetPackage). Maven has no
/// yanking: `yanked` is always false. A missing `publishedAt` stays `None`
/// (fails closed later). Cached 1h under namespace "deps-dev".
pub fn releases(api: &str, package: &str) -> Result<Vec<Release>, AdapterError> {
    releases_in(&crate::cache::cache_dir(), api, package)
}

/// Dependencies a consumer of `package@version` resolves (GetRequirements,
/// `maven.dependencies`): compile and runtime scope, after inheritance and
/// `dependencyManagement` scopes, first declaration of a name wins. Cached
/// without expiry (published versions are immutable) under "deps-dev".
pub fn requirements(
    api: &str,
    package: &str,
    version: &str,
) -> Result<Vec<DeclaredDep>, AdapterError> {
    requirements_in(&crate::cache::cache_dir(), api, package, version)
}

fn releases_in(root: &Path, api: &str, package: &str) -> Result<Vec<Release>, AdapterError> {
    let api = api.trim_end_matches('/');
    let key = format!("{api} {package} releases v{CACHE_FORMAT}");
    if let Some(text) = crate::cache::read_in(root, NAMESPACE, &key, Some(MAX_AGE))
        && let Ok(releases) = serde_json::from_str(&text)
    {
        return Ok(releases);
    }
    let url = format!("{api}/systems/maven/packages/{}", encode(package));
    let body = get(&url, || package.to_string())?;
    let doc: Package = parse(&body, || format!("deps.dev package {package}"))?;
    let releases: Vec<Release> = doc
        .versions
        .into_iter()
        .filter(|v| !v.version_key.version.is_empty())
        .map(|v| Release {
            version: Version::new(v.version_key.version),
            published_at: v.published_at.and_then(|t| t.parse().ok()),
            yanked: false,
        })
        .collect();
    if let Ok(text) = serde_json::to_string(&releases) {
        crate::cache::write_in(root, NAMESPACE, &key, &text);
    }
    Ok(releases)
}

fn requirements_in(
    root: &Path,
    api: &str,
    package: &str,
    version: &str,
) -> Result<Vec<DeclaredDep>, AdapterError> {
    let pom = pom(root, api.trim_end_matches('/'), package, version, 0)?;
    let mut out: Vec<DeclaredDep> = Vec::new();
    for dep in pom.deps {
        let scope = match dep.scope.as_str() {
            "" => pom.managed.get(&dep.key).map_or("", String::as_str),
            s => s,
        };
        if dep.version.is_empty()
            || !matches!(scope, "" | "compile" | "runtime")
            || out.iter().any(|d| d.name == dep.name)
        {
            continue;
        }
        out.push(DeclaredDep {
            name: dep.name,
            req: VersionReq::new(dep.version),
            optional: dep.optional,
        });
    }
    Ok(out)
}

/// One POM's dependencies after inheritance, before `dependencyManagement`
/// scopes are applied (that needs the child's management, which overrides
/// the parent's).
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct Pom {
    deps: Vec<PomDep>,
    /// [`PomDep::key`] -> non-empty managed scope, from this POM or its
    /// parents (nearest wins).
    managed: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PomDep {
    /// Resolved `group:artifact`.
    name: String,
    /// `name:type:classifier`, Maven's identity of a dependency.
    key: String,
    /// Resolved version; empty if deps.dev could not resolve it.
    version: String,
    /// Declared scope (here or in the parent that declares it); may be empty.
    scope: String,
    optional: bool,
}

/// Fetch (or load from cache) the [`Pom`] of `package@version`, following
/// its parents. A parent deps.dev does not know is treated as empty.
fn pom(
    root: &Path,
    api: &str,
    package: &str,
    version: &str,
    depth: usize,
) -> Result<Pom, AdapterError> {
    let key = format!("{api} {package}@{version} pom v{CACHE_FORMAT}");
    if let Some(text) = crate::cache::read_in(root, NAMESPACE, &key, None)
        && let Ok(pom) = serde_json::from_str(&text)
    {
        return Ok(pom);
    }
    let url = format!(
        "{api}/systems/maven/packages/{}/versions/{}:requirements",
        encode(package),
        encode(version)
    );
    let body = get(&url, || format!("{package}@{version}"))?;
    let doc: Requirements = parse(&body, || {
        format!("deps.dev requirements of {package}@{version}")
    })?;
    let maven = doc.maven;
    let parent = match maven.parent {
        Some(p) if !p.name.is_empty() && depth < MAX_PARENTS => {
            match pom(root, api, &p.name, &p.version, depth + 1) {
                Err(AdapterError::NotFound(_)) => Pom::default(),
                other => other?,
            }
        }
        _ => Pom::default(),
    };

    let mut pom = Pom::default();
    for e in maven.dependencies.iter().filter(|e| e.origin.is_empty()) {
        let (Some(name), Some(key)) = (e.resolved_name(), e.key()) else {
            continue;
        };
        // Entries without `name` are inherited: deps.dev drops their scope.
        let (scope, optional) = if e.name.is_empty() {
            parent
                .deps
                .iter()
                .find(|d| d.key == key)
                .map_or((String::new(), false), |d| (d.scope.clone(), d.optional))
        } else {
            (e.scope.clone(), e.optional == "true")
        };
        pom.deps.push(PomDep {
            name: name.to_string(),
            key,
            version: e.resolved_version().unwrap_or_default().to_string(),
            scope,
            optional,
        });
    }
    // Entries declared here (with a `name`) override inherited ones, even
    // with an empty scope.
    let mut managed: BTreeMap<String, String> = BTreeMap::new();
    for e in maven
        .dependency_management
        .iter()
        .filter(|e| !e.name.is_empty())
    {
        if let Some(key) = e.key() {
            managed.entry(key).or_insert_with(|| e.scope.clone());
        }
    }
    for (key, scope) in parent.managed {
        managed.entry(key).or_insert(scope);
    }
    managed.retain(|_, scope| !scope.is_empty());
    pom.managed = managed;

    if let Ok(text) = serde_json::to_string(&pom) {
        crate::cache::write_in(root, NAMESPACE, &key, &text);
    }
    Ok(pom)
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Package {
    versions: Vec<PackageVersion>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PackageVersion {
    version_key: VersionKey,
    published_at: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct VersionKey {
    name: String,
    version: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Requirements {
    maven: Maven,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Maven {
    parent: Option<VersionKey>,
    dependencies: Vec<Dependency>,
    dependency_management: Vec<Dependency>,
}

/// One `<dependency>` as deps.dev reports it. `name` and `version` are as
/// written in the POM (may hold `${...}` or be empty), `origin` is empty
/// for real dependencies (`parent`, `management`, `import` otherwise).
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Dependency {
    name: String,
    version: String,
    classifier: String,
    #[serde(rename = "type")]
    kind: String,
    scope: String,
    optional: String,
    resolved_name: String,
    resolved_version: String,
    origin: String,
}

/// `resolved` if set, else `declared` unless it holds a property reference.
fn resolved<'a>(resolved: &'a str, declared: &'a str) -> Option<&'a str> {
    if !resolved.is_empty() {
        Some(resolved)
    } else if !declared.is_empty() && !declared.contains("${") {
        Some(declared)
    } else {
        None
    }
}

impl Dependency {
    fn resolved_name(&self) -> Option<&str> {
        resolved(&self.resolved_name, &self.name)
    }

    fn resolved_version(&self) -> Option<&str> {
        resolved(&self.resolved_version, &self.version)
    }

    fn key(&self) -> Option<String> {
        let kind = if self.kind.is_empty() {
            "jar"
        } else {
            &self.kind
        };
        Some(format!(
            "{}:{kind}:{}",
            self.resolved_name()?,
            self.classifier
        ))
    }
}

fn get(url: &str, what: impl FnOnce() -> String) -> Result<String, AdapterError> {
    crate::http::get_string(url, &[("Accept", "application/json")]).map_err(|e| match e {
        crate::http::HttpError::NotFound(_) => AdapterError::NotFound(what()),
        other => other.into(),
    })
}

fn parse<T: serde::de::DeserializeOwned>(
    body: &str,
    what: impl FnOnce() -> String,
) -> Result<T, AdapterError> {
    serde_json::from_str(body).map_err(|e| AdapterError::Parse {
        what: what(),
        message: e.to_string(),
    })
}

/// Percent-encode one path segment: everything but unreserved characters
/// (`A-Z a-z 0-9 - . _ ~`).
fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Serve `routes` (path -> JSON body; anything else is a 404) and log
    /// every requested path.
    fn stub(routes: &'static [(&'static str, &'static str)]) -> (String, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        let api = crate::http::stub::serve(move |req| {
            seen.lock().unwrap().push(req.path.clone());
            match routes.iter().find(|(path, _)| *path == req.path) {
                Some((_, body)) => (200, vec![], body.to_string()),
                None => (404, vec![], "package not found".into()),
            }
        });
        (api, log)
    }

    fn deps(list: &[DeclaredDep]) -> Vec<(&str, &str, bool)> {
        list.iter()
            .map(|d| (d.name.as_str(), d.req.as_str(), d.optional))
            .collect()
    }

    #[test]
    fn encodes_path_segments() {
        assert_eq!(encode("org.example:lib"), "org.example%3Alib");
        assert_eq!(encode("1.0+build/x é~_-"), "1.0%2Bbuild%2Fx%20%C3%A9~_-");
    }

    #[test]
    fn releases_with_and_without_dates() {
        let (api, log) = stub(&[(
            "/systems/maven/packages/org.example%3Alib",
            r#"{"packageKey": {"system": "MAVEN", "name": "org.example:lib"},
                "versions": [
                  {"versionKey": {"system": "MAVEN", "name": "org.example:lib", "version": "1.0"},
                   "publishedAt": "2017-03-06T12:08:58Z", "isDefault": false,
                   "isDeprecated": false, "deprecatedReason": ""},
                  {"versionKey": {"system": "MAVEN", "name": "org.example:lib", "version": "1.1-beta-1"},
                   "isDefault": true},
                  {"versionKey": {"system": "MAVEN", "name": "org.example:lib", "version": "1.2"},
                   "publishedAt": "not a date"},
                  {"versionKey": {"system": "MAVEN", "name": "org.example:lib", "version": ""}}
                ]}"#,
        )]);
        let cache = tempfile::tempdir().unwrap();
        let got = releases_in(cache.path(), &format!("{api}/"), "org.example:lib").unwrap();
        let expected = vec![
            Release {
                version: Version::new("1.0"),
                published_at: Some("2017-03-06T12:08:58Z".parse().unwrap()),
                yanked: false,
            },
            Release {
                version: Version::new("1.1-beta-1"),
                published_at: None,
                yanked: false,
            },
            Release {
                version: Version::new("1.2"),
                published_at: None,
                yanked: false,
            },
        ];
        assert_eq!(got, expected);
        // Second call: from the cache.
        assert_eq!(
            releases_in(cache.path(), &api, "org.example:lib").unwrap(),
            expected
        );
        assert_eq!(log.lock().unwrap().len(), 1);

        match releases_in(cache.path(), &api, "no.such:pkg") {
            Err(AdapterError::NotFound(what)) => assert_eq!(what, "no.such:pkg"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn requirements_filter_scopes_origins_and_placeholders() {
        let (api, log) = stub(&[
            (
                "/systems/maven/packages/org.example%3Alib/versions/2.0%2Bb1:requirements",
                r#"{"maven": {
                  "parent": {"system": "MAVEN", "name": "org.example:parent", "version": "7"},
                  "dependencies": [
                    {"name": "org.example:core", "version": "${core.version}", "scope": "",
                     "optional": "false", "resolvedName": "org.example:core",
                     "resolvedVersion": "2.0", "origin": ""},
                    {"name": "org.example:rt", "version": "1", "scope": "runtime",
                     "optional": "false", "resolvedName": "org.example:rt",
                     "resolvedVersion": "1", "origin": ""},
                    {"name": "org.example:opt", "version": "3", "scope": "compile",
                     "optional": "true", "resolvedName": "org.example:opt",
                     "resolvedVersion": "3", "origin": ""},
                    {"name": "junit:junit", "version": "4.13", "scope": "test",
                     "resolvedName": "junit:junit", "resolvedVersion": "4.13", "origin": ""},
                    {"name": "javax.servlet:servlet-api", "version": "2.5", "scope": "provided",
                     "resolvedName": "javax.servlet:servlet-api", "resolvedVersion": "2.5"},
                    {"name": "com.sun:tools", "version": "1.8", "scope": "system",
                     "resolvedName": "com.sun:tools", "resolvedVersion": "1.8"},
                    {"name": "org.example:plain", "version": "5", "scope": "",
                     "resolvedName": "", "resolvedVersion": ""},
                    {"name": "org.example:over", "version": "4", "scope": "",
                     "resolvedName": "org.example:over", "resolvedVersion": "4", "origin": ""},
                    {"name": "${group}:unresolved", "version": "1",
                     "resolvedName": "", "resolvedVersion": "1"},
                    {"name": "org.example:nover", "version": "${missing}",
                     "resolvedName": "org.example:nover", "resolvedVersion": ""},
                    {"name": "org.example:managed-test", "version": "",
                     "resolvedName": "org.example:managed-test", "resolvedVersion": "6"},
                    {"name": "org.example:core", "version": "", "type": "test-jar",
                     "scope": "", "resolvedName": "org.example:core", "resolvedVersion": "2.0"},
                    {"name": "org.example:core", "version": "9", "scope": "compile",
                     "resolvedName": "org.example:core", "resolvedVersion": "9"},
                    {"name": "", "version": "", "scope": "", "optional": "",
                     "resolvedName": "org.mockito:mockito-core", "resolvedVersion": "3.11", "origin": ""},
                    {"name": "", "version": "", "scope": "", "optional": "",
                     "resolvedName": "org.example:inherited", "resolvedVersion": "8", "origin": ""},
                    {"name": "", "version": "", "scope": "", "optional": "",
                     "resolvedName": "org.example:parent", "resolvedVersion": "7", "origin": "parent"},
                    {"name": "", "resolvedName": "org.example:bom", "resolvedVersion": "1",
                     "origin": "import"}
                  ],
                  "dependencyManagement": [
                    {"name": "", "scope": "", "resolvedName": "org.example:managed-test",
                     "resolvedVersion": "6", "origin": "management"},
                    {"name": "org.example:over", "scope": "", "resolvedName": "org.example:over",
                     "resolvedVersion": "4", "origin": "management"}
                  ]
                }}"#,
            ),
            (
                "/systems/maven/packages/org.example%3Aparent/versions/7:requirements",
                r#"{"maven": {
                  "parent": {"name": "org.example:root", "version": "1"},
                  "dependencies": [
                    {"name": "org.mockito:mockito-core", "version": "3.11", "scope": "test",
                     "optional": "false", "resolvedName": "org.mockito:mockito-core",
                     "resolvedVersion": "3.11", "origin": ""},
                    {"name": "", "optional": "", "resolvedName": "org.example:inherited",
                     "resolvedVersion": "8", "origin": ""}
                  ],
                  "dependencyManagement": [
                    {"name": "org.example:managed-test", "version": "6", "scope": "test",
                     "resolvedName": "org.example:managed-test", "resolvedVersion": "6",
                     "origin": "management"},
                    {"name": "org.example:core", "type": "test-jar", "scope": "test",
                     "resolvedName": "org.example:core", "resolvedVersion": "2.0",
                     "origin": "management"}
                  ]
                }}"#,
            ),
            (
                "/systems/maven/packages/org.example%3Aroot/versions/1:requirements",
                r#"{"maven": {
                  "parent": {"name": "org.example:gone", "version": "1"},
                  "dependencies": [
                    {"name": "org.example:inherited", "version": "8", "scope": "compile",
                     "optional": "true", "resolvedName": "org.example:inherited",
                     "resolvedVersion": "8", "origin": ""}
                  ],
                  "dependencyManagement": [
                    {"name": "org.example:over", "scope": "test", "resolvedName": "org.example:over",
                     "resolvedVersion": "4", "origin": "management"}
                  ]
                }}"#,
            ),
        ]);
        let cache = tempfile::tempdir().unwrap();
        let got = requirements_in(cache.path(), &api, "org.example:lib", "2.0+b1").unwrap();
        assert_eq!(
            deps(&got),
            [
                // Placeholder version resolved; the later test-jar and
                // compile 9 entries of the same name are dropped.
                ("org.example:core", "2.0", false),
                ("org.example:rt", "1", false),
                ("org.example:opt", "3", true),
                // Unresolved, but a literal name and version: kept.
                ("org.example:plain", "5", false),
                // Root manages it as test, but the child's own management
                // entry (no scope) overrides that.
                ("org.example:over", "4", false),
                // Inherited twice; scope and optional from the root.
                ("org.example:inherited", "8", true),
            ]
        );
        // Dropped: test/provided/system, `${group}:unresolved`, nover,
        // managed-test (test via parent management), mockito (inherited
        // test), the parent and import entries. The unknown grandparent
        // `gone` is ignored.
        assert_eq!(log.lock().unwrap().len(), 4);

        // Cached: no further requests, also for the parent alone.
        let again = requirements_in(cache.path(), &api, "org.example:lib", "2.0+b1").unwrap();
        assert_eq!(again, got);
        let parent = requirements_in(cache.path(), &api, "org.example:parent", "7").unwrap();
        assert_eq!(deps(&parent), [("org.example:inherited", "8", true)]);
        assert_eq!(log.lock().unwrap().len(), 4);

        match requirements_in(cache.path(), &api, "org.example:lib", "9.9") {
            Err(AdapterError::NotFound(what)) => assert_eq!(what, "org.example:lib@9.9"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn bad_json_is_a_parse_error() {
        let (api, _) = stub(&[("/systems/maven/packages/a%3Ab", "<html>")]);
        let cache = tempfile::tempdir().unwrap();
        assert!(matches!(
            releases_in(cache.path(), &api, "a:b"),
            Err(AdapterError::Parse { .. })
        ));
    }

    #[test]
    #[ignore = "needs network (api.deps.dev)"]
    fn live_deps_dev() {
        let cache = tempfile::tempdir().unwrap();
        let root = cache.path();
        let names = |p: &str, v: &str| -> Vec<String> {
            requirements_in(root, DEFAULT_API, p, v)
                .unwrap()
                .into_iter()
                .map(|d| format!("{}@{}", d.name, d.req.as_str()))
                .collect()
        };
        assert_eq!(
            names("com.fasterxml.jackson.core:jackson-databind", "2.13.0"),
            [
                "com.fasterxml.jackson.core:jackson-annotations@2.13.0",
                "com.fasterxml.jackson.core:jackson-core@2.13.0"
            ]
        );
        assert_eq!(
            names("org.apache.commons:commons-text", "1.9"),
            ["org.apache.commons:commons-lang3@3.11"]
        );
        let log4j = names("org.apache.logging.log4j:log4j-core", "2.17.1");
        assert!(log4j.contains(&"org.apache.logging.log4j:log4j-api@2.17.1".to_string()));
        assert!(
            !log4j
                .iter()
                .any(|n| n.contains("junit") || n.contains("mockito"))
        );
        let guava = names("com.google.guava:guava", "24.1.1-jre");
        assert!(guava.contains(&"com.google.code.findbugs:jsr305@1.3.9".to_string()));

        let releases = releases_in(root, DEFAULT_API, "org.apache.commons:commons-text").unwrap();
        let r = releases
            .iter()
            .find(|r| r.version.as_str() == "1.9")
            .unwrap();
        assert!(r.published_at.is_some());
        assert!(matches!(
            releases_in(root, DEFAULT_API, "no.such.group:nope"),
            Err(AdapterError::NotFound(_))
        ));
    }
}
