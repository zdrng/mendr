//! npm registry lookups for pnpm projects, cached on disk under the `pnpm`
//! namespace:
//!
//! - packuments (`GET <registry>/<name>`), reduced to what the planner needs
//!   (versions, publish times, dependencies). The full document is needed:
//!   the abbreviated format has no per-version publish times. There is no
//!   yanking (unpublished versions just disappear), and `deprecated` is not
//!   treated as yanked: many fixed releases of old packages are deprecated.
//! - version manifests (`GET <registry>/<name>/<version>`): the dependency
//!   specs one published version declares, by declared name. The lockfile
//!   only records what each dependency resolved to, so the graph takes the
//!   requirements on its edges from here. Published versions are immutable,
//!   so these never expire.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ecosystem::{AdapterError, DeclaredDep, Release};
use crate::model::{Version, VersionReq};

/// How long a cached packument is trusted.
const MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);
/// Part of the cache keys; bump when [`PackageInfo`], [`Specs`] or their
/// parsing changes.
const CACHE_FORMAT: u32 = 1;

pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

/// The parsed subset of one packument.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub releases: Vec<Release>,
    /// Version -> dependencies + optional + peer dependencies.
    pub deps: BTreeMap<String, Vec<DeclaredDep>>,
}

/// Declared name -> spec (`^1.2.0`, `npm:real@^1`) of one published version:
/// `dependencies`, then `optionalDependencies`, then `peerDependencies` (the
/// first section that declares a name wins).
pub type Specs = BTreeMap<String, String>;

/// Registry base URL: `$pnpm_config_registry` (pnpm >= 11),
/// `$npm_config_registry` (pnpm 10) or the public registry. `.npmrc` and
/// `pnpm-workspace.yaml` are not read.
pub fn registry_url() -> String {
    let url = ["pnpm_config_registry", "npm_config_registry"]
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| DEFAULT_REGISTRY.to_string());
    if url.ends_with('/') { url } else { url + "/" }
}

/// Packument URL; scoped names keep the `@` and encode the slash.
pub fn packument_url(registry: &str, name: &str) -> String {
    format!("{registry}{}", name.replace('/', "%2f"))
}

/// Manifest URL of one version.
pub fn manifest_url(registry: &str, name: &str, version: &str) -> String {
    format!("{}/{version}", packument_url(registry, name))
}

/// Fetch (or load from cache) the info for `name`.
pub fn fetch(name: &str) -> Result<PackageInfo, AdapterError> {
    let registry = registry_url();
    let key = format!("{registry}{name} v{CACHE_FORMAT}");
    if let Some(text) = crate::cache::read("pnpm", &key, Some(MAX_AGE))
        && let Ok(info) = serde_json::from_str(&text)
    {
        return Ok(info);
    }
    let url = packument_url(&registry, name);
    let body =
        crate::http::get_string(&url, &[("Accept", "application/json")]).map_err(|e| match e {
            crate::http::HttpError::NotFound(_) => AdapterError::NotFound(name.to_string()),
            other => other.into(),
        })?;
    let info = parse(name, &body)?;
    if let Ok(text) = serde_json::to_string(&info) {
        crate::cache::write("pnpm", &key, &text);
    }
    Ok(info)
}

/// Fetch (or load from cache) the dependency specs of `name@version`.
/// `None` if the registry does not have that version or refuses to show it
/// (a package from another or a private registry).
pub fn fetch_specs(name: &str, version: &str) -> Result<Option<Specs>, AdapterError> {
    let registry = registry_url();
    let key = format!("{registry}{name}@{version} specs v{CACHE_FORMAT}");
    if let Some(text) = crate::cache::read("pnpm", &key, None)
        && let Ok(specs) = serde_json::from_str(&text)
    {
        return Ok(Some(specs));
    }
    let url = manifest_url(&registry, name, version);
    let body = match crate::http::get_string(&url, &[("Accept", "application/json")]) {
        Ok(body) => body,
        Err(
            crate::http::HttpError::NotFound(_)
            | crate::http::HttpError::Status {
                status: 401 | 403, ..
            },
        ) => return Ok(None),
        Err(other) => return Err(other.into()),
    };
    let manifest: Manifest = serde_json::from_str(&body).map_err(|e| AdapterError::Parse {
        what: format!("registry manifest of {name}@{version}"),
        message: e.to_string(),
    })?;
    let specs = specs(&manifest);
    if let Ok(text) = serde_json::to_string(&specs) {
        crate::cache::write("pnpm", &key, &text);
    }
    Ok(Some(specs))
}

#[derive(Deserialize)]
struct Packument {
    #[serde(default)]
    versions: BTreeMap<String, Manifest>,
    #[serde(default)]
    time: BTreeMap<String, Value>,
}

/// Dependency maps are kept as raw JSON: ancient packuments contain
/// malformed ones (arrays, non-string values) that must not fail the parse.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    dependencies: Option<Value>,
    optional_dependencies: Option<Value>,
    peer_dependencies: Option<Value>,
    peer_dependencies_meta: Option<Value>,
}

fn string_map(v: &Option<Value>) -> Vec<(String, String)> {
    v.as_ref()
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

fn specs(m: &Manifest) -> Specs {
    let mut out = Specs::new();
    for section in [
        &m.dependencies,
        &m.optional_dependencies,
        &m.peer_dependencies,
    ] {
        for (name, spec) in string_map(section) {
            out.entry(name).or_insert(spec);
        }
    }
    out
}

/// Dependencies a consumer resolves. A name in both `dependencies` and
/// `optionalDependencies` is optional; peers are optional when
/// `peerDependenciesMeta.<name>.optional` is set. Aliases
/// (`"x": "npm:real@range"`) become the real package and range.
fn declared(m: &Manifest) -> Vec<DeclaredDep> {
    let optional = string_map(&m.optional_dependencies);
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<DeclaredDep> = Vec::new();
    let mut push = |key: String, spec: String, optional: bool| {
        if seen.contains(&key) {
            return;
        }
        let (name, req) = match super::alias(&spec) {
            Some((name, range)) => (name.to_string(), range.to_string()),
            None => (key.clone(), spec),
        };
        seen.push(key);
        out.push(DeclaredDep {
            name,
            req: VersionReq::new(req),
            optional,
        });
    };
    for (name, req) in optional.iter().cloned() {
        push(name, req, true);
    }
    for (name, req) in string_map(&m.dependencies) {
        push(name, req, false);
    }
    for (name, req) in string_map(&m.peer_dependencies) {
        let optional = m
            .peer_dependencies_meta
            .as_ref()
            .and_then(|meta| meta.get(&name)?.get("optional")?.as_bool())
            .unwrap_or(false);
        push(name, req, optional);
    }
    out
}

pub fn parse(name: &str, body: &str) -> Result<PackageInfo, AdapterError> {
    let doc: Packument = serde_json::from_str(body).map_err(|e| AdapterError::Parse {
        what: format!("packument for {name}"),
        message: e.to_string(),
    })?;
    let mut info = PackageInfo::default();
    for (version, manifest) in &doc.versions {
        let published_at = doc
            .time
            .get(version)
            .and_then(Value::as_str)
            .and_then(|t| t.parse::<jiff::Timestamp>().ok());
        info.releases.push(Release {
            version: Version::new(version),
            published_at,
            yanked: false,
        });
        info.deps.insert(version.clone(), declared(manifest));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packument_subset() {
        let body = r#"{
          "name": "p",
          "versions": {
            "1.0.0": {"dependencies": {"a": "^1", "o": "~2"}, "optionalDependencies": {"o": "~2"},
                      "devDependencies": {"never": "1"}},
            "1.1.0": {"dependencies": ["legacy", "array"],
                      "peerDependencies": {"r": ">=16", "s": "*"},
                      "peerDependenciesMeta": {"s": {"optional": true}}},
            "1.2.0": {"dependencies": {"mm": "npm:minimist@^1.2.6", "old": "npm:minimist@0.0.8",
                                       "sx": "npm:@s/x"}},
            "2.0.0-rc.1": {"deprecated": "do not use"}
          },
          "time": {"created": "2014-01-01T00:00:00.000Z", "1.0.0": "2014-05-04T19:23:43.633Z",
                   "1.1.0": "2015-01-01T00:00:00Z", "unpublished": {"time": "x"}}
        }"#;
        let info = parse("p", body).unwrap();
        let versions: Vec<&str> = info.releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, ["1.0.0", "1.1.0", "1.2.0", "2.0.0-rc.1"]);
        assert_eq!(
            info.releases[0].published_at,
            Some("2014-05-04T19:23:43.633Z".parse().unwrap())
        );
        assert_eq!(info.releases[3].published_at, None);
        assert!(info.releases.iter().all(|r| !r.yanked));

        let deps = |v: &str| -> Vec<(String, String, bool)> {
            info.deps[v]
                .iter()
                .map(|d| (d.name.clone(), d.req.to_string(), d.optional))
                .collect()
        };
        assert_eq!(
            deps("1.0.0"),
            [
                ("o".into(), "~2".into(), true),
                ("a".into(), "^1".into(), false)
            ]
        );
        assert_eq!(
            deps("1.1.0"),
            [
                ("r".into(), ">=16".into(), false),
                ("s".into(), "*".into(), true)
            ]
        );
        // Aliases: real names and ranges; two aliases of one package stay.
        assert_eq!(
            deps("1.2.0"),
            [
                ("minimist".into(), "^1.2.6".into(), false),
                ("minimist".into(), "0.0.8".into(), false),
                ("@s/x".into(), "*".into(), false)
            ]
        );
        assert!(deps("2.0.0-rc.1").is_empty());
        assert!(parse("p", "<html>").is_err());
    }

    #[test]
    fn specs_keep_declared_names() {
        let m: Manifest = serde_json::from_str(
            r#"{"dependencies": {"mm": "npm:minimist@^1.2.6", "a": "^1"},
                "optionalDependencies": {"a": "^1", "o": "2"},
                "peerDependencies": {"react": "^18", "a": "*"},
                "devDependencies": {"never": "1"}}"#,
        )
        .unwrap();
        let specs: Vec<(String, String)> = specs(&m).into_iter().collect();
        let expected = [
            ("a", "^1"),
            ("mm", "npm:minimist@^1.2.6"),
            ("o", "2"),
            ("react", "^18"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        assert_eq!(specs, expected);
    }

    #[test]
    fn urls() {
        assert_eq!(
            packument_url(DEFAULT_REGISTRY, "@scope/pkg"),
            "https://registry.npmjs.org/@scope%2fpkg"
        );
        assert_eq!(
            manifest_url(DEFAULT_REGISTRY, "minimist", "1.2.6"),
            "https://registry.npmjs.org/minimist/1.2.6"
        );
    }
}
