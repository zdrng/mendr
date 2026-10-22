//! `mendr.toml` parsing, CLI overrides and validation.
//!
//! ```toml
//! [policy]
//! strategies = ["relock", "direct-bump", "override"]  # order = preference
//! allow-major = false
//! min-release-age = "7d"        # "0", "30s", "20m", "12h", "7d"
//! min-severity = "low"          # low | medium | high | critical
//! target = "minimal"            # or "latest-compatible"
//!
//! [npm]                         # npm projects; both keys optional
//! registry = "https://registry.npmjs.org/"
//! replace-registry-host = "always"   # npmjs | always | never | <host>
//!
//! [osv]
//! api = "https://api.osv.dev/v1"     # optional
//!
//! [[project]]                   # repeatable; default: one project at "."
//! path = "apps/web"             # relative to the config file
//! ecosystem = "npm"             # optional, auto-detected
//! install = "npm ci --ignore-scripts"
//! build = "npm run build"
//! test = "npm test"
//! timeout = "20m"               # per command; "0" = no timeout
//!
//! [[ignore]]
//! id = "GHSA-xxxx-yyyy"         # matches the advisory id or any alias
//! reason = "not reachable"
//! expires = 2026-12-31          # optional; inclusive (UTC date)
//! ```
//!
//! Unknown keys are rejected. Without a config file mendr uses the defaults
//! and a single auto-detected project in the current directory. `[npm]` and
//! `[osv]` values win over their environment variables (see
//! [`NpmConfig::registry_or_env`], [`OsvConfig::api_or_env`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::Strategy;
use crate::osv::SeverityLevel;

pub const CONFIG_FILE: &str = "mendr.toml";

/// How to choose among several acceptable fix versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetPolicy {
    /// The smallest acceptable version.
    Minimal,
    /// The highest acceptable version that is not a major bump from the
    /// smallest acceptable one.
    LatestCompatible,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// Enabled strategies in preference order. Default: all, cheapest first.
    pub strategies: Vec<Strategy>,
    /// Allow major bumps of direct dependencies / overrides. Default: false.
    pub allow_major: bool,
    /// Minimum age of any version mendr picks. Default: 7 days. Zero
    /// disables the check.
    pub min_release_age: Duration,
    /// Advisories below this level are reported as skipped. Default: low
    /// (everything). Advisories with unknown severity always pass.
    pub min_severity: SeverityLevel,
    pub target: TargetPolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            strategies: Strategy::ALL.to_vec(),
            allow_major: false,
            min_release_age: Duration::from_secs(7 * 86_400),
            min_severity: SeverityLevel::Low,
            target: TargetPolicy::Minimal,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProjectConfig {
    /// Project directory, absolute (joined onto the config's base dir).
    pub path: PathBuf,
    /// Adapter name; `None` = auto-detect.
    pub ecosystem: Option<String>,
    /// Per-field overrides of `Ecosystem::default_commands`.
    pub install: Option<String>,
    pub build: Option<String>,
    pub test: Option<String>,
    /// Per-command timeout. `None` = no timeout (also for `timeout = "0"`).
    pub timeout: Option<Duration>,
}

impl ProjectConfig {
    pub fn at(path: PathBuf) -> Self {
        ProjectConfig {
            path,
            ecosystem: None,
            install: None,
            build: None,
            test: None,
            timeout: None,
        }
    }

    /// `defaults` with this project's configured commands applied on top.
    pub fn commands(&self, defaults: crate::ecosystem::Commands) -> crate::ecosystem::Commands {
        crate::ecosystem::Commands {
            install: self.install.clone().or(defaults.install),
            build: self.build.clone().or(defaults.build),
            test: self.test.clone().or(defaults.test),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IgnoreRule {
    pub id: String,
    pub reason: String,
    /// Last day (inclusive, UTC) on which the rule applies.
    pub expires: Option<jiff::civil::Date>,
}

/// `[npm]`: registry settings for npm projects. No tokens: those stay in
/// `.npmrc` outside the project or in environment variables.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NpmConfig {
    /// http(s) URL.
    pub registry: Option<String>,
    /// `npmjs`, `always`, `never` or a host name.
    pub replace_registry_host: Option<String>,
}

impl NpmConfig {
    /// `registry`, else `$npm_config_registry` / `$NPM_CONFIG_REGISTRY`.
    pub fn registry_or_env(&self, var: impl Fn(&str) -> Option<String>) -> Option<String> {
        self.registry
            .clone()
            .or_else(|| var("npm_config_registry"))
            .or_else(|| var("NPM_CONFIG_REGISTRY"))
    }

    /// Environment for npm child processes: the configured keys only, so
    /// unset ones keep whatever the environment has.
    pub fn child_env(&self) -> Vec<(String, String)> {
        [
            ("npm_config_registry", &self.registry),
            (
                "npm_config_replace_registry_host",
                &self.replace_registry_host,
            ),
        ]
        .into_iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.clone()?)))
        .collect()
    }
}

/// `[osv]`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OsvConfig {
    /// API base URL (http(s)).
    pub api: Option<String>,
}

impl OsvConfig {
    /// `api`, else a non-empty `$MENDR_OSV_API`.
    pub fn api_or_env(&self, var: impl Fn(&str) -> Option<String>) -> Option<String> {
        self.api
            .clone()
            .or_else(|| var("MENDR_OSV_API").filter(|v| !v.trim().is_empty()))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Directory the config file lives in (or the cwd without a file).
    pub base_dir: PathBuf,
    /// The config file that was loaded, if any.
    pub file: Option<PathBuf>,
    pub policy: Policy,
    pub npm: NpmConfig,
    pub osv: OsvConfig,
    pub projects: Vec<ProjectConfig>,
    pub ignores: Vec<IgnoreRule>,
}

/// CLI flags that override the config file.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    pub allow_major: bool,
    pub min_release_age: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    policy: RawPolicy,
    #[serde(default)]
    npm: RawNpm,
    #[serde(default)]
    osv: RawOsv,
    #[serde(default)]
    project: Vec<RawProject>,
    #[serde(default)]
    ignore: Vec<RawIgnore>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawPolicy {
    strategies: Option<Vec<Strategy>>,
    allow_major: Option<bool>,
    min_release_age: Option<String>,
    min_severity: Option<SeverityLevel>,
    target: Option<TargetPolicy>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawNpm {
    registry: Option<String>,
    replace_registry_host: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawOsv {
    api: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawProject {
    #[serde(default = "dot")]
    path: String,
    ecosystem: Option<String>,
    install: Option<String>,
    build: Option<String>,
    test: Option<String>,
    timeout: Option<String>,
}

fn dot() -> String {
    ".".into()
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawIgnore {
    id: String,
    reason: String,
    expires: Option<toml::Value>,
}

/// Parse `"0"`, `"30s"`, `"20m"`, `"12h"`, `"7d"`.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().with_context(|| {
        format!("invalid duration `{s}` (expected e.g. \"7d\", \"12h\", \"20m\", \"30s\")")
    })?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("invalid duration `{s}`: unit must be one of s, m, h, d"),
    };
    let total = n
        .checked_mul(secs)
        .with_context(|| format!("duration `{s}` is too large"))?;
    Ok(Duration::from_secs(total))
}

/// An `http://` or `https://` URL with a host.
fn http_url(s: &str) -> Result<String> {
    let s = s.trim();
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .with_context(|| format!("`{s}` is not an http(s) URL"))?;
    if rest.is_empty() || rest.starts_with('/') || rest.contains(char::is_whitespace) {
        bail!("`{s}` is not an http(s) URL");
    }
    Ok(s.to_string())
}

/// npm's `replace-registry-host`: `npmjs`, `always`, `never` or a host
/// (optionally with a port).
fn replace_registry_host(s: &str) -> Result<String> {
    let s = s.trim();
    let host = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    if !host {
        bail!("`{s}` must be \"npmjs\", \"always\", \"never\" or a host name");
    }
    Ok(s.to_string())
}

fn parse_expires(v: &toml::Value) -> Result<jiff::civil::Date> {
    let text = match v {
        toml::Value::Datetime(dt) => {
            let Some(d) = dt.date else {
                bail!("`expires` must be a date like 2026-12-31")
            };
            if dt.time.is_some() {
                bail!("`expires` must be a date without time, like 2026-12-31");
            }
            format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)
        }
        toml::Value::String(s) => s.clone(),
        _ => bail!("`expires` must be a date like 2026-12-31"),
    };
    text.parse()
        .with_context(|| format!("invalid `expires` date `{text}`"))
}

impl Config {
    /// Defaults: one auto-detected project at `base_dir`.
    pub fn default_at(base_dir: &Path) -> Config {
        Config {
            base_dir: base_dir.to_path_buf(),
            file: None,
            policy: Policy::default(),
            npm: NpmConfig::default(),
            osv: OsvConfig::default(),
            projects: vec![ProjectConfig::at(base_dir.to_path_buf())],
            ignores: Vec::new(),
        }
    }

    /// Parse config text; relative project paths are joined onto `base_dir`.
    pub fn parse(text: &str, base_dir: &Path) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text).context("invalid mendr.toml")?;
        let mut policy = Policy::default();
        if let Some(s) = raw.policy.strategies {
            policy.strategies = s;
        }
        if let Some(v) = raw.policy.allow_major {
            policy.allow_major = v;
        }
        if let Some(v) = raw.policy.min_release_age {
            policy.min_release_age = parse_duration(&v).context("policy.min-release-age")?;
        }
        if let Some(v) = raw.policy.min_severity {
            policy.min_severity = v;
        }
        if let Some(v) = raw.policy.target {
            policy.target = v;
        }
        let npm = NpmConfig {
            registry: raw
                .npm
                .registry
                .map(|v| http_url(&v).context("npm.registry"))
                .transpose()?,
            replace_registry_host: raw
                .npm
                .replace_registry_host
                .map(|v| replace_registry_host(&v).context("npm.replace-registry-host"))
                .transpose()?,
        };
        let osv = OsvConfig {
            api: raw
                .osv
                .api
                .map(|v| http_url(&v).context("osv.api"))
                .transpose()?,
        };
        let mut projects = Vec::new();
        for p in raw.project {
            // "0" means no timeout (not "kill at once").
            let timeout = match &p.timeout {
                Some(t) => Some(
                    parse_duration(t).with_context(|| format!("project `{}`: timeout", p.path))?,
                )
                .filter(|d| !d.is_zero()),
                None => None,
            };
            projects.push(ProjectConfig {
                path: base_dir.join(&p.path),
                ecosystem: p.ecosystem,
                install: p.install,
                build: p.build,
                test: p.test,
                timeout,
            });
        }
        if projects.is_empty() {
            projects.push(ProjectConfig::at(base_dir.to_path_buf()));
        }
        let mut ignores = Vec::new();
        for i in raw.ignore {
            let expires = match &i.expires {
                Some(v) => Some(parse_expires(v).with_context(|| format!("ignore `{}`", i.id))?),
                None => None,
            };
            ignores.push(IgnoreRule {
                id: i.id,
                reason: i.reason,
                expires,
            });
        }
        Ok(Config {
            base_dir: base_dir.to_path_buf(),
            file: None,
            policy,
            npm,
            osv,
            projects,
            ignores,
        })
    }

    /// Load `path` if given (must exist), else `<cwd>/mendr.toml` if it
    /// exists, else defaults at `cwd`.
    pub fn load(path: Option<&Path>, cwd: &Path) -> Result<Config> {
        let file = match path {
            Some(p) => {
                let p = cwd.join(p);
                if !p.is_file() {
                    bail!("config file {} does not exist", p.display());
                }
                p
            }
            None => {
                let p = cwd.join(CONFIG_FILE);
                if !p.is_file() {
                    return Ok(Config::default_at(cwd));
                }
                p
            }
        };
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let base = file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| cwd.to_path_buf());
        let mut config =
            Config::parse(&text, &base).with_context(|| format!("in {}", file.display()))?;
        config.file = Some(file);
        Ok(config)
    }

    /// Apply CLI flags on top of the file.
    pub fn apply_overrides(&mut self, o: &Overrides) -> Result<()> {
        if o.allow_major {
            self.policy.allow_major = true;
        }
        if let Some(age) = &o.min_release_age {
            self.policy.min_release_age = parse_duration(age).context("--min-release-age")?;
        }
        Ok(())
    }

    /// Check cross-field constraints. `known_ecosystems` is
    /// `ecosystem::names()` in production.
    pub fn validate(&self, known_ecosystems: &[&str]) -> Result<()> {
        if self.policy.strategies.is_empty() {
            bail!("policy.strategies must not be empty");
        }
        for (i, s) in self.policy.strategies.iter().enumerate() {
            if self.policy.strategies[..i].contains(s) {
                bail!("policy.strategies lists `{s}` twice");
            }
        }
        for p in &self.projects {
            if let Some(e) = &p.ecosystem
                && !known_ecosystems.contains(&e.as_str())
            {
                bail!(
                    "project {}: unknown ecosystem `{e}` (known: {})",
                    p.path.display(),
                    known_ecosystems.join(", ")
                );
            }
        }
        for (i, p) in self.projects.iter().enumerate() {
            if self.projects[..i].iter().any(|q| q.path == p.path) {
                bail!("project {} is listed twice", p.path.display());
            }
        }
        for i in &self.ignores {
            if i.id.trim().is_empty() {
                bail!("ignore entries need a non-empty `id`");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[policy]
strategies = ["relock", "direct-bump"]
allow-major = true
min-release-age = "12h"
min-severity = "medium"
target = "latest-compatible"

[[project]]
path = "apps/web"
test = "npm test"

[[project]]
path = "services/api"
ecosystem = "cargo"
build = "cargo build"
timeout = "20m"

[[ignore]]
id = "GHSA-xxxx-yyyy"
reason = "not reachable"
expires = 2026-12-31

[[ignore]]
id = "RUSTSEC-2020-0001"
reason = "string date"
expires = "2027-01-02"
"#;

    #[test]
    fn parses_full_config() {
        let c = Config::parse(FULL, Path::new("/repo")).unwrap();
        assert_eq!(
            c.policy.strategies,
            vec![Strategy::Relock, Strategy::DirectBump]
        );
        assert!(c.policy.allow_major);
        assert_eq!(c.policy.min_release_age, Duration::from_secs(12 * 3600));
        assert_eq!(c.policy.min_severity, SeverityLevel::Medium);
        assert_eq!(c.policy.target, TargetPolicy::LatestCompatible);
        assert_eq!(c.projects.len(), 2);
        assert_eq!(c.projects[0].path, PathBuf::from("/repo/apps/web"));
        assert_eq!(c.projects[0].test.as_deref(), Some("npm test"));
        assert_eq!(c.projects[1].ecosystem.as_deref(), Some("cargo"));
        assert_eq!(c.projects[1].timeout, Some(Duration::from_secs(1200)));
        assert_eq!(c.ignores[0].expires, Some(jiff::civil::date(2026, 12, 31)));
        assert_eq!(c.ignores[1].expires, Some(jiff::civil::date(2027, 1, 2)));
        c.validate(&["cargo", "npm"]).unwrap();
    }

    #[test]
    fn defaults_without_file() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load(None, dir.path()).unwrap();
        assert_eq!(c.file, None);
        assert_eq!(
            c.projects,
            vec![ProjectConfig::at(dir.path().to_path_buf())]
        );
        assert_eq!(c.policy, Policy::default());
        assert!(Config::load(Some(Path::new("missing.toml")), dir.path()).is_err());

        std::fs::write(
            dir.path().join("mendr.toml"),
            "[policy]\nallow-major = true\n",
        )
        .unwrap();
        let c = Config::load(None, dir.path()).unwrap();
        assert!(c.policy.allow_major);
        assert_eq!(
            c.projects.len(),
            1,
            "no [[project]] = one project at the config dir"
        );
        assert_eq!(c.projects[0].path, dir.path());
    }

    #[test]
    fn overrides_win() {
        let mut c = Config::parse("[policy]\nmin-release-age = \"7d\"\n", Path::new("/r")).unwrap();
        c.apply_overrides(&Overrides {
            allow_major: true,
            min_release_age: Some("0".into()),
        })
        .unwrap();
        assert!(c.policy.allow_major);
        assert_eq!(c.policy.min_release_age, Duration::ZERO);
        assert!(
            c.apply_overrides(&Overrides {
                min_release_age: Some("1y".into()),
                ..Overrides::default()
            })
            .is_err()
        );
    }

    #[test]
    fn npm_and_osv_sections() {
        let c = Config::parse(
            r#"
[npm]
registry = "https://registry.npmjs.org/"
replace-registry-host = "always"

[osv]
api = "https://osv.intern.example/v1"
"#,
            Path::new("/r"),
        )
        .unwrap();
        assert_eq!(
            c.npm,
            NpmConfig {
                registry: Some("https://registry.npmjs.org/".into()),
                replace_registry_host: Some("always".into()),
            }
        );
        assert_eq!(c.osv.api.as_deref(), Some("https://osv.intern.example/v1"));
        assert_eq!(
            c.npm.child_env(),
            vec![
                (
                    "npm_config_registry".into(),
                    "https://registry.npmjs.org/".into()
                ),
                ("npm_config_replace_registry_host".into(), "always".into()),
            ]
        );

        for host in [
            "npmjs",
            "never",
            "npm.intern.example",
            "npm.intern.example:8443",
        ] {
            let text = format!("[npm]\nreplace-registry-host = \"{host}\"\n");
            let c = Config::parse(&text, Path::new("/r")).unwrap();
            assert_eq!(c.npm.replace_registry_host.as_deref(), Some(host));
        }

        let c = Config::default_at(Path::new("/r"));
        assert_eq!(c.npm, NpmConfig::default());
        assert!(c.npm.child_env().is_empty());
        assert_eq!(c.osv, OsvConfig::default());
    }

    #[test]
    fn npm_and_osv_validation() {
        for (bad, key) in [
            ("[npm]\nregistry = \"registry.npmjs.org\"\n", "npm.registry"),
            ("[npm]\nregistry = \"ftp://x/\"\n", "npm.registry"),
            ("[npm]\nregistry = \"https://\"\n", "npm.registry"),
            (
                "[npm]\nreplace-registry-host = \"\"\n",
                "npm.replace-registry-host",
            ),
            (
                "[npm]\nreplace-registry-host = \"https://x\"\n",
                "npm.replace-registry-host",
            ),
            ("[osv]\napi = \"osv.dev\"\n", "osv.api"),
        ] {
            let err = Config::parse(bad, Path::new("/r")).unwrap_err();
            assert!(format!("{err:#}").contains(key), "{bad:?}: {err:#}");
        }
        for bad in [
            "[npm]\ntoken = \"x\"\n",
            "[npm]\n_authToken = \"x\"\n",
            "[osv]\nurl = \"https://x\"\n",
        ] {
            assert!(Config::parse(bad, Path::new("/r")).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn config_wins_over_env() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(name, _)| *name == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let all = env(&[
            ("npm_config_registry", "https://lower.example/"),
            ("NPM_CONFIG_REGISTRY", "https://upper.example/"),
            ("MENDR_OSV_API", "https://env-osv.example/v1"),
        ]);
        let set = Config::parse(
            "[npm]\nregistry = \"https://file.example/\"\n[osv]\napi = \"https://file-osv.example/v1\"\n",
            Path::new("/r"),
        )
        .unwrap();
        assert_eq!(
            set.npm.registry_or_env(all).as_deref(),
            Some("https://file.example/")
        );
        assert_eq!(
            set.osv.api_or_env(all).as_deref(),
            Some("https://file-osv.example/v1")
        );

        let unset = Config::default_at(Path::new("/r"));
        assert_eq!(
            unset.npm.registry_or_env(all).as_deref(),
            Some("https://lower.example/")
        );
        let upper = env(&[("NPM_CONFIG_REGISTRY", "https://upper.example/")]);
        assert_eq!(
            unset.npm.registry_or_env(upper).as_deref(),
            Some("https://upper.example/")
        );
        assert_eq!(
            unset.osv.api_or_env(all).as_deref(),
            Some("https://env-osv.example/v1")
        );
        let blank = env(&[("MENDR_OSV_API", " ")]);
        assert_eq!(unset.osv.api_or_env(blank), None);
        assert_eq!(unset.npm.registry_or_env(env(&[])), None);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("20m").unwrap(), Duration::from_secs(1200));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        let err = parse_duration("18446744073709551615d").unwrap_err();
        assert!(format!("{err:#}").contains("too large"), "{err:#}");
        for bad in ["", "d", "7", "7 d", "-1d", "1.5h", "7days", "1y"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn zero_timeout_means_none() {
        for zero in ["0", "0s", "0d"] {
            let text = format!("[[project]]\ntimeout = \"{zero}\"\n");
            let c = Config::parse(&text, Path::new("/r")).unwrap();
            assert_eq!(c.projects[0].timeout, None, "{zero}");
        }
    }

    #[test]
    fn validation_errors() {
        let c = Config::parse(
            "[[project]]\npath = \"x\"\necosystem = \"cobol\"\n",
            Path::new("/r"),
        )
        .unwrap();
        let err = c.validate(&["cargo", "npm"]).unwrap_err().to_string();
        assert!(err.contains("unknown ecosystem `cobol`"), "{err}");

        let c = Config::parse("[policy]\nstrategies = []\n", Path::new("/r")).unwrap();
        assert!(c.validate(&[]).is_err());
        let c = Config::parse(
            "[policy]\nstrategies = [\"relock\", \"relock\"]\n",
            Path::new("/r"),
        )
        .unwrap();
        assert!(c.validate(&[]).is_err());
        let c = Config::parse(
            "[[project]]\npath = \"a\"\n[[project]]\npath = \"a\"\n",
            Path::new("/r"),
        )
        .unwrap();
        assert!(c.validate(&[]).is_err());

        for bad in [
            "[policy]\nmin-release-age = \"7x\"\n",
            "[policy]\nstrategies = [\"yolo\"]\n",
            "[policy]\nmin-severity = \"urgent\"\n",
            "[policy]\nunknown = 1\n",
            "[[project]]\ntimeout = \"soon\"\n",
            "[[ignore]]\nid = \"X\"\n",
            "[[ignore]]\nid = \"X\"\nreason = \"r\"\nexpires = \"tomorrow\"\n",
            "[[ignore]]\nid = \"X\"\nreason = \"r\"\nexpires = 2026-01-01T10:00:00Z\n",
        ] {
            assert!(
                Config::parse(bad, Path::new("/r")).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
