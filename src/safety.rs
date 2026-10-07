//! Safety checks run before any build/test command.
//!
//! Builds and tests execute untrusted code (build scripts, test suites,
//! install hooks of new dependency versions). mendr refuses to run them when
//! secrets are reachable, unless `--allow-unsandboxed` /
//! `[safety] allow-unsandboxed = true`.
//!
//! Isolation cannot be proven from inside, so the checks look for *danger*:
//! - credential files readable under `HOME` (SSH private keys, cloud, registry
//!   and Git credentials, see [`CREDENTIAL_FILES`]) or named by environment
//!   variables (`CARGO_HOME`, `DOCKER_CONFIG`, `KUBECONFIG`, ...);
//! - secret-looking environment variables (see [`is_secret_var`]); values are
//!   never printed;
//! - a reachable SSH agent (`SSH_AUTH_SOCK`) or Docker/Podman socket
//!   (`/var/run/docker.sock`, `$DOCKER_HOST`, rootless sockets under
//!   `$XDG_RUNTIME_DIR`, Docker Desktop/Colima sockets under `HOME`);
//! - every path in `SafetyConfig::deny_paths` (`~/` expanded) that is readable.
//!
//! Fixture tests run mendr with `HOME` set to an empty temp dir and a
//! cleared environment, so the checks pass there without the flag.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::config::SafetyConfig;

/// One failed safety check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Violation {
    /// Short check id: `"credential-file"`, `"secret-env"`, `"ssh-agent"`,
    /// `"docker-socket"`, `"deny-path"`.
    pub check: String,
    /// Human-readable description: the path or variable name and why it is
    /// dangerous (never the secret value).
    pub detail: String,
}

/// What the checks look at. [`Environment::current`] in production; tests
/// build one with a temp `HOME` and an injected variable map.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    pub home: Option<PathBuf>,
    pub vars: BTreeMap<String, String>,
    /// System-wide container sockets (not derived from `HOME`/vars).
    pub system_sockets: Vec<PathBuf>,
}

impl Environment {
    pub fn current() -> Environment {
        let vars: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.to_string_lossy().into_owned())))
            .collect();
        Environment {
            home: vars
                .get("HOME")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from),
            vars,
            system_sockets: [
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/run/podman/podman.sock",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
        }
    }

    fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// How a credential file is recognised.
#[derive(Clone, Copy)]
enum Cred {
    /// Dangerous if readable.
    Any,
    /// Dangerous if readable and the text contains one of these markers.
    Contains(&'static [&'static str]),
    /// A Docker `config.json`: dangerous if it holds `auths`, `credsStore`
    /// or `credHelpers`.
    DockerConfig,
    /// A directory: dangerous if it can be listed and is not empty.
    Dir,
}

/// Credential files relative to `HOME`, with a short description.
const CREDENTIAL_FILES: &[(&str, Cred, &str)] = &[
    (".aws/credentials", Cred::Any, "AWS credentials"),
    (".aws/sso/cache", Cred::Dir, "AWS SSO tokens"),
    (".cargo/credentials.toml", Cred::Any, "Cargo registry token"),
    (".cargo/credentials", Cred::Any, "Cargo registry token"),
    (
        ".npmrc",
        Cred::Contains(&["_auth", "_password"]),
        "npm registry token",
    ),
    (".yarnrc.yml", Cred::Contains(&["npmAuth"]), "Yarn token"),
    (".config/gh/hosts.yml", Cred::Any, "GitHub CLI credentials"),
    (
        ".docker/config.json",
        Cred::DockerConfig,
        "Docker registry credentials",
    ),
    (".netrc", Cred::Any, "netrc credentials"),
    (".git-credentials", Cred::Any, "Git credentials"),
    (".kube/config", Cred::Any, "Kubernetes credentials"),
    (
        ".config/gcloud/application_default_credentials.json",
        Cred::Any,
        "Google Cloud credentials",
    ),
    (
        ".config/gcloud/credentials.db",
        Cred::Any,
        "Google Cloud credentials",
    ),
    (
        ".config/gcloud/access_tokens.db",
        Cred::Any,
        "Google Cloud tokens",
    ),
    (".azure", Cred::Dir, "Azure CLI credentials"),
    (".pypirc", Cred::Any, "PyPI credentials"),
    (".gem/credentials", Cred::Any, "RubyGems credentials"),
    (".gnupg/private-keys-v1.d", Cred::Dir, "GnuPG private keys"),
];

/// Variables naming a credential file (or `:`-separated list of files).
const CREDENTIAL_FILE_VARS: &[(&str, &str)] = &[
    ("AWS_SHARED_CREDENTIALS_FILE", "AWS credentials"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "Google Cloud credentials"),
    ("KUBECONFIG", "Kubernetes credentials"),
    ("NETRC", "netrc credentials"),
];

/// Secret-looking variable names that are known to be harmless.
const HARMLESS_VARS: &[&str] = &["PASSWORD_STORE_DIR", "PASSWORD_STORE_KEY"];

/// Run all checks against the current process environment.
pub fn check(config: &SafetyConfig) -> Vec<Violation> {
    check_with(config, &Environment::current())
}

/// Run all checks against `env`.
pub fn check_with(config: &SafetyConfig, env: &Environment) -> Vec<Violation> {
    let mut out = Vec::new();
    credential_files(env, &mut out);
    secret_vars(env, &mut out);
    sockets(env, &mut out);
    for p in &config.deny_paths {
        let path = expand(p, env.home.as_deref());
        if readable(&path) {
            out.push(violation(
                "deny-path",
                format!(
                    "{} is readable (listed in [safety] deny-paths)",
                    path.display()
                ),
            ));
        }
    }
    // The same file can be named twice (e.g. `CARGO_HOME=~/.cargo`).
    let mut seen = std::collections::HashSet::new();
    out.retain(|v| seen.insert(v.clone()));
    out
}

/// Fail unless `check` is clean or unsandboxed runs are allowed. Prints a
/// warning listing violations when they are allowed.
pub fn enforce(config: &SafetyConfig) -> Result<()> {
    decide(config, &check(config))
}

fn decide(config: &SafetyConfig, violations: &[Violation]) -> Result<()> {
    if violations.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = violations
        .iter()
        .map(|v| format!("  - [{}] {}", v.check, v.detail))
        .collect();
    if config.allow_unsandboxed {
        eprintln!(
            "warning: running builds with secrets reachable (--allow-unsandboxed):\n{}",
            list.join("\n")
        );
        return Ok(());
    }
    bail!(
        "refusing to run builds: dependency build scripts and tests could read these secrets\n{}\n\
         Run mendr in a sandbox/container without them, use --plan-only, or pass \
         --allow-unsandboxed to run anyway.",
        list.join("\n")
    )
}

fn violation(check: &str, detail: String) -> Violation {
    Violation {
        check: check.to_string(),
        detail,
    }
}

/// `~` / `~/x` -> `HOME` / `HOME/x`; anything else unchanged.
fn expand(path: &str, home: Option<&Path>) -> PathBuf {
    match (path.strip_prefix('~'), home) {
        (Some(""), Some(h)) => h.to_path_buf(),
        (Some(rest), Some(h)) if rest.starts_with('/') => h.join(&rest[1..]),
        _ => PathBuf::from(path),
    }
}

/// A file that can be opened or a directory that can be listed.
fn readable(path: &Path) -> bool {
    if path.is_dir() {
        std::fs::read_dir(path).is_ok()
    } else {
        std::fs::File::open(path).is_ok()
    }
}

fn credential_matches(path: &Path, kind: Cred) -> bool {
    match kind {
        Cred::Any => path.is_file() && readable(path),
        Cred::Dir => std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some()),
        Cred::Contains(markers) => {
            std::fs::read_to_string(path).is_ok_and(|text| markers.iter().any(|m| text.contains(m)))
        }
        Cred::DockerConfig => {
            let Ok(text) = std::fs::read_to_string(path) else {
                return false;
            };
            // Unparseable but readable: assume the worst.
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
                return true;
            };
            let non_empty = |key: &str| match json.get(key) {
                Some(serde_json::Value::Object(m)) => !m.is_empty(),
                Some(serde_json::Value::String(s)) => !s.is_empty(),
                _ => false,
            };
            non_empty("auths") || non_empty("credsStore") || non_empty("credHelpers")
        }
    }
}

fn credential_files(env: &Environment, out: &mut Vec<Violation>) {
    let mut found = |path: PathBuf, kind: Cred, what: &str| {
        if credential_matches(&path, kind) {
            out.push(violation(
                "credential-file",
                format!("{} is readable ({what})", path.display()),
            ));
        }
    };
    if let Some(home) = &env.home {
        for (rel, kind, what) in CREDENTIAL_FILES {
            found(home.join(rel), *kind, what);
        }
        // SSH private keys, whatever their name.
        if let Ok(entries) = std::fs::read_dir(home.join(".ssh")) {
            let mut keys: Vec<PathBuf> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file() && is_private_key(p))
                .collect();
            keys.sort();
            for key in keys {
                found(key, Cred::Any, "SSH private key");
            }
        }
    }
    if let Some(dir) = env.var("CARGO_HOME") {
        for name in ["credentials.toml", "credentials"] {
            found(Path::new(dir).join(name), Cred::Any, "Cargo registry token");
        }
    }
    if let Some(dir) = env.var("DOCKER_CONFIG") {
        found(
            Path::new(dir).join("config.json"),
            Cred::DockerConfig,
            "Docker registry credentials",
        );
    }
    if let Some(file) = env.var("NPM_CONFIG_USERCONFIG") {
        found(
            PathBuf::from(file),
            Cred::Contains(&["_auth", "_password"]),
            "npm registry token",
        );
    }
    for (var, what) in CREDENTIAL_FILE_VARS {
        for file in env.var(var).into_iter().flat_map(|v| v.split(':')) {
            if !file.is_empty() {
                found(PathBuf::from(file), Cred::Any, what);
            }
        }
    }
}

/// A file in `~/.ssh` that looks like a private key (by name or header).
fn is_private_key(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(".pub")
        || matches!(
            name,
            "known_hosts" | "known_hosts.old" | "config" | "authorized_keys" | "environment"
        )
    {
        return false;
    }
    if name.starts_with("id_") {
        return true;
    }
    // Read only the start of the file: keys begin with a PEM/OpenSSH header.
    let mut head = [0u8; 64];
    let n = std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read(&mut f, &mut head))
        .unwrap_or(0);
    String::from_utf8_lossy(&head[..n]).contains("PRIVATE KEY")
}

/// Whether an environment variable name looks like it holds a secret:
/// a word (split on non-alphanumerics) ending in `TOKEN`, `SECRET`,
/// `PASSWORD`, `PASSWD`, `CREDENTIAL(S)` or `APIKEY`; a last word `KEY`,
/// `PAT` or `AUTH`; or a well-known credential name (`AWS_ACCESS_KEY_ID`, ...).
pub fn is_secret_var(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if HARMLESS_VARS.contains(&upper.as_str()) {
        return false;
    }
    if matches!(upper.as_str(), "AWS_ACCESS_KEY_ID" | "DOCKER_AUTH_CONFIG") {
        return true;
    }
    let words: Vec<&str> = upper
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let secret_word = |w: &&str| {
        [
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "CREDENTIAL",
            "CREDENTIALS",
            "APIKEY",
        ]
        .iter()
        .any(|s| w.ends_with(s))
    };
    words.iter().any(secret_word) || matches!(words.last(), Some(&("KEY" | "PAT" | "AUTH")))
}

fn secret_vars(env: &Environment, out: &mut Vec<Violation>) {
    for (name, value) in &env.vars {
        if !value.is_empty() && is_secret_var(name) {
            out.push(violation(
                "secret-env",
                format!("environment variable {name} looks like a secret"),
            ));
        }
    }
}

/// Whether a Unix socket at `path` accepts connections.
fn socket_reachable(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

fn sockets(env: &Environment, out: &mut Vec<Violation>) {
    if let Some(sock) = env.var("SSH_AUTH_SOCK")
        && socket_reachable(Path::new(sock))
    {
        out.push(violation(
            "ssh-agent",
            format!("SSH agent socket {sock} is reachable (SSH_AUTH_SOCK)"),
        ));
    }

    let mut candidates: Vec<PathBuf> = env.system_sockets.clone();
    if let Some(home) = &env.home {
        for rel in [
            ".docker/run/docker.sock",
            ".colima/default/docker.sock",
            ".rd/docker.sock",
        ] {
            candidates.push(home.join(rel));
        }
    }
    if let Some(dir) = env.var("XDG_RUNTIME_DIR") {
        candidates.push(Path::new(dir).join("docker.sock"));
        candidates.push(Path::new(dir).join("podman/podman.sock"));
    }
    if let Some(host) = env.var("DOCKER_HOST") {
        match host.strip_prefix("unix://") {
            Some(path) => candidates.push(PathBuf::from(path)),
            None => out.push(violation(
                "docker-socket",
                format!("DOCKER_HOST={host} points to a container daemon"),
            )),
        }
    }
    for path in candidates {
        if socket_reachable(&path) {
            out.push(violation(
                "docker-socket",
                format!(
                    "container daemon socket {} is reachable (builds could start privileged containers)",
                    path.display()
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(home: &Path, vars: &[(&str, &str)]) -> Environment {
        Environment {
            home: Some(home.to_path_buf()),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            system_sockets: Vec::new(),
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn checks(v: &[Violation]) -> Vec<&str> {
        v.iter().map(|v| v.check.as_str()).collect()
    }

    #[test]
    fn clean_environment_passes() {
        let home = tempfile::tempdir().unwrap();
        let e = env(
            home.path(),
            &[
                ("PATH", "/usr/bin"),
                ("HOME", "/h"),
                ("TOKENIZERS_PARALLELISM", "false"),
                ("GITHUB_TOKEN", ""),
            ],
        );
        assert_eq!(check_with(&SafetyConfig::default(), &e), vec![]);
        // Harmless files in the usual places.
        write(
            &home.path().join(".npmrc"),
            "registry=https://example.org/\n",
        );
        write(&home.path().join(".docker/config.json"), r#"{"auths": {}}"#);
        write(&home.path().join(".ssh/id_ed25519.pub"), "ssh-ed25519 AAAA");
        write(&home.path().join(".ssh/known_hosts"), "host key");
        std::fs::create_dir_all(home.path().join(".aws/sso/cache")).unwrap();
        assert_eq!(check_with(&SafetyConfig::default(), &e), vec![]);
    }

    #[test]
    fn credential_files_are_reported() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        write(&h.join(".ssh/id_ed25519"), "whatever");
        write(
            &h.join(".ssh/deploy"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        );
        write(&h.join(".aws/credentials"), "[default]\n");
        write(&h.join(".npmrc"), "//registry.npmjs.org/:_authToken=x\n");
        write(
            &h.join(".docker/config.json"),
            r#"{"credsStore": "desktop"}"#,
        );
        write(&h.join(".config/gh/hosts.yml"), "github.com:\n");
        let cargo_home = h.join("cargo-home");
        write(&cargo_home.join("credentials.toml"), "[registry]\n");
        let gcloud = h.join("sa.json");
        write(&gcloud, "{}");

        let e = env(
            h,
            &[
                ("CARGO_HOME", cargo_home.to_str().unwrap()),
                ("GOOGLE_APPLICATION_CREDENTIALS", gcloud.to_str().unwrap()),
            ],
        );
        let v = check_with(&SafetyConfig::default(), &e);
        let details: Vec<&str> = v.iter().map(|v| v.detail.as_str()).collect();
        let expect = [
            ".ssh/id_ed25519 is readable (SSH private key)",
            ".ssh/deploy is readable (SSH private key)",
            ".aws/credentials is readable (AWS credentials)",
            ".npmrc is readable (npm registry token)",
            ".docker/config.json is readable (Docker registry credentials)",
            ".config/gh/hosts.yml is readable (GitHub CLI credentials)",
            "cargo-home/credentials.toml is readable (Cargo registry token)",
            "sa.json is readable (Google Cloud credentials)",
        ];
        for e in expect {
            assert!(
                details.iter().any(|d| d.ends_with(e)),
                "missing {e:?} in {details:#?}"
            );
        }
        // GOOGLE_APPLICATION_CREDENTIALS is also reported as a secret-looking var.
        assert_eq!(v.len(), expect.len() + 1, "{details:#?}");
        assert!(checks(&v).iter().all(|c| *c != "docker-socket"));
    }

    #[test]
    fn secret_variable_names() {
        for name in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "NPM_TOKEN",
            "NODE_AUTH_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_MY_REG_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "ANTHROPIC_API_KEY",
            "DB_PASSWORD",
            "MYSQL_ROOT_PASSWORD",
            "PGPASSWORD",
            "AZURE_CLIENT_SECRET",
            "GITHUB_PAT",
            "npm_config_//registry.npmjs.org/:_authToken",
            "NPM_CONFIG__AUTH",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ] {
            assert!(is_secret_var(name), "{name} should be flagged");
        }
        for name in [
            "PATH",
            "HOME",
            "TOKENIZERS_PARALLELISM",
            "AWS_REGION",
            "AWS_PROFILE",
            "SSH_AUTH_SOCK",
            "KEYBOARD_LAYOUT",
            "PASSWORD_STORE_DIR",
            "NIX_SSL_CERT_FILE",
            "SECRETS_DIR",
        ] {
            assert!(!is_secret_var(name), "{name} should not be flagged");
        }

        let home = tempfile::tempdir().unwrap();
        let v = check_with(
            &SafetyConfig::default(),
            &env(
                home.path(),
                &[("NPM_TOKEN", "npm_abc123"), ("PATH", "/bin")],
            ),
        );
        assert_eq!(
            v,
            vec![violation(
                "secret-env",
                "environment variable NPM_TOKEN looks like a secret".into()
            )]
        );
        assert!(!v[0].detail.contains("npm_abc123"), "never print values");
    }

    #[test]
    fn sockets_are_reported_when_reachable() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("d.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        // Not a listening socket. (A bound-then-dropped listener can stay
        // alive in a child forked concurrently by another test on macOS.)
        let stale = home.path().join("stale.sock");
        write(&stale, "");

        let mut e = env(
            home.path(),
            &[
                ("DOCKER_HOST", &format!("unix://{}", sock.display())),
                ("SSH_AUTH_SOCK", sock.to_str().unwrap()),
            ],
        );
        e.system_sockets = vec![stale.clone(), home.path().join("missing.sock")];
        let v = check_with(&SafetyConfig::default(), &e);
        assert_eq!(checks(&v), vec!["ssh-agent", "docker-socket"], "{v:#?}");

        let e = env(home.path(), &[("DOCKER_HOST", "tcp://10.0.0.1:2375")]);
        let v = check_with(&SafetyConfig::default(), &e);
        assert_eq!(checks(&v), vec!["docker-socket"]);
        assert!(v[0].detail.contains("tcp://10.0.0.1:2375"));
    }

    #[test]
    fn deny_paths_expand_home() {
        let home = tempfile::tempdir().unwrap();
        write(&home.path().join("secrets/key"), "x");
        let config = SafetyConfig {
            allow_unsandboxed: false,
            deny_paths: vec![
                "~/secrets".into(),
                "~/missing".into(),
                home.path().join("secrets/key").display().to_string(),
            ],
        };
        let v = check_with(&config, &env(home.path(), &[]));
        assert_eq!(checks(&v), vec!["deny-path", "deny-path"]);
        assert!(v[0].detail.contains("secrets is readable"), "{v:#?}");
        assert_eq!(expand("~", Some(Path::new("/h"))), PathBuf::from("/h"));
        assert_eq!(expand("~x", Some(Path::new("/h"))), PathBuf::from("~x"));
        assert_eq!(expand("~/a", None), PathBuf::from("~/a"));
    }

    #[test]
    fn decide_refuses_unless_allowed() {
        let v = vec![violation(
            "secret-env",
            "environment variable X_TOKEN looks like a secret".into(),
        )];
        let mut config = SafetyConfig::default();
        assert!(decide(&config, &[]).is_ok());
        let err = decide(&config, &v).unwrap_err().to_string();
        assert!(
            err.contains("[secret-env] environment variable X_TOKEN"),
            "{err}"
        );
        assert!(err.contains("--allow-unsandboxed"), "{err}");
        config.allow_unsandboxed = true;
        assert!(decide(&config, &v).is_ok());
    }
}
