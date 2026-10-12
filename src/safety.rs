//! Safety checks run before any build/test command.
//!
//! Builds and tests execute untrusted code (build scripts, test suites,
//! install hooks of new dependency versions). mendr refuses to run them when
//! secrets are reachable, unless `--allow-secrets` /
//! `[safety] allow-secrets = true`.
//!
//! Isolation cannot be proven from inside, so the checks look for *danger*:
//! - credential files readable under `HOME` (SSH private keys, also in
//!   subfolders of `~/.ssh`, cloud, registry and Git credentials, see
//!   [`CREDENTIAL_FILES`]) or named by environment variables (`CARGO_HOME`,
//!   `DOCKER_CONFIG`, `KUBECONFIG`, `XDG_CONFIG_HOME`, ...);
//! - a Git credential helper in the system/global Git config (a build can
//!   ask it for tokens with `git credential fill`);
//! - secret-looking environment variables (see [`is_secret_var`]) and
//!   variables whose value holds a URL with a password
//!   (`scheme://user:pass@host`); values are never printed;
//! - an SSH agent (`SSH_AUTH_SOCK`) that holds identities or does not answer
//!   the identity query, and reachable Docker/Podman sockets
//!   (`/var/run/docker.sock`, `$DOCKER_HOST`, rootless sockets under
//!   `$XDG_RUNTIME_DIR`, Docker Desktop/OrbStack/Colima/Lima/Rancher/Podman
//!   machine sockets, Docker context endpoints);
//! - every path in `SafetyConfig::deny_paths` (`~/` expanded) that is readable;
//! - in the project itself ([`check_project`]; these files are copied into
//!   the temp copy): an `.npmrc`/`.yarnrc.yml` with a registry token and
//!   `.env` / `.env.*` files.
//!
//! With `--sandbox` builds run in a container that sees none of the host
//! ([`crate::sandbox`]), so only the project checks run
//! ([`enforce_project`]).
//!
//! Fixture tests run mendr with `HOME` set to an empty temp dir and a
//! cleared environment, so the checks pass there without the flag.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};

use crate::config::SafetyConfig;

/// One failed safety check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Violation {
    /// Short check id: `"credential-file"`, `"git-credential-helper"`,
    /// `"secret-env"`, `"ssh-agent"`, `"docker-socket"`, `"deny-path"`,
    /// `"project-file"`.
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
    /// Git config keys (`credential.helper`, `credential.<url>.helper`)
    /// that set a credential helper, from [`git_credential_helpers`].
    pub git_credential_helpers: Vec<String>,
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
            git_credential_helpers: git_credential_helpers(),
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
    /// An npm-style rc file: dangerous if a `_auth*` / `_password` key has a
    /// value other than a `${VAR}` reference to an unset variable.
    NpmAuth,
}

/// Credential files relative to `HOME`, with a short description.
const CREDENTIAL_FILES: &[(&str, Cred, &str)] = &[
    (".aws/credentials", Cred::Any, "AWS credentials"),
    (".aws/sso/cache", Cred::Dir, "AWS SSO tokens"),
    (".cargo/credentials.toml", Cred::Any, "Cargo registry token"),
    (".cargo/credentials", Cred::Any, "Cargo registry token"),
    (".npmrc", Cred::NpmAuth, "npm registry token"),
    (".yarnrc.yml", Cred::Contains(&["npmAuth"]), "Yarn token"),
    (".config/pnpm/rc", Cred::NpmAuth, "pnpm registry token"),
    (
        "Library/Preferences/pnpm/rc",
        Cred::NpmAuth,
        "pnpm registry token",
    ),
    (".config/git/credentials", Cred::Any, "Git credentials"),
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

/// How long to wait for an SSH agent's answer.
const AGENT_TIMEOUT: Duration = Duration::from_secs(1);

/// Run all environment checks against `env`.
pub fn check_with(config: &SafetyConfig, env: &Environment) -> Vec<Violation> {
    let mut out = Vec::new();
    credential_files(env, &mut out);
    git_helpers(env, &mut out);
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

/// Checks on the project directory `dir`, whose files are copied into the
/// temp copy where builds run: registry tokens in its `.npmrc` /
/// `.yarnrc.yml` and `.env` / `.env.*` files (except `.example`,
/// `.sample`, `.template`).
pub fn check_project(dir: &Path, env: &Environment) -> Vec<Violation> {
    let mut out = Vec::new();
    for (name, kind, what) in [
        (".npmrc", Cred::NpmAuth, "an npm registry token"),
        (".yarnrc.yml", Cred::Contains(&["npmAuth"]), "a Yarn token"),
    ] {
        let path = dir.join(name);
        if credential_matches(&path, kind, env) {
            out.push(violation(
                "project-file",
                format!(
                    "{} holds {what} (copied into the build's temp copy)",
                    path.display()
                ),
            ));
        }
    }
    let mut env_files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_env_file)
        })
        .filter(|p| p.is_file() && readable(p))
        .collect();
    env_files.sort();
    for path in env_files {
        out.push(violation(
            "project-file",
            format!(
                "{} may hold secrets (copied into the build's temp copy)",
                path.display()
            ),
        ));
    }
    out
}

/// `.env`, `.env.local`, `.env.production`, ... but not templates.
fn is_env_file(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && ![".example", ".sample", ".template"]
            .iter()
            .any(|s| name.ends_with(s))
}

/// Fail unless the environment checks and the checks on `project` are
/// clean or reachable secrets are allowed (`allow-secrets`). Prints a warning listing
/// violations when they are allowed.
pub fn enforce(config: &SafetyConfig, project: &Path) -> Result<()> {
    let env = Environment::current();
    let mut violations = check_with(config, &env);
    violations.extend(check_project(project, &env));
    decide(
        config,
        &violations,
        "Run mendr with --sandbox (see [sandbox] in mendr.toml) or somewhere without them, \
         use --plan-only, or pass --allow-secrets to run anyway.",
    )
}

/// [`enforce`] for `--sandbox` runs: only [`check_project`], since its
/// files are copied into the container.
pub fn enforce_project(config: &SafetyConfig, project: &Path) -> Result<()> {
    decide(
        config,
        &check_project(project, &Environment::current()),
        "They are copied into the sandbox: remove them from the project, use --plan-only, \
         or pass --allow-secrets to run anyway.",
    )
}

fn decide(config: &SafetyConfig, violations: &[Violation], hint: &str) -> Result<()> {
    if violations.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = violations
        .iter()
        .map(|v| format!("  - [{}] {}", v.check, v.detail))
        .collect();
    if config.allow_secrets {
        crate::progress::warn(format!(
            "running builds with secrets reachable (--allow-secrets):\n{}",
            list.join("\n")
        ));
        return Ok(());
    }
    bail!(
        "refusing to run builds: dependency build scripts and tests could read these secrets\n{}\n{hint}",
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

fn credential_matches(path: &Path, kind: Cred, env: &Environment) -> bool {
    match kind {
        Cred::Any => path.is_file() && readable(path),
        Cred::Dir => std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some()),
        Cred::Contains(markers) => {
            std::fs::read_to_string(path).is_ok_and(|text| markers.iter().any(|m| text.contains(m)))
        }
        Cred::NpmAuth => std::fs::read_to_string(path).is_ok_and(|text| npmrc_has_auth(&text, env)),
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

/// Whether npm rc text sets `_auth`, `_authToken`, `_password` (any
/// registry scope) to a value. A bare `${VAR}` value counts only if `VAR`
/// is set; the token then lives in the environment.
fn npmrc_has_auth(text: &str, env: &Environment) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let (key, value) = (key.trim(), value.trim().trim_matches('"'));
        if !(key.contains("_auth") || key.contains("_password")) || value.is_empty() {
            return false;
        }
        match value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
            Some(var) if !var.contains(['$', '{', '}']) => env.var(var).is_some(),
            _ => true,
        }
    })
}

fn credential_files(env: &Environment, out: &mut Vec<Violation>) {
    let mut found = |path: PathBuf, kind: Cred, what: &str| {
        if credential_matches(&path, kind, env) {
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
        // SSH private keys, whatever their name, also in subfolders.
        let mut keys = Vec::new();
        ssh_keys(&home.join(".ssh"), 3, &mut keys);
        keys.sort();
        for key in keys {
            found(key, Cred::Any, "SSH private key");
        }
    }
    if let Some(dir) = env.var("XDG_CONFIG_HOME") {
        found(
            Path::new(dir).join("git/credentials"),
            Cred::Any,
            "Git credentials",
        );
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
        found(PathBuf::from(file), Cred::NpmAuth, "npm registry token");
    }
    for (var, what) in CREDENTIAL_FILE_VARS {
        for file in env.var(var).into_iter().flat_map(|v| v.split(':')) {
            if !file.is_empty() {
                found(PathBuf::from(file), Cred::Any, what);
            }
        }
    }
}

/// Private keys in `dir` and its subdirectories, up to `depth` levels
/// (symlinked directories are not followed).
fn ssh_keys(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            if depth > 0 {
                ssh_keys(&path, depth - 1, out);
            }
        } else if path.is_file() && is_private_key(&path) {
            out.push(path);
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
        if value.is_empty() {
            continue;
        }
        if is_secret_var(name) {
            out.push(violation(
                "secret-env",
                format!("environment variable {name} looks like a secret"),
            ));
        } else if has_url_credentials(value) {
            out.push(violation(
                "secret-env",
                format!("environment variable {name} holds a URL with a password"),
            ));
        }
    }
}

/// Whether `value` contains a URL with a password: `scheme://user:pass@host`
/// (the user may be empty).
fn has_url_credentials(value: &str) -> bool {
    let mut rest = value;
    while let Some(i) = rest.find("://") {
        rest = &rest[i + 3..];
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
            .unwrap_or(rest.len());
        let authority = &rest[..end];
        if let Some((userinfo, _host)) = authority.rsplit_once('@')
            && userinfo
                .split_once(':')
                .is_some_and(|(_, pass)| !pass.is_empty())
        {
            return true;
        }
    }
    false
}

/// Keys of the Git config (system, global, `GIT_CONFIG_*`; not a repo's
/// own config) that set a credential helper: `credential.helper` or
/// `credential.<url>.helper` with a non-empty last value (an empty value
/// resets the list). Empty when Git is not installed.
pub fn git_credential_helpers() -> Vec<String> {
    let output = std::process::Command::new("git")
        .args([
            "config",
            "--null",
            "--get-regexp",
            r"^credential\..*helper$",
        ])
        // Outside any repository, so only system/global config counts.
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    match output {
        Ok(o) => parse_git_helpers(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

/// Parse `git config --null --get-regexp` output (`key\nvalue\0` entries).
fn parse_git_helpers(output: &str) -> Vec<String> {
    let mut set: BTreeMap<String, bool> = BTreeMap::new();
    for entry in output.split('\0').filter(|e| !e.is_empty()) {
        let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
        set.insert(key.to_string(), !value.trim().is_empty());
    }
    set.into_iter()
        .filter(|(_, on)| *on)
        .map(|(key, _)| key)
        .collect()
}

fn git_helpers(env: &Environment, out: &mut Vec<Violation>) {
    for key in &env.git_credential_helpers {
        out.push(violation(
            "git-credential-helper",
            format!(
                "Git config sets {key}; builds can get stored tokens with `git credential fill`"
            ),
        ));
    }
}

/// Whether a Unix socket at `path` accepts connections.
fn socket_reachable(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// What an SSH agent socket says when asked for its identities.
#[derive(Debug, PartialEq, Eq)]
enum Agent {
    /// Nothing accepts connections there.
    Unreachable,
    /// The agent holds this many identities.
    Identities(u32),
    /// Reachable, but no usable answer (timeout, refusal, garbage).
    Unclear(String),
}

/// Ask the agent at `path` for its identities (SSH agent protocol:
/// `SSH2_AGENTC_REQUEST_IDENTITIES` = 11, answered by
/// `SSH2_AGENT_IDENTITIES_ANSWER` = 12 with a key count).
fn query_agent(path: &Path, timeout: Duration) -> Agent {
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(path) else {
        return Agent::Unreachable;
    };
    let mut ask = || -> std::io::Result<Agent> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(&[0, 0, 0, 1, 11])?;
        let mut head = [0u8; 5]; // length + message type
        stream.read_exact(&mut head)?;
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if head[4] != 12 || len < 5 {
            return Ok(Agent::Unclear(format!(
                "unexpected answer type {}",
                head[4]
            )));
        }
        let mut count = [0u8; 4];
        stream.read_exact(&mut count)?;
        Ok(Agent::Identities(u32::from_be_bytes(count)))
    };
    ask().unwrap_or_else(|e| Agent::Unclear(e.to_string()))
}

/// Subdirectories of `dir` (sorted; none if it cannot be listed).
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

/// Endpoints of the Docker CLI contexts in `<config>/contexts/meta/*/meta.json`:
/// `(context name, docker host)`.
fn docker_contexts(config_dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for dir in subdirs(&config_dir.join("contexts/meta")) {
        let Ok(text) = std::fs::read_to_string(dir.join("meta.json")) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let name = json["Name"].as_str().unwrap_or("?").to_string();
        if let Some(host) = json["Endpoints"]["docker"]["Host"].as_str()
            && !host.is_empty()
        {
            out.push((name, host.to_string()));
        }
    }
    out
}

fn sockets(env: &Environment, out: &mut Vec<Violation>) {
    if let Some(sock) = env.var("SSH_AUTH_SOCK") {
        // launchd always provides an agent on macOS: only one that holds
        // keys (or does not answer clearly) is a danger.
        let problem = match query_agent(Path::new(sock), AGENT_TIMEOUT) {
            Agent::Unreachable | Agent::Identities(0) => None,
            Agent::Identities(n) => Some(format!("holds {n} identities")),
            Agent::Unclear(why) => Some(format!(
                "is reachable and did not answer the identity query ({why})"
            )),
        };
        if let Some(problem) = problem {
            out.push(violation(
                "ssh-agent",
                format!("SSH agent socket {sock} {problem} (SSH_AUTH_SOCK)"),
            ));
        }
    }

    let mut candidates: Vec<PathBuf> = env.system_sockets.clone();
    let mut docker_hosts: Vec<(String, String)> = Vec::new();
    if let Some(home) = &env.home {
        for rel in [
            ".docker/run/docker.sock",
            ".orbstack/run/docker.sock",
            ".rd/docker.sock",
            ".local/share/containers/podman/machine/podman.sock",
            "Library/Containers/com.docker.docker/Data/docker.raw.sock",
        ] {
            candidates.push(home.join(rel));
        }
        for profile in subdirs(&home.join(".colima")) {
            candidates.push(profile.join("docker.sock"));
        }
        for vm in subdirs(&home.join(".lima")) {
            candidates.push(vm.join("sock/docker.sock"));
        }
        for machine in subdirs(&home.join(".local/share/containers/podman/machine")) {
            candidates.push(machine.join("podman.sock"));
        }
    }
    let docker_config = match (env.var("DOCKER_CONFIG"), &env.home) {
        (Some(dir), _) => Some(PathBuf::from(dir)),
        (None, Some(home)) => Some(home.join(".docker")),
        (None, None) => None,
    };
    if let Some(dir) = docker_config {
        for (name, host) in docker_contexts(&dir) {
            docker_hosts.push((format!("Docker context `{name}`"), host));
        }
    }
    if let Some(dir) = env.var("TMPDIR") {
        // Podman 5 machine API sockets on macOS.
        let dir = Path::new(dir).join("podman");
        let mut socks: Vec<PathBuf> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "sock"))
            .collect();
        socks.sort();
        candidates.extend(socks);
    }
    if let Some(dir) = env.var("XDG_RUNTIME_DIR") {
        candidates.push(Path::new(dir).join("docker.sock"));
        candidates.push(Path::new(dir).join("podman/podman.sock"));
    }
    if let Some(host) = env.var("DOCKER_HOST") {
        docker_hosts.push(("DOCKER_HOST".into(), host.to_string()));
    }
    for (source, host) in docker_hosts {
        match host.strip_prefix("unix://") {
            Some(path) => candidates.push(PathBuf::from(path)),
            None if source == "DOCKER_HOST" => out.push(violation(
                "docker-socket",
                format!("DOCKER_HOST={host} points to a container daemon"),
            )),
            None => out.push(violation(
                "docker-socket",
                format!("{source} points to a container daemon at {host}"),
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
            git_credential_helpers: Vec::new(),
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
            &h.join(".config/pnpm/rc"),
            "//registry.npmjs.org/:_authToken=x\n",
        );
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
            ".config/pnpm/rc is readable (pnpm registry token)",
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

        let agent = fake_agent(home.path(), "agent.sock", vec![0, 0, 0, 5, 12, 0, 0, 0, 1]);

        let mut e = env(
            home.path(),
            &[
                ("DOCKER_HOST", &format!("unix://{}", sock.display())),
                ("SSH_AUTH_SOCK", agent.to_str().unwrap()),
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

    /// A fake SSH agent at `dir/name` that answers every identity request
    /// with `answer`.
    fn fake_agent(dir: &Path, name: &str, answer: Vec<u8>) -> PathBuf {
        let path = dir.join(name);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut request = [0u8; 5];
                if s.read_exact(&mut request).is_ok() && request == [0, 0, 0, 1, 11] {
                    let _ = s.write_all(&answer);
                }
            }
        });
        path
    }

    #[test]
    fn ssh_agent_counts_only_with_identities() {
        let dir = tempfile::tempdir().unwrap();
        let none = fake_agent(dir.path(), "none.sock", vec![0, 0, 0, 5, 12, 0, 0, 0, 0]);
        let two = fake_agent(dir.path(), "two.sock", vec![0, 0, 0, 5, 12, 0, 0, 0, 2]);
        let refuses = fake_agent(dir.path(), "refuses.sock", vec![0, 0, 0, 1, 5]);
        let t = Duration::from_secs(5);
        assert_eq!(query_agent(&none, t), Agent::Identities(0));
        assert_eq!(query_agent(&two, t), Agent::Identities(2));
        assert!(matches!(query_agent(&refuses, t), Agent::Unclear(_)));
        assert_eq!(
            query_agent(&dir.path().join("missing.sock"), t),
            Agent::Unreachable
        );
        // Accepts connections but never answers.
        let silent = dir.path().join("silent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&silent).unwrap();
        assert!(matches!(
            query_agent(&silent, Duration::from_millis(100)),
            Agent::Unclear(_)
        ));

        let ssh = |sock: &Path| {
            let e = env(dir.path(), &[("SSH_AUTH_SOCK", sock.to_str().unwrap())]);
            check_with(&SafetyConfig::default(), &e)
        };
        assert_eq!(ssh(&none), vec![], "launchd's empty agent is fine");
        let v = ssh(&two);
        assert_eq!(checks(&v), vec!["ssh-agent"]);
        assert!(v[0].detail.contains("holds 2 identities"), "{v:#?}");
        let v = ssh(&refuses);
        assert!(v[0].detail.contains("did not answer"), "{v:#?}");
    }

    #[test]
    fn git_credential_helpers_are_reported() {
        let output = "credential.helper\nosxkeychain\0\
                      credential.https://a.example.helper\nstore\0\
                      credential.helper\n\0\
                      credential.https://b.example.helper\n!f() { echo password=hunter2; }; f\0";
        assert_eq!(
            parse_git_helpers(output),
            vec![
                "credential.https://a.example.helper",
                "credential.https://b.example.helper"
            ]
        );
        assert_eq!(parse_git_helpers(""), Vec::<String>::new());

        let home = tempfile::tempdir().unwrap();
        let mut e = env(home.path(), &[]);
        e.git_credential_helpers = parse_git_helpers(output);
        let v = check_with(&SafetyConfig::default(), &e);
        assert_eq!(
            checks(&v),
            vec!["git-credential-helper", "git-credential-helper"]
        );
        assert!(v.iter().all(|v| !v.detail.contains("hunter2")), "{v:#?}");
    }

    #[test]
    fn url_credentials_in_values() {
        for yes in [
            "postgres://user:pass@db/app",
            "https://:token@github.com/x.git",
            "a http://u:p@proxy:3128 b",
            "https://example.org https://u:p@h",
        ] {
            assert!(has_url_credentials(yes), "{yes}");
        }
        for no in [
            "https://user@host/x",
            "https://host/path:x@y",
            "http://proxy:3128",
            "u:p@host",
            "https://u:@host",
            "",
        ] {
            assert!(!has_url_credentials(no), "{no}");
        }
        let home = tempfile::tempdir().unwrap();
        let e = env(
            home.path(),
            &[
                ("DATABASE_URL", "postgres://app:s3cr3t@db/app"),
                ("REGISTRY", "https://registry.example.org/"),
            ],
        );
        let v = check_with(&SafetyConfig::default(), &e);
        assert_eq!(
            v,
            vec![violation(
                "secret-env",
                "environment variable DATABASE_URL holds a URL with a password".into()
            )]
        );
    }

    #[test]
    fn project_files_are_reported() {
        let project = tempfile::tempdir().unwrap();
        let p = project.path();
        let home = tempfile::tempdir().unwrap();
        let e = env(home.path(), &[]);
        write(&p.join(".npmrc"), "registry=https://example.org/\n");
        write(&p.join(".env.example"), "TOKEN=\n");
        write(&p.join(".envrc"), "use flake\n");
        assert_eq!(check_project(p, &e), vec![]);

        // A reference to an unset variable is not a token.
        write(
            &p.join(".npmrc"),
            "//npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n",
        );
        assert_eq!(check_project(p, &e), vec![]);
        let with_token = env(home.path(), &[("NPM_TOKEN", "x")]);
        assert_eq!(checks(&check_project(p, &with_token)), vec!["project-file"]);

        write(&p.join(".npmrc"), "//registry.npmjs.org/:_authToken=abc\n");
        write(&p.join(".env"), "SECRET=1\n");
        write(&p.join(".env.local"), "SECRET=2\n");
        let v = check_project(p, &e);
        let details: Vec<&str> = v.iter().map(|v| v.detail.as_str()).collect();
        assert_eq!(details.len(), 3, "{details:#?}");
        assert!(details[0].contains(".npmrc holds an npm registry token"));
        assert!(details[1].contains("/.env may hold secrets"));
        assert!(details[2].contains("/.env.local may hold secrets"));
    }

    #[test]
    fn more_credential_and_socket_locations() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        write(&h.join(".ssh/work/id_rsa"), "x");
        write(
            &h.join(".ssh/keys/deep/deploy"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        );
        write(&h.join(".ssh/config.d/work"), "Host x\n");
        write(&h.join(".config/git/credentials"), "https://u:p@h\n");
        let xdg = h.join("xdg");
        write(&xdg.join("git/credentials"), "https://u:p@h\n");
        let mut socks = Vec::new();
        for rel in [
            ".orbstack/run/docker.sock",
            ".lima/default/sock/docker.sock",
            ".colima/work/docker.sock",
        ] {
            std::fs::create_dir_all(h.join(rel).parent().unwrap()).unwrap();
            socks.push(std::os::unix::net::UnixListener::bind(h.join(rel)).unwrap());
        }
        let ctx_sock = h.join("ctx.sock");
        socks.push(std::os::unix::net::UnixListener::bind(&ctx_sock).unwrap());
        write(
            &h.join(".docker/contexts/meta/abc/meta.json"),
            &format!(
                r#"{{"Name":"local","Endpoints":{{"docker":{{"Host":"unix://{}"}}}}}}"#,
                ctx_sock.display()
            ),
        );
        write(
            &h.join(".docker/contexts/meta/def/meta.json"),
            r#"{"Name":"remote","Endpoints":{"docker":{"Host":"tcp://10.0.0.2:2376"}}}"#,
        );

        let e = env(h, &[("XDG_CONFIG_HOME", xdg.to_str().unwrap())]);
        let v = check_with(&SafetyConfig::default(), &e);
        let details: Vec<&str> = v.iter().map(|v| v.detail.as_str()).collect();
        for expect in [
            ".ssh/work/id_rsa is readable (SSH private key)",
            ".ssh/keys/deep/deploy is readable (SSH private key)",
            ".config/git/credentials is readable (Git credentials)",
            "xdg/git/credentials is readable (Git credentials)",
            "Docker context `remote` points to a container daemon at tcp://10.0.0.2:2376",
        ] {
            assert!(
                details.iter().any(|d| d.contains(expect)),
                "missing {expect:?} in {details:#?}"
            );
        }
        for sock in [
            ".orbstack/run/docker.sock",
            ".lima/default/sock/docker.sock",
            ".colima/work/docker.sock",
            "ctx.sock",
        ] {
            assert!(
                details
                    .iter()
                    .any(|d| d.contains(sock) && d.contains("is reachable")),
                "missing {sock} in {details:#?}"
            );
        }
        assert!(
            !details.iter().any(|d| d.contains("config.d")),
            "{details:#?}"
        );
        assert_eq!(v.len(), 9, "{details:#?}");
    }

    #[test]
    fn deny_paths_expand_home() {
        let home = tempfile::tempdir().unwrap();
        write(&home.path().join("secrets/key"), "x");
        let config = SafetyConfig {
            allow_secrets: false,
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
        assert!(decide(&config, &[], "hint").is_ok());
        let err = decide(&config, &v, "Pass --allow-secrets.")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("[secret-env] environment variable X_TOKEN"),
            "{err}"
        );
        assert!(err.contains("--allow-secrets"), "{err}");
        config.allow_secrets = true;
        assert!(decide(&config, &v, "hint").is_ok());
    }
}
