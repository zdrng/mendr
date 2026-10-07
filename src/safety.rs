//! Safety checks run before any build/test command (M3).
//!
//! Builds and tests execute untrusted code (build scripts, test suites,
//! install hooks of new dependency versions). mendr refuses to run them when
//! secrets are reachable, unless `--allow-unsandboxed` /
//! `[safety] allow-unsandboxed = true`.
//!
//! TODO(M3): implement [`check`]. Intended checks:
//! - credential files readable: `~/.ssh/id_*`, `~/.aws/credentials`,
//!   `~/.config/gcloud`, `~/.docker/config.json`, `~/.npmrc` with tokens,
//!   `$CARGO_HOME/credentials.toml`, `~/.netrc`, `~/.git-credentials`, ...;
//! - secret-looking environment variables (`*_TOKEN`, `*_SECRET`,
//!   `*_PASSWORD`, `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`, ...);
//! - Docker socket reachable (`/var/run/docker.sock`, `$DOCKER_HOST`);
//! - every path in `SafetyConfig::deny_paths` (`~/` expanded) readable.
//!
//! Fixture tests run mendr with `HOME` set to an empty temp dir and a
//! cleared environment, so the checks pass there without the flag.

use anyhow::{Result, bail};

use crate::config::SafetyConfig;

/// One failed safety check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Short check id, e.g. `"credential-file"`, `"secret-env"`, `"docker-socket"`.
    pub check: String,
    /// What was found, e.g. the path or variable name (never the secret value).
    pub detail: String,
}

/// Run all checks against the current process environment.
// TODO(M3): real checks; this stub reports nothing.
pub fn check(_config: &SafetyConfig) -> Vec<Violation> {
    Vec::new()
}

/// Fail unless `check` is clean or unsandboxed runs are allowed. Prints a
/// warning listing violations when they are allowed.
pub fn enforce(config: &SafetyConfig) -> Result<()> {
    let violations = check(config);
    if violations.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = violations
        .iter()
        .map(|v| format!("  - {}: {}", v.check, v.detail))
        .collect();
    if config.allow_unsandboxed {
        eprintln!(
            "warning: running builds with secrets reachable (--allow-unsandboxed):\n{}",
            list.join("\n")
        );
        return Ok(());
    }
    bail!(
        "refusing to run builds: secrets are reachable from this environment\n{}\n\
         Run mendr in a sandbox/container, use --plan-only, or pass --allow-unsandboxed.",
        list.join("\n")
    )
}
