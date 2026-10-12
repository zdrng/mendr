//! `--sandbox`: run install/build/test in a throwaway container.
//!
//! Each command gets a fresh `docker run --rm` / `podman run --rm` (see
//! [`Sandbox::command`]) that sees only two host directories, mounted at
//! the same paths as on the host (absolute symlinks in the copy keep
//! working):
//! - the project copy (working directory);
//! - `HOME`: a temp dir kept for one project's whole verification, so tool
//!   caches (npm, pnpm, Cargo registry via [`Ecosystem::sandbox_env`])
//!   outlive a single command. Removed when the [`Sandbox`] is dropped.
//!
//! Nothing else from the host gets in: no environment variables, no other
//! files, no sockets. The command runs as the invoking user (Docker:
//! `--user uid:gid`; Podman: `--userns=keep-id`, i.e. rootless Podman), so
//! files it writes into the copy can be removed afterwards, with all
//! capabilities dropped. The network stays on (installs need registries).
//!
//! When `sh` exits the container stops, which kills anything it left
//! running in the background. The engine CLI forwards Ctrl-C to the
//! container (`--init` passes it on to `sh`); on a timeout or interrupt
//! [`Sandbox::kill`] removes the container, because killing the CLI alone
//! does not stop it.
//!
//! Scanning, planning, graph resolution and `--write` stay on the host: they
//! run no project or dependency code.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

use crate::config::{Engine, SandboxConfig};
use crate::ecosystem::Ecosystem;
use crate::model::log_tail;

/// Label on every container mendr starts (`docker ps --filter label=mendr`).
const LABEL: &str = "mendr";
/// File [`Sandbox::check`] looks for inside the container.
const PROBE: &str = ".mendr-probe";

pub struct Sandbox {
    engine: Engine,
    image: String,
    /// `HOME` in the container.
    home: TempDir,
    /// [`Ecosystem::sandbox_env`] with paths joined onto `home`.
    env: Vec<(String, PathBuf)>,
}

impl Sandbox {
    /// Create the sandbox `HOME` for one project. Runs nothing yet.
    pub fn new(config: &SandboxConfig, eco: &dyn Ecosystem) -> Result<Sandbox> {
        let home = tempfile::Builder::new()
            .prefix("mendr-home-")
            .tempdir()
            .context("creating the sandbox HOME")?;
        let env = eco
            .sandbox_env()
            .iter()
            .map(|(k, rel)| (k.to_string(), home.path().join(rel)))
            .collect();
        Ok(Sandbox {
            engine: config.engine,
            image: config.image.clone(),
            home,
            env,
        })
    }

    pub fn describe(&self) -> String {
        format!("{} {}", self.engine.program(), self.image)
    }

    /// Run a trivial command the way [`command`](Self::command) runs real
    /// ones: fails if the engine is missing or not running, the image cannot
    /// be pulled, or the temp dir is not visible in the container (macOS:
    /// not shared with the engine's VM). Pulls the image if needed.
    pub fn check(&self) -> Result<()> {
        let home = self.home.path();
        std::fs::write(home.join(PROBE), "").context("writing the sandbox probe file")?;
        let program = self.engine.program();
        let out = self
            .command(home, &format!("test -f {PROBE}"), &container_name())
            .stdin(Stdio::null())
            .output();
        let out = match out {
            Ok(out) => out,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("`{program}` not found: install it or pick another [sandbox] engine")
            }
            Err(e) => return Err(e).with_context(|| format!("running `{program}`")),
        };
        if out.status.success() {
            return Ok(());
        }
        let mut output = String::from_utf8_lossy(&out.stderr).into_owned();
        output.push_str(&String::from_utf8_lossy(&out.stdout));
        // `test -f` itself fails with 1 (mounted, but not the host dir); the
        // engine fails with 125 and names the path if it cannot mount it.
        let home_text = home.display().to_string();
        if out.status.code() == Some(1) || output.contains(&home_text) {
            bail!(
                "{home_text} is not visible in the {program} container: the temp dir must be \
                 shared with the {program} VM (set TMPDIR to a directory it shares, e.g. one in \
                 your home directory; `nix develop` sets TMPDIR to /tmp/nix-shell.*)\n{}",
                log_tail(&output)
            );
        }
        bail!(
            "could not run the sandbox image `{}` with {program}:\n{}",
            self.image,
            log_tail(&output)
        )
    }

    /// `sh -c script` in a new container `name` with `dir` as working
    /// directory. The caller sets stdio and spawns it.
    pub fn command(&self, dir: &Path, script: &str, name: &str) -> Command {
        let mut cmd = Command::new(self.engine.program());
        cmd.args(self.args(dir, script, name));
        cmd
    }

    fn args(&self, dir: &Path, script: &str, name: &str) -> Vec<String> {
        let home = self.home.path().display().to_string();
        let dir = dir.display().to_string();
        let mut args: Vec<String> = [
            "run",
            "--rm",
            "--init",
            "--name",
            name,
            "--label",
            LABEL,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ]
        .map(String::from)
        .to_vec();
        match self.engine {
            Engine::Docker => {
                // SAFETY: plain syscalls that cannot fail.
                let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
                args.extend(["--user".into(), format!("{uid}:{gid}")]);
            }
            Engine::Podman => args.push("--userns=keep-id".into()),
        }
        args.extend([
            "-v".into(),
            format!("{dir}:{dir}"),
            "-v".into(),
            format!("{home}:{home}"),
            "-w".into(),
            dir,
            "-e".into(),
            format!("HOME={home}"),
        ]);
        for (key, path) in &self.env {
            args.extend(["-e".into(), format!("{key}={}", path.display())]);
        }
        args.extend([self.image.clone(), "sh".into(), "-c".into(), script.into()]);
        args
    }

    /// Remove container `name` if it is still there (best effort).
    pub fn kill(&self, name: &str) {
        let _ = Command::new(self.engine.program())
            .args(["rm", "--force", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// `mendr-<pid>-<n>`: unique per command.
pub fn container_name() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "mendr-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::cargo::Cargo;
    use crate::ecosystem::fake::Fake;

    fn sandbox(engine: Engine, eco: &dyn Ecosystem) -> Sandbox {
        let config = SandboxConfig {
            engine,
            image: "img:1".into(),
            enabled: true,
        };
        Sandbox::new(&config, eco).unwrap()
    }

    #[test]
    fn mounts_only_the_copy_and_home() {
        let s = sandbox(Engine::Podman, &Fake::new());
        let home = s.home.path().display().to_string();
        let args = s.args(Path::new("/tmp/copy"), "make test", "mendr-1-0");
        let expected: Vec<String> = [
            "run",
            "--rm",
            "--init",
            "--name",
            "mendr-1-0",
            "--label",
            "mendr",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--userns=keep-id",
            "-v",
            "/tmp/copy:/tmp/copy",
            "-v",
            &format!("{home}:{home}"),
            "-w",
            "/tmp/copy",
            "-e",
            &format!("HOME={home}"),
            "img:1",
            "sh",
            "-c",
            "make test",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(args, expected);
    }

    #[test]
    fn docker_runs_as_the_user_and_ecosystem_env_lands_in_home() {
        let s = sandbox(Engine::Docker, &Cargo::new());
        let home = s.home.path().display().to_string();
        let args = s.args(Path::new("/w"), "true", "n");
        // SAFETY: plain syscalls that cannot fail.
        let user = unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) };
        assert!(args.windows(2).any(|w| w == ["--user", user.as_str()]));
        assert!(!args.iter().any(|a| a.starts_with("--userns")));
        let cargo_home = format!("CARGO_HOME={home}/.cargo");
        assert!(args.windows(2).any(|w| w == ["-e", cargo_home.as_str()]));
    }

    #[test]
    fn names_are_unique() {
        assert_ne!(container_name(), container_name());
    }

    #[test]
    fn home_is_removed_on_drop() {
        let s = sandbox(Engine::Docker, &Fake::new());
        let home = s.home.path().to_path_buf();
        assert!(home.is_dir());
        drop(s);
        assert!(!home.exists());
    }

    /// Needs a running engine: `MENDR_TEST_SANDBOX=podman cargo test
    /// sandbox -- --ignored` (image: `MENDR_TEST_SANDBOX_IMAGE`, default
    /// `docker.io/library/alpine:3`).
    #[test]
    #[ignore]
    fn runs_in_a_real_container() {
        let engine = match std::env::var("MENDR_TEST_SANDBOX").as_deref() {
            Ok("podman") => Engine::Podman,
            _ => Engine::Docker,
        };
        let config = SandboxConfig {
            engine,
            image: std::env::var("MENDR_TEST_SANDBOX_IMAGE")
                .unwrap_or_else(|_| "docker.io/library/alpine:3".into()),
            enabled: true,
        };
        let s = Sandbox::new(&config, &Fake::new()).unwrap();
        s.check().unwrap();

        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("in"), "x").unwrap();
        // SECRET_TEST_VAR must not reach the container.
        let out = s
            .command(
                work.path(),
                "test -f in && echo \"$HOME|$SECRET_TEST_VAR\" > out && mkdir d && touch d/f",
                &container_name(),
            )
            .env("SECRET_TEST_VAR", "leak")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let written = std::fs::read_to_string(work.path().join("out")).unwrap();
        assert_eq!(written, format!("{}|\n", s.home.path().display()));
        // Owned by us: the temp dir can be removed.
        work.close().unwrap();

        let err = Sandbox {
            image: "docker.io/library/does-not-exist-mendr:0".into(),
            ..Sandbox::new(&config, &Fake::new()).unwrap()
        }
        .check()
        .unwrap_err();
        assert!(err.to_string().contains("could not run"), "{err:#}");
    }
}
