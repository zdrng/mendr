//! Unix (Linux, macOS, BSD): `sh -c`, process groups and signals.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::interrupt;

pub const SHELL: &str = "sh -c";

pub fn shell(command: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd
}

pub fn command(name: &str) -> Command {
    Command::new(name)
}

/// Process group of the command running right now (0 = none), for the
/// signal handler.
static RUNNING: AtomicI32 = AtomicI32::new(0);

/// The process group of a spawned command.
pub struct Tree {
    group: libc::pid_t,
}

pub fn spawn(cmd: &mut Command) -> io::Result<(Child, Tree)> {
    // Its own process group, so everything it starts can be killed at once,
    // and a terminal's Ctrl-C reaches mendr only (the handler forwards it).
    let child = cmd.process_group(0).spawn()?;
    let group = child.id() as libc::pid_t;
    RUNNING.store(group, Ordering::SeqCst);
    Ok((child, Tree { group }))
}

impl Tree {
    /// SIGKILL every process left in the group.
    pub fn kill(&self) {
        // SAFETY: plain syscall. The group id is the pid of a child we
        // spawned as a group leader; it cannot be reused while any member is
        // alive, and reuse right after the last one exited would need a pid
        // wraparound within microseconds.
        unsafe {
            libc::killpg(self.group, libc::SIGKILL);
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = RUNNING.compare_exchange(self.group, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// SIGINT, SIGTERM and SIGHUP. The handler forwards the signal to the
/// running command's group (it does not get a terminal's Ctrl-C itself);
/// when mendr must exit at once it kills the group first.
pub fn install_interrupt_handlers() {
    for sig in [interrupt::SIGINT, interrupt::SIGTERM, interrupt::SIGHUP] {
        // SAFETY: `on_signal` only does async-signal-safe things (atomics,
        // killpg, _exit); the sigaction structs are fully initialised.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                && old.sa_sigaction == libc::SIG_IGN
            {
                continue;
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    let group = RUNNING.load(Ordering::SeqCst);
    // SAFETY: killpg and _exit are async-signal-safe; `record` only uses
    // atomics.
    unsafe {
        if group > 0 {
            libc::killpg(group, sig);
        }
        if interrupt::record(sig) {
            if group > 0 {
                libc::killpg(group, libc::SIGKILL);
            }
            libc::_exit(128 + sig);
        }
    }
}

pub fn terminal_width() -> Option<usize> {
    // SAFETY: TIOCGWINSZ only writes into the `winsize` we pass.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
    (ok && ws.ws_col > 0).then_some(ws.ws_col as usize)
}

pub fn enable_ansi() {}

pub fn user_cache_dir(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| var("HOME").map(|home| PathBuf::from(home).join(".cache")))
}

pub fn temp_cache_name() -> String {
    // SAFETY: getuid cannot fail and has no side effects.
    format!("mendr-{}", unsafe { libc::getuid() })
}

pub fn replacement_permissions(existing: Option<&fs::Metadata>) -> Option<fs::Permissions> {
    let mode = existing.map_or(0o644, |m| m.permissions().mode() & 0o7777);
    Some(fs::Permissions::from_mode(mode))
}

pub fn symlink(target: &Path, link: &Path, _dir: bool) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

pub fn wrapper_script(dir: &Path, name: &str) -> Option<String> {
    dir.join(name).is_file().then(|| format!("./{name}"))
}

#[cfg(test)]
pub fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_numbers_are_the_systems() {
        assert_eq!(interrupt::SIGHUP, libc::SIGHUP);
        assert_eq!(interrupt::SIGINT, libc::SIGINT);
        assert_eq!(interrupt::SIGTERM, libc::SIGTERM);
    }

    #[test]
    fn cache_dir_prefers_xdg_then_home() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        assert_eq!(
            user_cache_dir(env(&[("XDG_CACHE_HOME", "/x"), ("HOME", "/h")])),
            Some(PathBuf::from("/x"))
        );
        assert_eq!(
            user_cache_dir(env(&[("HOME", "/h")])),
            Some(PathBuf::from("/h/.cache"))
        );
        assert_eq!(user_cache_dir(env(&[])), None);
    }

    #[test]
    fn replacements_keep_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gradlew");
        fs::write(&file, "").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o750)).unwrap();
        let meta = fs::metadata(&file).unwrap();
        assert_eq!(replacement_permissions(Some(&meta)).unwrap().mode(), 0o750);
        assert_eq!(replacement_permissions(None).unwrap().mode(), 0o644);
    }

    #[test]
    fn wrapper_is_called_from_the_project_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(wrapper_script(dir.path(), "gradlew"), None);
        fs::write(dir.path().join("gradlew"), "").unwrap();
        assert_eq!(
            wrapper_script(dir.path(), "gradlew").as_deref(),
            Some("./gradlew")
        );
    }
}
