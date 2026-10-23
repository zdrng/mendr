//! Everything that depends on the operating system, behind one small
//! interface: running a command in the shell, killing a command together
//! with everything it started, interrupts, the terminal, per-user paths,
//! file permissions and symlinks. The rest of mendr does not know which
//! system it runs on; the compiler builds only the implementation for the
//! target: `unix.rs` (Linux, macOS, BSD) or `windows.rs`. All of mendr's
//! `unsafe` code lives in these two files.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

/// The shell commands run in, for messages: `sh -c` or `cmd /C`.
pub const SHELL: &str = imp::SHELL;

/// A command that runs `command` in the platform's shell: `sh -c` on Unix,
/// `cmd /D /S /C` on Windows.
pub fn shell(command: &str) -> Command {
    imp::shell(command)
}

/// A command that starts the program `name` from the PATH. On Windows that
/// may be a batch file (`npm.cmd`), which `Command::new` alone does not
/// find.
pub fn command(name: &str) -> Command {
    imp::command(name)
}

/// A running command and every process it starts. While it runs, an
/// interrupt reaches it (see [`install_interrupt_handlers`]). Dropping it
/// kills whatever of it is still running, so nothing a command started in
/// the background outlives it.
pub struct ProcessTree {
    child: Child,
    tree: imp::Tree,
}

impl ProcessTree {
    /// Spawns `cmd` so that it and everything it starts can be killed
    /// together: in its own process group (Unix) or job object (Windows).
    pub fn spawn(cmd: &mut Command) -> io::Result<Self> {
        let (child, tree) = imp::spawn(cmd)?;
        Ok(ProcessTree { child, tree })
    }

    /// The command's exit status, if it has exited.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Kills every process of the tree and waits for the command itself.
    pub fn kill(&mut self) -> io::Result<()> {
        self.tree.kill();
        let _ = self.child.kill();
        self.child.wait().map(drop)
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        self.tree.kill();
    }
}

/// Installs the handlers that turn interrupts into [`crate::interrupt`]
/// events and pass them on to the running [`ProcessTree`]. Interrupts that
/// are ignored at startup stay ignored.
pub fn install_interrupt_handlers() {
    imp::install_interrupt_handlers();
}

/// Columns of the terminal on stderr, if stderr is one.
pub fn terminal_width() -> Option<usize> {
    imp::terminal_width()
}

/// Makes the terminal on stderr interpret ANSI escape sequences (colors,
/// erasing the status line). Unix terminals always do.
pub fn enable_ansi() {
    imp::enable_ansi();
}

/// The user's cache directory from the environment `var`:
/// `$XDG_CACHE_HOME` or `$HOME/.cache` on Unix, `%LOCALAPPDATA%` on Windows.
pub fn user_cache_dir(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    imp::user_cache_dir(var)
}

/// Name of mendr's cache directory in the system temp directory, per user
/// where that directory is shared (`/tmp`).
pub fn temp_cache_name() -> String {
    imp::temp_cache_name()
}

/// Permissions for a file that replaces `existing` (`None`: a new file):
/// the same as before.
pub fn replacement_permissions(existing: Option<&fs::Metadata>) -> Option<fs::Permissions> {
    imp::replacement_permissions(existing)
}

/// Creates the symlink `link` pointing to `target`; `dir` says whether the
/// target is a directory (Windows needs to know).
pub fn symlink(target: &Path, link: &Path, dir: bool) -> io::Result<()> {
    imp::symlink(target, link, dir)
}

/// How to call the build tool wrapper `name` (`gradlew`) of the project in
/// `dir` from its shell: `./gradlew` on Unix, `gradlew.bat` on Windows.
/// `None` if the project has none.
pub fn wrapper_script(dir: &Path, name: &str) -> Option<String> {
    imp::wrapper_script(dir, name)
}

/// Whether process `pid` still exists, waiting up to 5s for it to go.
#[cfg(all(test, unix))]
pub fn still_alive(pid: u32) -> bool {
    let start = std::time::Instant::now();
    while imp::exists(pid) {
        if start.elapsed() > std::time::Duration::from_secs(5) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}
