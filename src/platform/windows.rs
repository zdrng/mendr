//! Windows: `cmd /C`, job objects and console control events.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle,
    STD_ERROR_HANDLE, SetConsoleCtrlHandler, SetConsoleMode,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, ExitProcess, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};
use windows_sys::core::BOOL;

use crate::interrupt::{self, SIGHUP, SIGINT, SIGTERM};

pub const SHELL: &str = "cmd /C";

pub fn shell(command: &str) -> Command {
    let mut cmd = Command::new("cmd");
    // /D: no AutoRun commands from the registry. /S /C "...": cmd runs the
    // text between the outer quotes as it is; Rust's argument quoting does
    // not fit cmd's rules, hence raw_arg.
    cmd.raw_arg(format!("/D /S /C \"{command}\""));
    cmd
}

pub fn command(name: &str) -> Command {
    Command::new(find_in_path(name).unwrap_or_else(|| PathBuf::from(name)))
}

/// `name` with the first extension of `%PATHEXT%` that exists in a `%PATH%`
/// directory, like cmd finds programs.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        exts.split(';')
            .filter(|ext| !ext.is_empty())
            .map(|ext| dir.join(format!("{name}{ext}")))
            .find(|path| path.is_file())
    })
}

/// Job object of the command running right now (0 = none), for the console
/// control handler.
static RUNNING: AtomicIsize = AtomicIsize::new(0);

/// The job object holding a spawned command and everything it starts.
pub struct Tree {
    job: HANDLE,
}

pub fn spawn(cmd: &mut Command) -> io::Result<(Child, Tree)> {
    // SAFETY: plain calls with valid arguments; the job handle is owned by
    // `Tree` (closed on drop), the info struct is fully initialised.
    let tree = unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let tree = Tree { job };
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        // Closing the last handle kills the tree, also when mendr dies.
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        tree
    };
    // Suspended until it is in the job, so nothing it starts can escape.
    let mut child = cmd.creation_flags(CREATE_SUSPENDED).spawn()?;
    // SAFETY: both handles are valid; the child's is owned by `child`.
    if unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle() as HANDLE) } == 0 {
        let e = io::Error::last_os_error();
        let _ = child.kill();
        return Err(e);
    }
    if let Err(e) = resume(child.id()) {
        let _ = child.kill();
        return Err(e);
    }
    RUNNING.store(tree.job as isize, Ordering::SeqCst);
    Ok((child, tree))
}

/// Resumes the threads of the suspended process `pid` (std does not expose
/// the handle of its main thread, so they are found in a thread snapshot).
fn resume(pid: u32) -> io::Result<()> {
    // SAFETY: the snapshot and thread handles are closed here; THREADENTRY32
    // is initialised with its size as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut resumed = false;
        let mut more = Thread32First(snapshot, &mut entry);
        while more != 0 {
            if entry.th32OwnerProcessID == pid {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                if !thread.is_null() {
                    resumed |= ResumeThread(thread) != u32::MAX;
                    CloseHandle(thread);
                }
            }
            more = Thread32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        if resumed {
            Ok(())
        } else {
            Err(io::Error::other(
                "could not start the command's main thread",
            ))
        }
    }
}

impl Tree {
    /// Terminates every process in the job.
    pub fn kill(&self) {
        // SAFETY: the job handle is valid until drop.
        unsafe {
            TerminateJobObject(self.job, 1);
        }
    }

    #[cfg(test)]
    fn active_processes(&self) -> u32 {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };
        // SAFETY: the struct is fully initialised and large enough.
        unsafe {
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
            QueryInformationJobObject(
                self.job,
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            info.ActiveProcesses
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = RUNNING.compare_exchange(self.job as isize, 0, Ordering::SeqCst, Ordering::SeqCst);
        // SAFETY: we own the handle; closing it kills what is left (see spawn).
        unsafe {
            CloseHandle(self.job);
        }
    }
}

/// Ctrl-C, Ctrl-Break and closing the console. Commands share mendr's
/// console, so they get these events themselves; when mendr must exit at
/// once it terminates the running command's job first.
pub fn install_interrupt_handlers() {
    // SAFETY: registers a handler with the signature the API expects.
    unsafe {
        SetConsoleCtrlHandler(Some(on_console_event), 1);
    }
}

unsafe extern "system" fn on_console_event(event: u32) -> BOOL {
    let sig = match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => SIGINT,
        CTRL_CLOSE_EVENT => SIGHUP,
        _ => SIGTERM, // logoff, shutdown
    };
    if interrupt::record(sig) {
        let job = RUNNING.load(Ordering::SeqCst);
        // SAFETY: a running job's handle stays valid while it is in
        // RUNNING; ExitProcess does not return.
        unsafe {
            if job != 0 {
                TerminateJobObject(job as HANDLE, 1);
            }
            ExitProcess((128 + sig) as u32);
        }
    }
    1
}

pub fn terminal_width() -> Option<usize> {
    // SAFETY: the API only writes into the struct we pass.
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &mut info) == 0 {
            return None;
        }
        let width = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        usize::try_from(width).ok().filter(|w| *w > 0)
    }
}

pub fn enable_ansi() {
    // SAFETY: reads and sets the mode of our own stderr console.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

pub fn user_cache_dir(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    var("LOCALAPPDATA").map(PathBuf::from)
}

/// The temp directory is the user's own on Windows.
pub fn temp_cache_name() -> String {
    "mendr".to_string()
}

/// Windows has only the read-only flag; a new file gets the default.
pub fn replacement_permissions(existing: Option<&fs::Metadata>) -> Option<fs::Permissions> {
    existing.map(fs::Metadata::permissions)
}

pub fn symlink(target: &Path, link: &Path, dir: bool) -> io::Result<()> {
    if dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

pub fn wrapper_script(dir: &Path, name: &str) -> Option<String> {
    let script = format!("{name}.bat");
    dir.join(&script).is_file().then_some(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn the_shell_runs_the_command_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let status = shell(r#"echo "a b"> out & exit 3"#)
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(3));
        let out = fs::read_to_string(dir.path().join("out")).unwrap();
        assert_eq!(out.trim_end(), "\"a b\"");
    }

    #[test]
    fn killing_the_tree_kills_what_the_command_started() {
        // cmd starts ping, which would run for a minute.
        let mut cmd = shell("ping -n 60 127.0.0.1 > nul");
        let (mut child, tree) = spawn(&mut cmd).unwrap();
        let start = Instant::now();
        while tree.active_processes() < 2 {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "ping did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        tree.kill();
        child.wait().unwrap();
        while tree.active_processes() > 0 {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "processes survived"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn programs_are_found_with_their_extension() {
        // cmd.exe is in System32 on every Windows.
        let found = find_in_path("cmd").unwrap();
        assert!(
            found
                .to_string_lossy()
                .to_lowercase()
                .ends_with(r"\cmd.exe"),
            "{found:?}"
        );
        assert_eq!(find_in_path("no-such-program-mendr"), None);
    }

    #[test]
    fn cache_dir_is_local_app_data() {
        let var = |name: &str| {
            (name == "LOCALAPPDATA").then(|| OsString::from(r"C:\Users\u\AppData\Local"))
        };
        assert_eq!(
            user_cache_dir(var),
            Some(PathBuf::from(r"C:\Users\u\AppData\Local"))
        );
    }

    #[test]
    fn wrapper_is_the_batch_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(wrapper_script(dir.path(), "gradlew"), None);
        fs::write(dir.path().join("gradlew.bat"), "").unwrap();
        assert_eq!(
            wrapper_script(dir.path(), "gradlew").as_deref(),
            Some("gradlew.bat")
        );
    }
}
